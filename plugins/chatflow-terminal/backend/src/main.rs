//! `cc-chatflow-terminal`: CortexTerm's chat flow (`chatflow-terminal`, `chatflow@1`).
//!
//! A turn gathers facts and learned memory, then uses model calls and read-only checks. The shell's
//! folder and last Runs, a failed Run's output, and the machine's processes and ports when the
//! question is about them go before the user's text. The flow streams the answer into the session
//! journal and, when the answer carries a ```sh block, journals that one command as a proposal
//! together with the risk engine's assessment (`terminal.assess`). The model only proposes and
//! explains; whether a command runs is the user's and the risk engine's call, never the model's.

mod flow;
mod config;
mod routing;
mod learning;
mod replay;
mod security;

use cc_protocol::contracts::lifecycle::{Hello, ProbeCheck, ProbeReport};
use cc_protocol::{BoxFuture, Call, Ctx, Plugin, PluginEnv, RpcError, run_plugin};
use flow::Flow;
use serde_json::Value;
use std::sync::Arc;

const CATEGORY: &str = "chatflow-terminal";

struct FlowPlugin {
    flow: Arc<Flow>,
}

impl Plugin for FlowPlugin {
    fn handle(&self, ctx: Ctx, call: Call) -> BoxFuture<'static, Result<Value, RpcError>> {
        self.flow.connect(ctx);
        let flow = self.flow.clone();
        Box::pin(async move {
            let verb = call.method.strip_prefix(CATEGORY).and_then(|rest| rest.strip_prefix('.')).unwrap_or(&call.method).to_owned();
            flow.dispatch(&verb, call.params).await
        })
    }

    fn event(&self, ctx: Ctx, topic: String, data: Value) -> BoxFuture<'static, ()> {
        self.flow.connect(ctx);
        let flow = self.flow.clone();
        Box::pin(async move { flow.terminal_event(&topic, data) })
    }

    fn probe(&self, ctx: Ctx) -> BoxFuture<'static, Result<ProbeReport, RpcError>> {
        self.flow.connect(ctx);
        let flow = self.flow.clone();
        Box::pin(async move {
            let started = std::time::Instant::now();
            let check = match flow.prompts_present() {
                Ok(()) => ProbeCheck { name: "prompts".into(), ok: true, detail: "ask, fix, explain, security and learning prompts and schema found".into(), ms: started.elapsed().as_millis() as u64 },
                Err(detail) => ProbeCheck { name: "prompts".into(), ok: false, detail, ms: started.elapsed().as_millis() as u64 },
            };
            Ok(ProbeReport::from_checks(vec![check]))
        })
    }

    fn activate(&self, ctx: Ctx) -> BoxFuture<'static, Result<(), RpcError>> {
        self.flow.connect(ctx);
        let flow = self.flow.clone();
        Box::pin(async move { flow.activate(); Ok(()) })
    }

    fn shutdown(&self, _ctx: Ctx) -> BoxFuture<'static, ()> {
        let flow = self.flow.clone();
        Box::pin(async move { flow.cancel_all() })
    }
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_env("CORTEX_LOG").unwrap_or_else(|_| "warn".into()))
        .with_writer(std::io::stderr)
        .init();
    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("cc-chatflow-terminal: cannot start the async runtime: {error}");
            std::process::exit(1);
        }
    };
    let code = runtime.block_on(async {
        let env = match PluginEnv::from_env() {
            Ok(env) => env,
            Err(error) => {
                eprintln!("cc-chatflow-terminal: {error}");
                return 2;
            }
        };
        let flow = Arc::new(Flow::new(env));
        let mut hello = Hello::new("cc-chatflow-terminal", env!("CARGO_PKG_VERSION"), CATEGORY, "chatflow@1");
        hello.subscribes = vec!["terminal.run.started".into(), "terminal.run.finished".into()];
        hello.provides = flow::VERBS.iter().map(|verb| format!("{CATEGORY}.{verb}")).collect();
        let plugin = Arc::new(FlowPlugin { flow: flow.clone() });
        let mut terminate = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(stream) => stream,
            Err(error) => {
                eprintln!("cc-chatflow-terminal: cannot handle SIGTERM: {error}");
                return 1;
            }
        };
        let outcome = tokio::select! {
            outcome = run_plugin(hello, plugin) => outcome,
            _ = terminate.recv() => Ok(()),
            _ = tokio::signal::ctrl_c() => Ok(()),
        };
        flow.cancel_all();
        match outcome {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("cc-chatflow-terminal: {error}");
                1
            }
        }
    });
    std::process::exit(code);
}
