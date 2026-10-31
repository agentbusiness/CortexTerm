//! `cc-terminal` executable: serve `terminal@1` to the frame.

use cc_protocol::contracts::lifecycle::{Hello, ProbeReport};
use cc_protocol::contracts::terminal::methods;
use cc_protocol::{BoxFuture, Call, Ctx, Plugin, PluginEnv, RpcError, parse_params, run_plugin, to_value};
use cc_terminal::Terminals;
use cc_terminal::command::Commands;
use serde_json::Value;
use std::sync::{Arc, OnceLock};

struct TerminalPlugin {
    terms: Arc<Terminals>,
    commands: Arc<Commands>,
    ctx: Arc<OnceLock<Ctx>>,
}

impl Plugin for TerminalPlugin {
    fn handle(&self, ctx: Ctx, call: Call) -> BoxFuture<'static, Result<Value, RpcError>> {
        let _ = self.ctx.set(ctx.clone());
        let terms = self.terms.clone();
        let commands = self.commands.clone();
        Box::pin(async move {
            match call.method.as_str() {
                methods::SHARES => to_value(&cc_terminal::command::shares()),
                methods::COMMAND_RUN => commands.run(ctx, call.params, call.items, call.cancel).await,
                methods::COMMAND_STOP => to_value(&commands.stop(&id_of(&call.params)?)?),
                methods::COMMAND_JOBS_LIST => Ok(commands.jobs()),
                methods::COMMAND_JOBS_GET => to_value(&commands.get(&ctx, call.params).await?),
                methods::COMMAND_OUTPUT_READ => commands.output(parse_params(call.params)?).await,
                _ => terms.dispatch(&call.method, call.params).await,
            }
        })
    }

    fn probe(&self, ctx: Ctx) -> BoxFuture<'static, Result<ProbeReport, RpcError>> {
        let _ = self.ctx.set(ctx);
        Box::pin(async { Ok(cc_terminal::probe::run().await) })
    }

    /// Take the shells over from `cortexd` (starting it when needed) right before serving.
    fn activate(&self, ctx: Ctx) -> BoxFuture<'static, Result<(), RpcError>> {
        let _ = self.ctx.set(ctx);
        let terms = self.terms.clone();
        // Jobs a stopped instance left running are lost now (once the graph answers).
        tokio::spawn(self.commands.clone().recover());
        Box::pin(async move { terms.attach().await })
    }

    // No state export: the shells and what the tracker must remember live in cortexd, and the
    // next instance takes them over in `activate`.

    fn shutdown(&self, _ctx: Ctx) -> BoxFuture<'static, ()> {
        self.terms.detach();
        Box::pin(async {})
    }
}

fn id_of(params: &Value) -> Result<String, RpcError> {
    params.get("id").and_then(Value::as_str).map(str::to_owned).ok_or_else(|| RpcError::invalid_params("`id` is needed"))
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_env("CORTEX_LOG").unwrap_or_else(|_| "warn".into()))
        .with_writer(std::io::stderr)
        .init();
    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("cc-terminal: cannot start the async runtime: {error}");
            std::process::exit(1);
        }
    };
    let code = runtime.block_on(async {
        if let Err(error) = PluginEnv::from_env() {
            eprintln!("cc-terminal: {error}");
            return 2;
        }
        let ctx_slot: Arc<OnceLock<Ctx>> = Arc::new(OnceLock::new());
        let publish_slot = ctx_slot.clone();
        let emit = Arc::new(move |topic: &str, data: Value| {
            if let Some(ctx) = publish_slot.get() {
                ctx.publish(topic, data);
            }
        });
        // Runs live in the memory plugin's graph and streams (through the frame); until the frame
        // and the memory plugin answer, the store keeps them waiting in memory.
        let memory_slot = ctx_slot.clone();
        let memory: cc_terminal::store::Memory = Arc::new(move |method: &'static str, params: Value| {
            let slot = memory_slot.clone();
            Box::pin(async move {
                let ctx = slot.get().cloned().ok_or_else(|| RpcError::new(cc_protocol::codes::UNAVAILABLE, "not connected to the frame yet"))?;
                ctx.call(method, params).await
            })
        });
        let store = cc_terminal::store::Store::new(memory.clone(), cc_terminal::store::default_dir());
        let terms = Terminals::new(emit.clone(), Some(store.clone()));
        let commands = Commands::new(Some(store.clone()), emit, cc_terminal::wire::home());
        terms.set_learner(cc_terminal::habits::Learner::new(store, memory));
        let mut hello = Hello::new("cc-terminal", env!("CARGO_PKG_VERSION"), "terminal", "terminal@1");
        hello.provides = [
            methods::OPEN,
            methods::WRITE,
            methods::RESIZE,
            methods::CLOSE,
            methods::LIST,
            methods::SNAPSHOT,
            methods::STATE,
            methods::RUNS,
            methods::RUN_OUTPUT,
            methods::RUN_HISTOGRAM,
            methods::ASSESS,
            methods::COMPLETE,
            methods::PLACES,
            methods::FILE_READ,
            methods::FILE_WRITE,
            methods::HABITS,
            methods::SCAN,
            methods::SCRIPT_FETCH,
            methods::PACKAGES_CHECK,
            methods::SANDBOX_WRAP,
            methods::SHARES,
            methods::COMMAND_RUN,
            methods::COMMAND_STOP,
            methods::COMMAND_JOBS_LIST,
            methods::COMMAND_JOBS_GET,
            methods::COMMAND_OUTPUT_READ,
        ]
        .iter()
            .map(|m| (*m).to_owned())
            .collect();
        let plugin = Arc::new(TerminalPlugin { terms: terms.clone(), commands, ctx: ctx_slot });
        let mut terminate = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(stream) => stream,
            Err(error) => {
                eprintln!("cc-terminal: cannot handle SIGTERM: {error}");
                return 1;
            }
        };
        let outcome = tokio::select! {
            outcome = run_plugin(hello, plugin) => outcome,
            _ = terminate.recv() => Ok(()),
            _ = tokio::signal::ctrl_c() => Ok(()),
        };
        // The shells stay with cortexd for the next instance, however this one ends.
        terms.detach();
        match outcome {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("cc-terminal: {error}");
                1
            }
        }
    });
    std::process::exit(code);
}
