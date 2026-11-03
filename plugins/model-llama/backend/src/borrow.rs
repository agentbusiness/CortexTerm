//! Another app's model, through the mesh: on this machine (one model per machine: the apps here
//! are members of each other's mesh without pairing), or, on a machine without a GPU, on any
//! member. Cards show the model each member holds and lends. `look` finds one this app accepts;
//! `call` forwards a `model.*` call to it (`mesh.call`), stream items as the model produces them.

use cc_protocol::contracts::mesh::PeersResult;
use cc_protocol::contracts::model::tags;
use cc_protocol::{Ctx, RpcError};
use serde_json::{Value, json};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// The app on this Mac whose model serves here.
#[derive(Debug, Clone, PartialEq)]
pub struct Lender {
    pub node: String,
    pub name: String,
    /// The app (`cortexcode`), as the window shows it.
    pub software: String,
    pub model_id: String,
}

/// A model of another app on this Mac that this app accepts: a `coding` one always (Qwen ranks
/// above this app's Gemma), an `office` one only while Gemma is not loaded here (two Gemmas
/// would not both stay). `anywhere` (this machine has no GPU): a reachable member's on any
/// machine, this machine's first.
pub async fn look(ctx: &Ctx, own_loaded: bool, anywhere: bool) -> Option<Lender> {
    let peers = tokio::time::timeout(Duration::from_secs(3), ctx.call("mesh.peers", json!({}))).await.ok()?.ok()?;
    let peers: PeersResult = serde_json::from_value(peers).ok()?;
    let mut found: Vec<(usize, Lender)> = peers
        .peers
        .into_iter()
        .filter(|peer| (anywhere || peer.member.local) && peer.reachable)
        .filter_map(|peer| {
            let card = peer.card?;
            let software = card.software;
            let model = card.model?;
            let rank = if model.tags.iter().any(|tag| tag == tags::CODING) {
                0
            } else if !own_loaded && model.tags.iter().any(|tag| tag == tags::OFFICE) {
                1
            } else {
                return None;
            };
            let rank = if peer.member.local { rank } else { rank + 2 };
            Some((rank, Lender { node: peer.member.node, name: peer.member.name, software, model_id: model.model_id }))
        })
        .collect();
    found.sort_by_key(|(rank, _)| *rank);
    found.into_iter().next().map(|(_, lender)| lender)
}

/// Give a forwarded call its own conversation space: `cache_key` gets the `cortexterm:` prefix.
pub fn prefix_cache_key(params: &mut Value) {
    if let Some(key) = params.get_mut("cache_key")
        && let Some(text) = key.as_str()
        && !text.starts_with("cortexterm:")
    {
        *key = Value::String(format!("cortexterm:{text}"));
    }
}

/// One call on the lender's model. Stream items go to `on_item` as they arrive; `cancel` cancels
/// the call there.
pub async fn call(ctx: &Ctx, lender: &Lender, method: &str, params: Value, on_item: &mut (dyn FnMut(Value) + Send), cancel: Option<CancellationToken>) -> Result<Value, RpcError> {
    let mut stream = ctx.call_stream("mesh.call", json!({"node": lender.node, "method": method, "params": params}))?;
    let cancel = cancel.unwrap_or_default();
    loop {
        tokio::select! {
            item = stream.next() => match item {
                Some(item) => on_item(item),
                None => break,
            },
            _ = cancel.cancelled() => {
                stream.cancel();
                break;
            }
        }
    }
    stream.finish().await
}
