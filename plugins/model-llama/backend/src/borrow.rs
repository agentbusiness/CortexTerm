//! A member's model, through the mesh, for a machine without a usable GPU (a machine with one runs
//! its own model and lends it; the cortex-network). Cards show the model each member holds and
//! lends. `look` finds one; `call` forwards a `model.*` call to it (`mesh.call`), stream items as
//! the model produces them.

use cc_protocol::contracts::mesh::PeersResult;
use cc_protocol::contracts::model::tags;
use cc_protocol::{Ctx, RpcError};
use serde_json::{Value, json};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// The member whose model serves here.
#[derive(Debug, Clone, PartialEq)]
pub struct Lender {
    pub node: String,
    pub name: String,
    /// The app (`cortexcode`), as the window shows it.
    pub software: String,
    pub model_id: String,
    /// The model on the member's computer (its card's `plugin`), named on every call to it.
    pub plugin: String,
}

/// A reachable member's model to serve here, for a machine without a usable GPU: a `coding` one
/// before an `office` one, and another app's on this machine before another computer's.
pub async fn look(ctx: &Ctx) -> Option<Lender> {
    let peers = tokio::time::timeout(Duration::from_secs(3), ctx.call("mesh.peers", json!({}))).await.ok()?.ok()?;
    let peers: PeersResult = serde_json::from_value(peers).ok()?;
    let mut found: Vec<(usize, Lender)> = peers
        .peers
        .into_iter()
        .filter(|peer| peer.reachable)
        .filter_map(|peer| {
            let card = peer.card?;
            let software = card.software;
            // The member's best model for this app: a `coding` one before an `office` one.
            let ranked = |model: &cc_protocol::contracts::mesh::ModelCard| {
                if model.tags.iter().any(|tag| tag == tags::CODING) {
                    Some(0)
                } else if model.tags.iter().any(|tag| tag == tags::OFFICE) {
                    Some(1)
                } else {
                    None
                }
            };
            let (rank, model) = card.models.into_iter().filter_map(|model| ranked(&model).map(|rank| (rank, model))).min_by_key(|(rank, _)| *rank)?;
            let rank = if peer.member.local { rank } else { rank + 2 };
            Some((rank, Lender { node: peer.member.node, name: peer.member.name, software, model_id: model.model_id, plugin: model.plugin }))
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
pub async fn call(ctx: &Ctx, lender: &Lender, method: &str, mut params: Value, on_item: &mut (dyn FnMut(Value) + Send), cancel: Option<CancellationToken>) -> Result<Value, RpcError> {
    if let Some(params) = params.as_object_mut() {
        params.insert(cc_protocol::contracts::model::PLUGIN_PARAM.to_owned(), Value::String(lender.plugin.clone()));
    }
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
