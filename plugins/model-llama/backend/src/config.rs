//! `[backend.config]` of plugin.toml (the frame config's `[plugin.config]` wins).

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    /// "" = by memory (`catalog::for_memory`).
    pub variant: String,
    /// Context tokens per slot.
    pub ctx: u32,
    pub parallel: u32,
    pub ubatch: u32,
    /// f16 | q8_0 (q8_0 needs flash attention; checked once, f16 otherwise).
    pub kv_type: String,
    pub idle_unload_s: u64,
    /// Borrow the model of another app on this Mac (a local member of the mesh) instead of
    /// loading Gemma, and yield Gemma when such an app asks.
    pub borrow: bool,
    /// The llama-server binary (default: beside this executable).
    pub server_bin: Option<String>,
    /// Where models live (default `$CORTEX_HOME/models`).
    pub models_dir: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            variant: String::new(),
            ctx: 8192,
            parallel: 2,
            ubatch: 256,
            kv_type: "f16".into(),
            idle_unload_s: 600,
            borrow: true,
            server_bin: None,
            models_dir: None,
        }
    }
}

impl Config {
    pub fn from_value(value: &serde_json::Value) -> Self {
        if value.is_null() {
            return Self::default();
        }
        serde_json::from_value(value.clone()).unwrap_or_else(|error| {
            tracing::warn!(%error, "plugin config not understood; using the defaults");
            Self::default()
        })
    }
}
