//! Configuration inspection and proposals. Only the person's reviewed shell command can apply.

use cc_protocol::contracts::model::ToolSpec;
use serde_json::{Value, json};
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

const REQUEST_BYTES: usize = 320 * 1024;
const OUTPUT_BYTES: usize = 24 * 1024;

pub fn tool() -> ToolSpec {
    ToolSpec {
        name: "config".into(),
        description: "Inspect a UTF-8 config or preview one exact replacement. Read first; use its sha256 for preview. Preview never edits the target: the app shows a diff and a user-run command. Secret edits and administrator files belong in the editor.".into(),
        parameters: json!({
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": ["inspect", "preview"]},
                "path": {"type": "string", "description": "File on this runner's machine. Relative paths use this terminal's folder; never use a local path for an SSH target."},
                "format": {"type": "string", "enum": ["text", "json", "jsonc", "jsonl", "toml", "yaml", "xml", "plist", "ini", "env", "shell", "nginx", "haproxy", "systemd", "ssh", "hcl", "csv", "tsv", "sql"], "description": "Omit to infer from the filename. Text/product dialects still need their native validator."},
                "start_line": {"type": "integer", "minimum": 1},
                "line_count": {"type": "integer", "minimum": 1, "maximum": 60},
                "expected_sha256": {"type": "string", "description": "Preview only: copy sha256 from this file's inspect result."},
                "old_text": {"type": "string", "description": "Preview only: exact current text, without displayed line numbers; must occur once. No secret lines."},
                "new_text": {"type": "string", "description": "Preview only: replacement text. No secrets; keep unrelated settings unchanged."}
            },
            "required": ["action", "path"],
            "additionalProperties": false
        }),
    }
}

/// Launch only bundled inspection/preview code. `apply` is absent from this interface.
pub async fn call(arguments: &str, cwd: Option<&str>, helper: &Path, home: &Path) -> Result<String, String> {
    if arguments.len() > REQUEST_BYTES {
        return Err("Configuration request exceeds 320 KiB; select a smaller change.".into());
    }
    let request: Value = serde_json::from_str(arguments).map_err(|_| "Give config arguments as a JSON object.".to_owned())?;
    let action = request.get("action").and_then(Value::as_str).filter(|action| matches!(*action, "inspect" | "preview"))
        .ok_or_else(|| "config supports inspect or preview only; the person runs any change.".to_owned())?;
    if !request.get("path").and_then(Value::as_str).is_some_and(|path| !path.trim().is_empty()) {
        return Err("Give the configuration file's path.".into());
    }
    if !helper.is_file() {
        return Err("The bundled configuration helper is missing. Use the native editor.".into());
    }
    let mut command = Command::new("python3");
    command.arg(helper).arg(action).arg("--home").arg(home)
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).kill_on_drop(true);
    if let Some(cwd) = cwd { command.arg("--cwd").arg(cwd); }
    // Request contents travel through stdin, never command arguments or shell interpolation.
    let mut child = command.spawn().map_err(|_| "Configuration inspection needs an installed Python 3. Use the native editor if unavailable.".to_owned())?;
    let result = tokio::time::timeout(Duration::from_secs(8), async move {
        let mut stdin = child.stdin.take().ok_or_else(|| "Cannot send the config request.".to_owned())?;
        stdin.write_all(arguments.as_bytes()).await.map_err(|_| "Cannot send the config request.".to_owned())?;
        drop(stdin);
        child.wait_with_output().await.map_err(|_| "Configuration helper did not finish.".to_owned())
    }).await.map_err(|_| "Configuration helper exceeded 8 seconds; no change was applied.".to_owned())??;
    if result.stdout.len() > OUTPUT_BYTES {
        return Err("Configuration output exceeded its limit. Inspect fewer lines in the native editor.".into());
    }
    let value: Value = serde_json::from_slice(&result.stdout).map_err(|_| "Configuration helper returned no readable result. No change was applied.".to_owned())?;
    // Helper errors are ordinary tool evidence, with no copied parser input or stderr.
    serde_json::to_string(&value).map_err(|_| "Cannot read the configuration result.".to_owned())
}
