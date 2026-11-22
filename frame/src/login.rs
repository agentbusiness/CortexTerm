//! Start at login (macOS): a LaunchAgent opens the app when the person logs in, without a window
//! (`CORTEX_BACKGROUND=1`: the shell keeps its window hidden until the Dock icon is clicked), so
//! the frame, its mesh and its model run whether a window is open or not. The window's close
//! button hides it; only Quit stops the app. Written by the app's own frame on its default home,
//! again only when it changed; System Settings, Login Items, turns it off.

use std::path::{Path, PathBuf};

/// The app's name: its bundle in /Applications and its LaunchAgent's label.
const APP: &str = "CortexTerm";
const LABEL: &str = "ai.cortexterm.login";

/// Write the LaunchAgent when this frame runs on the person's own home (not a test home).
pub fn register(home: &Path, default_home: &Path) {
    if !cfg!(target_os = "macos") || home != default_home {
        return;
    }
    let Some(bundle) = bundle() else { return };
    let Some(user) = std::env::var_os("HOME").map(PathBuf::from) else { return };
    let agent = user.join("Library").join("LaunchAgents").join(format!("{LABEL}.plist"));
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/bin/open</string>
    <string>-g</string>
    <string>--env</string>
    <string>CORTEX_BACKGROUND=1</string>
    <string>-a</string>
    <string>{}</string>
  </array>
  <key>RunAtLoad</key><true/>
</dict>
</plist>
"#,
        escape(&bundle.display().to_string())
    );
    if std::fs::read_to_string(&agent).is_ok_and(|current| current == plist) {
        return;
    }
    let written = agent.parent().map_or(Ok(()), std::fs::create_dir_all).and_then(|()| std::fs::write(&agent, plist));
    match written {
        Ok(()) => tracing::info!(agent = %agent.display(), bundle = %bundle.display(), "the app starts at login"),
        Err(error) => tracing::warn!(%error, agent = %agent.display(), "cannot write the login item"),
    }
}

/// The app the person opens: in /Applications, else ~/Applications, else the bundle this frame
/// runs from.
fn bundle() -> Option<PathBuf> {
    let name = format!("{APP}.app");
    let mut places = vec![PathBuf::from("/Applications").join(&name)];
    if let Some(user) = std::env::var_os("HOME") {
        places.push(PathBuf::from(user).join("Applications").join(&name));
    }
    if let Some(found) = places.into_iter().find(|place| place.is_dir()) {
        return Some(found);
    }
    let exe = std::env::current_exe().ok()?;
    exe.ancestors().find(|dir| dir.extension().is_some_and(|ext| ext == "app")).map(Path::to_path_buf)
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}
