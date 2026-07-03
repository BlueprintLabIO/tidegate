//! Native OS notifications — approval channel 2. Best-effort: a failed
//! notification must never block a call (the model-legible timeout result is
//! the real fallback). No external crate; we shell out to the platform tool.

use std::process::Command;

pub fn send(title: &str, body: &str) {
    let _ = try_send(title, body);
}

#[cfg(target_os = "macos")]
fn try_send(title: &str, body: &str) -> std::io::Result<()> {
    // osascript display notification. Escape double quotes and backslashes.
    let esc = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
    let script = format!(
        "display notification \"{}\" with title \"{}\"",
        esc(body),
        esc(title)
    );
    Command::new("osascript").arg("-e").arg(script).spawn()?.wait()?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn try_send(title: &str, body: &str) -> std::io::Result<()> {
    Command::new("notify-send").arg(title).arg(body).spawn()?.wait()?;
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn try_send(_title: &str, _body: &str) -> std::io::Result<()> {
    Ok(())
}
