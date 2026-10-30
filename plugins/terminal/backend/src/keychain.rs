//! Secrets a command asked for (a password, a key's passphrase), kept in the macOS Keychain when
//! the user chose to remember them. Each is a generic password of the service [`SERVICE`] whose
//! account is the ask's key (`<program> · <prompt>`, such as `sudo · Password:`). CortexTerm keeps
//! no copy anywhere else.

pub const SERVICE: &str = "CortexTerm prompt";

#[cfg(target_os = "macos")]
pub fn get(key: &str) -> Option<String> {
    let bytes = security_framework::passwords::get_generic_password(SERVICE, key).ok()?;
    String::from_utf8(bytes).ok()
}

#[cfg(target_os = "macos")]
pub fn set(key: &str, secret: &str) -> Result<(), String> {
    security_framework::passwords::set_generic_password(SERVICE, key, secret.as_bytes()).map_err(|e| format!("Keychain: {e}"))
}

#[cfg(target_os = "macos")]
pub fn delete(key: &str) -> Result<(), String> {
    match security_framework::passwords::delete_generic_password(SERVICE, key) {
        Ok(()) => Ok(()),
        // Already gone.
        Err(error) if error.code() == -25300 => Ok(()),
        Err(error) => Err(format!("Keychain: {error}")),
    }
}

#[cfg(not(target_os = "macos"))]
pub fn get(_key: &str) -> Option<String> {
    None
}

#[cfg(not(target_os = "macos"))]
pub fn set(_key: &str, _secret: &str) -> Result<(), String> {
    Err("secrets can only be remembered on macOS".into())
}

#[cfg(not(target_os = "macos"))]
pub fn delete(_key: &str) -> Result<(), String> {
    Ok(())
}
