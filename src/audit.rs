use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

#[derive(Serialize)]
pub struct AuditEvent<'a> {
    pub timestamp: DateTime<Utc>,
    pub organization: &'a str,
    pub instance: &'a str,
    pub operation: &'a str,
    pub plan_id: &'a str,
    pub outcome: &'a str,
    /// Why a plan failed, without response bodies (they are never logged).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<&'a str>,
}

pub fn append(path: &Path, event: &AuditEvent<'_>) -> Result<()> {
    ensure_parent(path)?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("cannot open audit log {}", path.display()))?;
    restrict(&file)?;
    writeln!(file, "{}", serde_json::to_string(event)?).context("cannot write audit log")?;
    Ok(())
}

pub fn ensure_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

#[cfg(unix)]
pub fn restrict(file: &std::fs::File) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(())
}
#[cfg(not(unix))]
pub fn restrict(_: &std::fs::File) -> Result<()> {
    Ok(())
}
