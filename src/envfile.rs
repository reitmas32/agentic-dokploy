//! Instances defined as one dotenv file each, in `instances/<organization>.env`
//! next to the configuration:
//!
//! ```text
//! DOKPLOY_URL=https://dokploy.example.com
//! DOKPLOY_API_KEY=…
//! DOKPLOY_PATHS=~/work/example
//! ```
//!
//! The file holds a secret, so it must be a regular owner-only file inside an
//! owner-only directory. Values are taken literally: no variable expansion, no
//! command substitution. Unknown keys are an error, so a typo such as
//! `DOKPLOY_PATH` cannot silently drop the directory mapping.

use crate::config::{ApprovalMode, InstanceConfig};
use anyhow::{Context, Result, bail};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};
use url::Url;

const KNOWN_KEYS: [&str; 8] = [
    "DOKPLOY_URL",
    "DOKPLOY_API_KEY",
    "DOKPLOY_PATHS",
    "DOKPLOY_ORGANIZATION",
    "DOKPLOY_INSTANCE",
    "DOKPLOY_APPROVAL",
    "DOKPLOY_DEFAULT",
    "DOKPLOY_ALLOW_HTTP",
];

/// Parses `KEY=value` lines. Blank lines and `#` comments are skipped, an
/// optional `export ` prefix is accepted, and a value may be wrapped in single
/// or double quotes. Nothing is expanded.
pub fn parse(content: &str) -> Result<BTreeMap<String, String>> {
    let mut values = BTreeMap::new();
    for (number, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let (key, value) = line
            .split_once('=')
            .with_context(|| format!("line {}: expected KEY=value", number + 1))?;
        let key = key.trim();
        if !KNOWN_KEYS.contains(&key) {
            bail!(
                "line {}: unknown key {key}; expected one of {}",
                number + 1,
                KNOWN_KEYS.join(", ")
            );
        }
        let value = value.trim();
        let value = match (value.chars().next(), value.chars().last()) {
            (Some(q @ ('"' | '\'')), Some(end)) if value.len() >= 2 && q == end => {
                &value[1..value.len() - 1]
            }
            _ => value,
        };
        if values.insert(key.to_owned(), value.to_owned()).is_some() {
            bail!("line {}: {key} is defined twice", number + 1);
        }
    }
    Ok(values)
}

/// Reads an instance file after checking it cannot be read by anyone else.
pub fn read_protected(path: &Path) -> Result<BTreeMap<String, String>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("cannot read instance file {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!(
            "{} must be a regular file, not a symbolic link",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!(
                "{} holds an API key and must be owner-only (chmod 600)",
                path.display()
            );
        }
    }
    let content = fs::read_to_string(path)
        .with_context(|| format!("cannot read instance file {}", path.display()))?;
    parse(&content).with_context(|| format!("invalid instance file {}", path.display()))
}

/// The API key of an instance file, read when a request needs it.
pub fn api_key(path: &Path) -> Result<String> {
    let values = read_protected(path)?;
    let key = values
        .get("DOKPLOY_API_KEY")
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .with_context(|| format!("{} has no DOKPLOY_API_KEY", path.display()))?;
    Ok(key.to_owned())
}

fn expand_home(path: &str, home: &Path) -> PathBuf {
    match path.strip_prefix("~/") {
        Some(rest) => home.join(rest),
        None if path == "~" => home.to_path_buf(),
        None => PathBuf::from(path),
    }
}

fn boolean(values: &BTreeMap<String, String>, key: &str, path: &Path) -> Result<bool> {
    match values.get(key).map(|v| v.to_ascii_lowercase()) {
        None => Ok(false),
        Some(v) if v == "true" || v == "1" || v == "yes" => Ok(true),
        Some(v) if v == "false" || v == "0" || v == "no" || v.is_empty() => Ok(false),
        Some(v) => bail!("{}: {key} must be true or false, got {v:?}", path.display()),
    }
}

/// Builds the instance an env file describes. The organization defaults to
/// the file name (`globex.env` → `globex`), the instance to `production`.
pub fn instance_from_file(path: &Path, home: &Path) -> Result<InstanceConfig> {
    let values = read_protected(path)?;
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .context("instance file name must be UTF-8")?;
    let get = |key: &str| {
        values
            .get(key)
            .map(String::as_str)
            .filter(|v| !v.is_empty())
    };

    let base_url =
        get("DOKPLOY_URL").with_context(|| format!("{} has no DOKPLOY_URL", path.display()))?;
    let base_url = Url::parse(base_url)
        .with_context(|| format!("{}: DOKPLOY_URL is not a valid URL", path.display()))?;
    if get("DOKPLOY_API_KEY").is_none() {
        bail!("{} has no DOKPLOY_API_KEY", path.display());
    }
    let approval = match get("DOKPLOY_APPROVAL") {
        None => None,
        Some("token") => Some(ApprovalMode::Token),
        Some("terminal") => Some(ApprovalMode::Terminal),
        Some(other) => bail!(
            "{}: DOKPLOY_APPROVAL must be token or terminal, got {other:?}",
            path.display()
        ),
    };
    let paths = get("DOKPLOY_PATHS")
        .map(|list| {
            list.split([',', ':'])
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .map(|p| expand_home(p, home))
                .collect()
        })
        .unwrap_or_default();

    Ok(InstanceConfig {
        organization: get("DOKPLOY_ORGANIZATION").unwrap_or(stem).to_owned(),
        name: get("DOKPLOY_INSTANCE").unwrap_or("production").to_owned(),
        base_url,
        api_key_env: None,
        api_key_file: None,
        env_file: Some(path.to_path_buf()),
        approval,
        default: boolean(&values, "DOKPLOY_DEFAULT", path)?,
        allow_http: boolean(&values, "DOKPLOY_ALLOW_HTTP", path)?,
        paths,
    })
}

/// Every `*.env` file of an owner-only directory, in name order.
pub fn load_dir(directory: &Path, home: &Path) -> Result<Vec<InstanceConfig>> {
    let metadata = fs::symlink_metadata(directory)
        .with_context(|| format!("cannot read {}", directory.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!(
            "{} must be a directory, not a symbolic link",
            directory.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!(
                "{} holds API keys and must be owner-only (chmod 700)",
                directory.display()
            );
        }
    }
    let mut files: Vec<PathBuf> = fs::read_dir(directory)?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| path.extension().is_some_and(|ext| ext == "env"))
        .collect();
    files.sort();
    files
        .iter()
        .map(|file| instance_from_file(file, home))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_literal_values() {
        let values = parse(
            "# Globex\nexport DOKPLOY_URL=\"https://dokploy.globex.com\"\nDOKPLOY_API_KEY='abc$HOME'\n\nDOKPLOY_PATHS=~/work/globex, /srv/globex\n",
        )
        .unwrap();
        assert_eq!(values["DOKPLOY_URL"], "https://dokploy.globex.com");
        assert_eq!(values["DOKPLOY_API_KEY"], "abc$HOME");
        assert_eq!(values["DOKPLOY_PATHS"], "~/work/globex, /srv/globex");
    }

    #[test]
    fn rejects_typos_duplicates_and_garbage() {
        assert!(parse("DOKPLOY_PATH=/x").is_err());
        assert!(parse("DOKPLOY_URL=a\nDOKPLOY_URL=b").is_err());
        assert!(parse("just text").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn builds_an_instance_and_enforces_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let home = Path::new("/home/me");
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let file = directory.path().join("globex.env");
        fs::write(
            &file,
            "DOKPLOY_URL=https://dokploy.globex.com\nDOKPLOY_API_KEY=k-123\nDOKPLOY_PATHS=~/work/globex\nDOKPLOY_APPROVAL=terminal\n",
        )
        .unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_dir(directory.path(), home).is_err());

        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        let instances = load_dir(directory.path(), home).unwrap();
        let globex = &instances[0];
        assert_eq!(globex.label(), "globex/production");
        assert_eq!(globex.base_url.as_str(), "https://dokploy.globex.com/");
        assert_eq!(globex.paths, vec![PathBuf::from("/home/me/work/globex")]);
        assert_eq!(globex.approval, Some(ApprovalMode::Terminal));
        assert_eq!(globex.api_key().unwrap(), "k-123");
        assert!(!format!("{globex:?}").contains("k-123"));

        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(load_dir(directory.path(), home).is_err());
    }
}
