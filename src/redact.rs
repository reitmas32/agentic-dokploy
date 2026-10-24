//! What may reach stdout. Secrets never do: they are replaced in API
//! responses, and an env block is shown as its keys with the value lengths.

use serde_json::Value;

pub const REDACTED: &str = "[REDACTED]";

/// Keys whose value is a secret or may contain one.
fn is_secret_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    matches!(
        key.as_str(),
        "env" | "buildargs" | "buildsecrets" | "composefile" | "customgiturl" | "privatekey"
    ) || [
        "password",
        "secret",
        "token",
        "apikey",
        "api_key",
        "credential",
        "privatekey",
        "private_key",
        "passphrase",
        "cookie",
        "authorization",
    ]
    .iter()
    .any(|needle| key.contains(needle))
}

/// Replaces every secret value in a Dokploy response. `composeFile` is a
/// secret too: it usually embeds environment values.
pub fn redact(value: Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .into_iter()
                .map(|(key, value)| {
                    let value = if is_secret_key(&key) && !value.is_null() {
                        Value::String(REDACTED.into())
                    } else {
                        redact(value)
                    };
                    (key, value)
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.into_iter().map(redact).collect()),
        value => value,
    }
}

/// Compose labels with credential-bearing values hidden. Traefik middlewares
/// such as `basicauth.users` carry password hashes in a label.
pub fn redact_labels(labels: Value) -> Value {
    fn secret_label(key: &str) -> bool {
        let key = key.to_ascii_lowercase();
        [
            "basicauth",
            "digestauth",
            "password",
            "secret",
            "token",
            "users",
            "apikey",
            "credential",
        ]
        .iter()
        .any(|needle| key.contains(needle))
    }
    match labels {
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(
                    |item| match item.as_str().and_then(|label| label.split_once('=')) {
                        Some((key, _)) if secret_label(key) => {
                            Value::String(format!("{key}={REDACTED}"))
                        }
                        _ => item,
                    },
                )
                .collect(),
        ),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| {
                    let value = if secret_label(&key) {
                        Value::String(REDACTED.into())
                    } else {
                        value
                    };
                    (key, value)
                })
                .collect(),
        ),
        other => other,
    }
}

/// One line of an env block as it may be shown: the key and the value length.
#[derive(Debug, PartialEq, Eq, serde::Serialize)]
pub struct EnvLine {
    pub key: String,
    pub length: usize,
}

/// The keys of a dotenv-style block, in order, without their values.
pub fn env_keys(env: &str) -> Vec<EnvLine> {
    env.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let line = line.strip_prefix("export ").unwrap_or(line);
            let (key, value) = line.split_once('=')?;
            Some(EnvLine {
                key: key.trim().to_owned(),
                length: value.chars().count(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn nested_secrets_are_redacted() {
        let out = redact(json!({
            "name": "api",
            "env": "A=1",
            "composeFile": "services: {}",
            "refreshToken": "abc",
            "registry": {"password": "p", "username": "u"},
            "sshKeys": [{"privateKey": "k", "name": "deploy"}],
            "description": null
        }));
        assert_eq!(out["name"], "api");
        assert_eq!(out["env"], REDACTED);
        assert_eq!(out["composeFile"], REDACTED);
        assert_eq!(out["refreshToken"], REDACTED);
        assert_eq!(out["registry"]["password"], REDACTED);
        assert_eq!(out["registry"]["username"], "u");
        assert_eq!(out["sshKeys"][0]["privateKey"], REDACTED);
        assert!(out["description"].is_null());
    }

    #[test]
    fn credential_labels_are_redacted() {
        let out = redact_labels(json!([
            "traefik.enable=true",
            "traefik.http.middlewares.auth.basicauth.users=admin:$apr1$hash",
            "traefik.http.routers.web.rule=Host(`docs.example.com`)"
        ]));
        assert_eq!(out[0], "traefik.enable=true");
        assert_eq!(
            out[1],
            format!("traefik.http.middlewares.auth.basicauth.users={REDACTED}")
        );
        assert_eq!(
            out[2],
            "traefik.http.routers.web.rule=Host(`docs.example.com`)"
        );
    }

    #[test]
    fn env_shows_keys_and_lengths_only() {
        let lines = env_keys("# comment\nDOMAIN=docs.example.com\n\nexport TOKEN=abc\nEMPTY=\n");
        assert_eq!(
            lines,
            vec![
                EnvLine {
                    key: "DOMAIN".into(),
                    length: 16
                },
                EnvLine {
                    key: "TOKEN".into(),
                    length: 3
                },
                EnvLine {
                    key: "EMPTY".into(),
                    length: 0
                },
            ]
        );
    }
}
