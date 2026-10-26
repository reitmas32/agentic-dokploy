//! Container and deployment logs as a harness may see them.
//!
//! Dokploy answers `<router>.readLogs` (the last lines of `docker logs
//! --timestamps`, without follow) and `deployment.readLogs` (the build log) as
//! plain text. None of it reaches stdout before `Redactor` replaces the
//! service's own secret values, URL credentials, `Authorization` and `Bearer`
//! values, JWTs, PEM blocks, well-known token formats and
//! `password=` / `secret:` / `token=` style pairs.

use crate::failure::{Kind, fail_with};
use crate::redact::{REDACTED, env_pairs, is_secret_key};
use anyhow::{Result, bail};
use regex::{Captures, Regex};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::sync::LazyLock;

/// The most lines Dokploy's `readLogs` returns.
pub const DOKPLOY_TAIL_MAX: u32 = 10_000;
/// Shortest secret value searched for literally: shorter ones (`true`,
/// `5432`) would blank out unrelated text.
const MIN_SECRET_LEN: usize = 6;
/// A PEM block without an END line stops being redacted after this many
/// lines (an RSA-8192 key is about 100), so a stray BEGIN cannot hide a log.
const PEM_MAX_LINES: usize = 150;
/// Longest `--search` text, as in Dokploy.
const SEARCH_MAX_LEN: usize = 500;

// ------------------------------------------------------------------ params

/// `--tail`: at least one line and at most `max` (`security.log_tail_max`).
pub fn validate_tail(tail: u32, max: u32) -> Result<()> {
    if tail == 0 {
        bail!("--tail must be at least 1");
    }
    if tail > max {
        bail!(
            "--tail {tail} is above the limit of {max} lines; narrow it with --since or --search, or raise security.log_tail_max (at most {DOKPLOY_TAIL_MAX})"
        );
    }
    Ok(())
}

/// `--since`: `all` or a whole number of seconds, minutes, hours or days
/// (`30s`, `10m`, `1h`, `2d`), the format Dokploy accepts, returned as
/// `docker logs` takes it. Docker reads Go durations, which have no days, so
/// `2d` is sent as `48h`.
pub fn docker_since(since: &str) -> Result<String> {
    if since == "all" {
        return Ok(since.to_owned());
    }
    let invalid = || {
        anyhow::anyhow!(
            "--since must be `all` or a duration such as 30s, 10m, 1h or 2d, got {since:?}"
        )
    };
    let unit = since
        .chars()
        .last()
        .filter(|u| "smhd".contains(*u))
        .ok_or_else(invalid)?;
    let amount = &since[..since.len() - 1];
    if amount.is_empty() || !amount.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid());
    }
    let amount: u32 = amount.parse().map_err(|_| invalid())?;
    Ok(match unit {
        'd' => format!("{}h", u64::from(amount) * 24),
        _ => since.to_owned(),
    })
}

/// `--search` is matched here, on redacted lines, and never sent to Dokploy:
/// a server-side filter runs on the raw log, so whether it matched would tell
/// a caller what a secret starts with. Without a shell in between, any text
/// works except control characters.
pub fn validate_search(search: &str) -> Result<()> {
    if search.is_empty() {
        bail!("--search cannot be empty");
    }
    if search.chars().count() > SEARCH_MAX_LEN {
        bail!("--search is longer than {SEARCH_MAX_LEN} characters");
    }
    if search.chars().any(char::is_control) {
        bail!("--search cannot contain control characters");
    }
    Ok(())
}

// -------------------------------------------------------------- containers

/// A container of a Compose, from `docker.getContainersByAppNameMatch`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Container {
    pub id: String,
    pub name: String,
    pub state: String,
    /// The Compose service it runs (`web` for `<appName>-web-1`).
    pub service: Option<String>,
}

pub fn containers(response: &Value, app_name: &str) -> Vec<Container> {
    let text = |item: &Value, key: &str| {
        item.get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    response
        .as_array()
        .into_iter()
        .flatten()
        .map(|item| {
            let name = text(item, "name");
            Container {
                id: text(item, "containerId"),
                service: compose_service(&name, app_name).map(str::to_owned),
                state: text(item, "state"),
                name,
            }
        })
        .collect()
}

/// The service in a container name: `<app>-<service>-<index>` for Docker
/// Compose, `<app>_<service>.<slot>.<task>` for a Swarm stack.
pub fn compose_service<'a>(name: &'a str, app_name: &str) -> Option<&'a str> {
    let rest = name.strip_prefix(app_name)?.strip_prefix(['-', '_'])?;
    if let Some((service, index)) = rest.rsplit_once('-') {
        if !index.is_empty() && index.bytes().all(|b| b.is_ascii_digit()) {
            return Some(service);
        }
    }
    Some(rest.split_once('.').map_or(rest, |(service, _)| service))
}

/// The container whose logs to read. `wanted` is a Compose service, a
/// container name or a container id; without it the Compose must run a
/// single container. Among several matches a lone running one wins.
pub fn pick_container<'a>(
    containers: &'a [Container],
    wanted: Option<&str>,
    label: &str,
) -> Result<&'a Container> {
    let details = || {
        let services: BTreeSet<_> = containers
            .iter()
            .filter_map(|c| c.service.clone())
            .collect();
        json!({
            "candidates": services,
            "containers": containers.iter().map(|c| json!({"name": c.name, "service": c.service, "state": c.state})).collect::<Vec<_>>()
        })
    };
    let Some(wanted) = wanted else {
        return match containers {
            [only] => Ok(only),
            [] => Err(fail_with(
                Kind::ServiceNotFound,
                format!("{label} has no containers; check that it is deployed (`get service`)"),
                details(),
            )),
            _ => Err(fail_with(
                Kind::ServiceAmbiguous,
                format!(
                    "{label} runs {} containers: pass --container with one of details.candidates",
                    containers.len()
                ),
                details(),
            )),
        };
    };
    let matches: Vec<&Container> = containers
        .iter()
        .filter(|c| {
            c.name == wanted
                || c.id == wanted
                || (!c.id.is_empty() && wanted.len() > c.id.len() && wanted.starts_with(&c.id))
                || c.service.as_deref() == Some(wanted)
        })
        .collect();
    let running: Vec<&Container> = matches
        .iter()
        .copied()
        .filter(|c| c.state == "running")
        .collect();
    match (matches.as_slice(), running.as_slice()) {
        ([only], _) | (_, [only]) => Ok(*only),
        ([], _) => Err(fail_with(
            Kind::ServiceNotFound,
            format!("no container of {label} matches {wanted:?}; see details.candidates"),
            details(),
        )),
        _ => Err(fail_with(
            Kind::ServiceAmbiguous,
            format!(
                "{wanted:?} matches {} containers of {label}: pass one container name",
                matches.len()
            ),
            json!({"candidates": matches.iter().map(|c| &c.name).collect::<Vec<_>>()}),
        )),
    }
}

// ---------------------------------------------------------------- redactor

static ANSI_ESCAPE: LazyLock<Regex> = LazyLock::new(|| compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]"));
static PEM_BEGIN: LazyLock<Regex> = LazyLock::new(|| compile(r"-----BEGIN [A-Z0-9 ]+-----"));
static PEM_END: LazyLock<Regex> = LazyLock::new(|| compile(r"-----END [A-Z0-9 ]+-----"));
/// `scheme://user:password@`: the password, up to the last `@` of the URL.
static URL_PASSWORD: LazyLock<Regex> =
    LazyLock::new(|| compile(r"(?P<keep>\b[A-Za-z][A-Za-z0-9+.\-]*://[^\s:/@]*:)[^\s/]+@"));
/// `scheme://<long token>@`: a token used as the user (Sentry DSN, Git URLs).
static URL_TOKEN_USER: LazyLock<Regex> =
    LazyLock::new(|| compile(r"(?P<keep>\b[A-Za-z][A-Za-z0-9+.\-]*://)[^\s:/@]{20,}@"));
static AUTHORIZATION: LazyLock<Regex> = LazyLock::new(|| {
    compile(r#"(?i)(?P<keep>\b(?:proxy-)?authorization["']?\s*[:=]\s*["']?)[^"'\r\n]+"#)
});
static BEARER: LazyLock<Regex> =
    LazyLock::new(|| compile(r"(?i)(?P<keep>\bbearer\s+)[A-Za-z0-9\-._~+/]{8,}=*"));
static JWT: LazyLock<Regex> =
    LazyLock::new(|| compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*"));
/// GitHub, GitLab, Slack, OpenAI/Anthropic, Stripe and AWS access keys.
static KNOWN_TOKENS: LazyLock<Regex> = LazyLock::new(|| {
    compile(concat!(
        r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|glpat-[A-Za-z0-9_\-]{20,}",
        r"|xox[abprs]-[A-Za-z0-9\-]{10,}|sk-[A-Za-z0-9_\-]{20,}",
        r"|(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{10,}|whsec_[A-Za-z0-9]{10,}|AKIA[0-9A-Z]{16})\b"
    ))
});
/// `password=x`, `"api_key": "x"`, `'SECRET_KEY': 'x'`, `Set-Cookie: x`.
static SECRET_PAIR: LazyLock<Regex> = LazyLock::new(|| {
    compile(concat!(
        r#"(?i)(?P<keep>[A-Za-z0-9_.\-]*(?:password|passwd|secret|token|api[_\-]?key|access[_\-]?key|private[_\-]?key|credential|cookie)"#,
        r#"[A-Za-z0-9_.\-]*["']?\s*[:=]\s*)(?P<value>"[^"]*"|'[^']*'|[^\s"',;&)\]}]+)"#
    ))
});

fn compile(pattern: &str) -> Regex {
    Regex::new(pattern).expect("log redaction patterns are valid")
}

/// One log line: Docker's timestamp, when it has one, and the redacted text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LogLine {
    pub ts: Option<String>,
    pub line: String,
}

impl LogLine {
    /// Whether the line contains `needle`, ignoring case like `grep -i`.
    pub fn contains(&self, needle: &str) -> bool {
        let needle = needle.to_lowercase();
        self.line.to_lowercase().contains(&needle)
            || self
                .ts
                .as_deref()
                .is_some_and(|ts| ts.to_lowercase().contains(&needle))
    }
}

/// Replaces secrets in log text: the literal values of one service's secrets
/// plus patterns that look like credentials in any log.
#[derive(Debug, Default)]
pub struct Redactor {
    /// Longest first, so a secret containing another is replaced whole.
    secrets: Vec<String>,
}

impl Redactor {
    pub fn new(secrets: impl IntoIterator<Item = String>) -> Self {
        let mut secrets: Vec<String> = secrets
            .into_iter()
            .filter(|s| s.chars().count() >= MIN_SECRET_LEN)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
        Self { secrets }
    }

    /// A redactor for the logs of the service whose `<router>.one` detail
    /// this is: its env and build values under secret-looking keys, secrets
    /// written in its Compose, passwords in its URLs and any other field with
    /// a secret key (database passwords, private keys).
    pub fn for_service(detail: &Value) -> Self {
        let mut secrets = Vec::new();
        collect_secrets(detail, &mut secrets);
        Self::new(secrets)
    }

    /// Number of literal values this redactor looks for.
    pub fn secret_count(&self) -> usize {
        self.secrets.len()
    }

    /// Splits a log into lines and redacts each. PEM blocks span lines, so
    /// they are tracked across them.
    pub fn lines(&self, text: &str) -> Vec<LogLine> {
        let mut pem_lines_left = 0;
        text.lines()
            .map(|raw| {
                let raw = ANSI_ESCAPE.replace_all(raw, "");
                let (ts, message) = split_timestamp(&raw);
                let message = redact_pem(message, &mut pem_lines_left);
                LogLine {
                    ts: ts.map(str::to_owned),
                    line: self.redact(&message),
                }
            })
            .collect()
    }

    /// Free text (a config file, a log) redacted line by line and returned
    /// whole: lines, timestamps and a final newline are kept.
    pub fn text(&self, text: &str) -> String {
        let mut pem_lines_left = 0;
        let mut out: Vec<String> = text
            .lines()
            .map(|line| self.redact(&redact_pem(line, &mut pem_lines_left)))
            .collect();
        if text.ends_with('\n') {
            out.push(String::new());
        }
        out.join("\n")
    }

    /// One line of text with every secret replaced. PEM blocks need `lines`.
    pub fn redact(&self, text: &str) -> String {
        let mut text = text.to_owned();
        for secret in &self.secrets {
            if text.contains(secret.as_str()) {
                text = text.replace(secret.as_str(), REDACTED);
            }
        }
        let keep = |caps: &Captures| format!("{}{REDACTED}", &caps["keep"]);
        for pattern in [&URL_PASSWORD, &URL_TOKEN_USER] {
            text = pattern
                .replace_all(&text, |caps: &Captures| format!("{}@", keep(caps)))
                .into_owned();
        }
        for pattern in [&AUTHORIZATION, &BEARER] {
            text = pattern.replace_all(&text, keep).into_owned();
        }
        for pattern in [&JWT, &KNOWN_TOKENS] {
            text = pattern.replace_all(&text, REDACTED).into_owned();
        }
        SECRET_PAIR
            .replace_all(&text, |caps: &Captures| {
                let value = &caps["value"];
                let quote = value.chars().next().filter(|c| matches!(c, '"' | '\''));
                if value
                    .trim_matches(['"', '\''])
                    .starts_with(&REDACTED[..REDACTED.len() - 1])
                {
                    caps[0].to_owned()
                } else if let Some(quote) = quote {
                    format!("{}{quote}{REDACTED}{quote}", &caps["keep"])
                } else {
                    keep(caps)
                }
            })
            .into_owned()
    }
}

/// `2026-10-26T04:02:58.295905747Z message` → the timestamp and the message.
fn split_timestamp(line: &str) -> (Option<&str>, &str) {
    let (first, rest) = line.split_once(' ').unwrap_or((line, ""));
    if chrono::DateTime::parse_from_rfc3339(first).is_ok() {
        (Some(first), rest)
    } else {
        (None, line)
    }
}

/// Replaces PEM blocks from their BEGIN line to their END line, whole lines
/// in between included. `lines_left` carries an open block to the next line.
fn redact_pem(message: &str, lines_left: &mut usize) -> String {
    let mut out = String::new();
    let mut rest = message;
    loop {
        if *lines_left > 0 {
            out.push_str(REDACTED);
            match PEM_END.find(rest) {
                Some(end) => {
                    rest = &rest[end.end()..];
                    *lines_left = 0;
                }
                None => {
                    *lines_left -= 1;
                    return out;
                }
            }
        } else {
            match PEM_BEGIN.find(rest) {
                Some(begin) => {
                    out.push_str(&rest[..begin.start()]);
                    rest = &rest[begin.end()..];
                    *lines_left = PEM_MAX_LINES;
                }
                None => {
                    out.push_str(rest);
                    return out;
                }
            }
        }
    }
}

/// Env variables whose value is a secret: `is_secret_key`, plus the `*_KEY`
/// and `*_DSN` names that carry keys without saying so (`BOT_SERVICE_KEY`).
fn is_secret_env_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    is_secret_key(key) || lower.ends_with("key") || lower.contains("dsn")
}

fn collect_secrets(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                match (key.to_ascii_lowercase().as_str(), value) {
                    ("env" | "buildargs" | "buildsecrets", Value::String(block)) => {
                        for (key, value) in env_pairs(block) {
                            env_secret(key, value, out);
                        }
                    }
                    ("composefile", Value::String(file)) => compose_secrets(file, out),
                    (_, Value::String(text)) if is_secret_key(key) => push_secret(text, out),
                    _ => collect_secrets(value, out),
                }
            }
        }
        Value::Array(items) => items.iter().for_each(|item| collect_secrets(item, out)),
        _ => {}
    }
}

fn env_secret(key: &str, value: &str, out: &mut Vec<String>) {
    if is_secret_env_key(key) {
        push_secret(value, out);
    } else if let Some(password) = url_password(unquote(value)) {
        out.push(password.to_owned());
    }
}

/// Values written in the `environment` of a Compose's services. `${VAR}`
/// references are skipped: their values come from the env block.
fn compose_secrets(file: &str, out: &mut Vec<String>) {
    let Ok(yaml) = serde_yaml::from_str::<serde_yaml::Value>(file) else {
        return;
    };
    let scalar = |value: &serde_yaml::Value| match value {
        serde_yaml::Value::String(s) => Some(s.clone()),
        serde_yaml::Value::Number(n) => Some(n.to_string()),
        _ => None,
    };
    let services = yaml.get("services").and_then(serde_yaml::Value::as_mapping);
    for service in services.into_iter().flat_map(|s| s.values()) {
        let mut pairs = Vec::new();
        match service.get("environment") {
            Some(serde_yaml::Value::Mapping(map)) => {
                for (key, value) in map {
                    if let (Some(key), Some(value)) = (key.as_str(), scalar(value)) {
                        pairs.push((key.to_owned(), value));
                    }
                }
            }
            Some(serde_yaml::Value::Sequence(items)) => {
                for item in items.iter().filter_map(serde_yaml::Value::as_str) {
                    if let Some((key, value)) = item.split_once('=') {
                        pairs.push((key.to_owned(), value.to_owned()));
                    }
                }
            }
            _ => {}
        }
        for (key, value) in pairs {
            if !value.contains("${") {
                env_secret(&key, &value, out);
            }
        }
    }
}

/// A secret value as a whole and, when it spans lines (a PEM key, possibly
/// with escaped `\n`), each line on its own.
fn push_secret(value: &str, out: &mut Vec<String>) {
    let value = unquote(value.trim());
    out.push(value.to_owned());
    for line in value.split('\n').flat_map(|line| line.split("\\n")) {
        let line = line.trim();
        if !line.starts_with("-----") {
            out.push(line.to_owned());
        }
    }
    if let Some(password) = url_password(value) {
        out.push(password.to_owned());
    }
}

fn url_password(value: &str) -> Option<&str> {
    let (_, rest) = value.split_once("://")?;
    let authority = rest.split('/').next()?;
    let (userinfo, _) = authority.rsplit_once('@')?;
    let (_, password) = userinfo.split_once(':')?;
    Some(password)
}

fn unquote(value: &str) -> &str {
    for quote in ['"', '\''] {
        if let Some(inner) = value
            .strip_prefix(quote)
            .and_then(|v| v.strip_suffix(quote))
        {
            return inner;
        }
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    fn redacted(redactor: &Redactor, text: &str) -> Vec<String> {
        redactor.lines(text).into_iter().map(|l| l.line).collect()
    }

    #[test]
    fn tail_is_bounded() {
        assert!(validate_tail(1, 2000).is_ok());
        assert!(validate_tail(2000, 2000).is_ok());
        assert!(validate_tail(0, 2000).is_err());
        assert!(validate_tail(2001, 2000).is_err());
    }

    #[test]
    fn since_follows_dokploy_and_speaks_docker() {
        for (since, docker) in [
            ("all", "all"),
            ("30s", "30s"),
            ("10m", "10m"),
            ("1h", "1h"),
            ("0s", "0s"),
            ("2d", "48h"),
        ] {
            assert_eq!(docker_since(since).unwrap(), docker, "{since}");
        }
        for bad in [
            "",
            "10",
            "m",
            "1w",
            "1h30m",
            "-1h",
            "1.5h",
            "10m;id",
            "ALL",
            " 1h",
            "1hé",
            "99999999999d",
        ] {
            assert!(docker_since(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn search_rejects_control_characters_and_long_text() {
        assert!(validate_search("InterfaceError: connection already closed").is_ok());
        assert!(validate_search("/api/v1/auth").is_ok());
        assert!(validate_search("").is_err());
        assert!(validate_search("a\nb").is_err());
        assert!(validate_search(&"x".repeat(501)).is_err());
    }

    #[test]
    fn search_ignores_case() {
        let line = LogLine {
            ts: None,
            line: "psycopg2.InterfaceError: connection already closed".into(),
        };
        assert!(line.contains("CONNECTION ALREADY"));
        assert!(!line.contains("timeout"));
    }

    fn sample_containers() -> Vec<Container> {
        let app = "compose-quantify-wireless-alarm-qzu21r";
        containers(
            &json!([
                {"containerId": "038cb9e85ab9", "name": format!("{app}-worker-1"), "state": "running"},
                {"containerId": "0423b8ddf4ae", "name": format!("{app}-web-1"), "state": "exited"},
                {"containerId": "1423b8ddf4ae", "name": format!("{app}-web-2"), "state": "running"},
                {"containerId": "2423b8ddf4ae", "name": format!("{app}-beat-1"), "state": "running"}
            ]),
            app,
        )
    }

    #[test]
    fn container_names_map_to_compose_services() {
        assert_eq!(compose_service("app-web-1", "app"), Some("web"));
        assert_eq!(
            compose_service("app-celery-worker-12", "app"),
            Some("celery-worker")
        );
        assert_eq!(compose_service("app_web.1.k2j3h4", "app"), Some("web"));
        assert_eq!(compose_service("other-web-1", "app"), None);
    }

    #[test]
    fn containers_are_picked_by_service_name_or_id() {
        let containers = sample_containers();
        let pick = |wanted: Option<&str>| {
            pick_container(&containers, wanted, "svc").map(|c| c.name.clone())
        };
        let app = "compose-quantify-wireless-alarm-qzu21r";
        assert_eq!(pick(Some("worker")).unwrap(), format!("{app}-worker-1"));
        // web-1 exited, web-2 runs: the running one wins.
        assert_eq!(pick(Some("web")).unwrap(), format!("{app}-web-2"));
        assert_eq!(
            pick(Some(&format!("{app}-web-1"))).unwrap(),
            format!("{app}-web-1")
        );
        assert_eq!(pick(Some("2423b8ddf4ae")).unwrap(), format!("{app}-beat-1"));
        assert_eq!(
            pick(Some(
                "2423b8ddf4ae0000000000000000000000000000000000000000000000000000"
            ))
            .unwrap(),
            format!("{app}-beat-1")
        );
        let missing = pick_container(&containers, Some("api"), "svc").unwrap_err();
        let (report, code) = crate::failure::report(&missing);
        assert_eq!(code, Kind::ServiceNotFound.exit_code());
        assert_eq!(
            report["error"]["details"]["candidates"],
            json!(["beat", "web", "worker"])
        );
        let ambiguous = pick_container(&containers, None, "svc").unwrap_err();
        assert_eq!(
            crate::failure::report(&ambiguous).1,
            Kind::ServiceAmbiguous.exit_code()
        );
        assert!(pick_container(&containers[..1], None, "svc").is_ok());
        assert!(pick_container(&[], None, "svc").is_err());
    }

    #[test]
    fn service_secret_values_are_redacted_literally() {
        let detail = json!({
            "name": "core",
            "env": "DEBUG=True\nSECRET_KEY=\"django-insecure-abc123\"\nBOT_SERVICE_KEY=bot-key-777\nAPI_KEY=short\nDATABASE_URL=postgres://core:pg-pass-42@db:5432/core\nPORT=8000\nAPP_NAME=konectus-core",
            "composeFile": "services:\n  web:\n    environment:\n      REDIS_PASSWORD: redis-inline-9\n      OTHER_TOKEN: ${OTHER_TOKEN}\n  worker:\n    environment:\n      - CELERY_SECRET=celery-secret-1\n",
            "databasePassword": "native-db-pass",
            "sshKey": {"privateKey": "line-one-aaaa\nline-two-bbbb"}
        });
        let redactor = Redactor::for_service(&detail);
        let out = redacted(
            &redactor,
            "booting konectus-core on 8000 DEBUG=True\nkey django-insecure-abc123 bot bot-key-777 short\nconnect pg-pass-42 redis-inline-9 celery-secret-1 native-db-pass\nline-two-bbbb\n${OTHER_TOKEN}",
        );
        assert_eq!(out[0], "booting konectus-core on 8000 DEBUG=True");
        assert_eq!(out[1], "key [REDACTED] bot [REDACTED] short");
        assert_eq!(
            out[2],
            "connect [REDACTED] [REDACTED] [REDACTED] [REDACTED]"
        );
        assert_eq!(out[3], "[REDACTED]");
        assert_eq!(out[4], "${OTHER_TOKEN}");
    }

    #[test]
    fn credential_patterns_are_redacted() {
        let redactor = Redactor::default();
        let cases = [
            (
                "conn postgres://core:s3cr3t@db.internal:5432/core failed",
                "conn postgres://core:[REDACTED]@db.internal:5432/core failed",
            ),
            (
                "redis://:p@ss@redis:6379/0",
                "redis://:[REDACTED]@redis:6379/0",
            ),
            (
                "sentry https://0123456789abcdef0123456789abcdef@o1.ingest.sentry.io/4",
                "sentry https://[REDACTED]@o1.ingest.sentry.io/4",
            ),
            (
                "http://localhost:8000/health ok",
                "http://localhost:8000/health ok",
            ),
            (
                "Authorization: Basic dXNlcjpwYXNz",
                "Authorization: [REDACTED]",
            ),
            (
                r#"{"authorization": "Bearer abc.def", "path": "/x"}"#,
                r#"{"authorization": "[REDACTED]", "path": "/x"}"#,
            ),
            (
                "curl -H 'bearer abcdefgh12345678'",
                "curl -H 'bearer [REDACTED]'",
            ),
            (
                "jwt eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlX2hlcmU done",
                "jwt [REDACTED] done",
            ),
            ("key sk_live_51Hxxxxxxxxxxxx end", "key [REDACTED] end"),
            ("aws AKIAIOSFODNN7EXAMPLE", "aws [REDACTED]"),
            (
                "login password=hunter2&user=bob",
                "login password=[REDACTED]&user=bob",
            ),
            ("DB_PASSWORD: hunter2", "DB_PASSWORD: [REDACTED]"),
            (
                "{'PASSWORD': 'two words', 'HOST': 'db'}",
                "{'PASSWORD': '[REDACTED]', 'HOST': 'db'}",
            ),
            (
                r#"{"api_key":"k-123","n":1}"#,
                r#"{"api_key":"[REDACTED]","n":1}"#,
            ),
            ("?token=abc123&page=2", "?token=[REDACTED]&page=2"),
            ("SECRET_KEY = 'django-x'", "SECRET_KEY = '[REDACTED]'"),
            (
                "Set-Cookie: sessionid=abc; Path=/",
                "Set-Cookie: [REDACTED]; Path=/",
            ),
            (
                "psycopg2.InterfaceError: connection already closed",
                "psycopg2.InterfaceError: connection already closed",
            ),
            (
                r#"File "/app/core/token_service.py", line 10"#,
                r#"File "/app/core/token_service.py", line 10"#,
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(redactor.redact(input), expected, "{input}");
        }
    }

    #[test]
    fn already_redacted_values_stay_single() {
        let redactor = Redactor::new(["hunter2-long".to_owned()]);
        assert_eq!(
            redactor.redact("password=hunter2-long \"token\": \"hunter2-long\""),
            "password=[REDACTED] \"token\": \"[REDACTED]\""
        );
    }

    #[test]
    fn pem_blocks_are_redacted_across_lines() {
        let redactor = Redactor::default();
        let text = "2026-10-26T04:02:58.295905747Z loading key\n\
                    2026-10-26T04:02:58.295905748Z -----BEGIN PRIVATE KEY-----\n\
                    2026-10-26T04:02:58.295905749Z MIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n\
                    2026-10-26T04:02:58.295905750Z -----END PRIVATE KEY----- loaded\n\
                    2026-10-26T04:02:58.295905751Z key=\"-----BEGIN RSA PRIVATE KEY-----\\nMIIB\\n-----END RSA PRIVATE KEY-----\" ok\n\
                    2026-10-26T04:02:58.295905752Z after";
        let lines = redactor.lines(text);
        let shown: Vec<&str> = lines.iter().map(|l| l.line.as_str()).collect();
        assert_eq!(
            shown,
            [
                "loading key",
                "[REDACTED]",
                "[REDACTED]",
                "[REDACTED] loaded",
                "key=\"[REDACTED]\" ok",
                "after"
            ]
        );
        assert_eq!(
            lines[0].ts.as_deref(),
            Some("2026-10-26T04:02:58.295905747Z")
        );
    }

    #[test]
    fn text_is_redacted_and_keeps_its_shape() {
        let text = "providers:\n  docker:\n    endpoint: tcp://admin:hunter22@docker:2375\n\
                    acme:\n  email: ops@example.com\n\
                    key: |\n  -----BEGIN EC PRIVATE KEY-----\n  MHcCAQEEIB\n  -----END EC PRIVATE KEY-----\n\
                    2026-10-26T04:02:58Z token: abc123\n";
        assert_eq!(
            Redactor::default().text(text),
            "providers:\n  docker:\n    endpoint: tcp://admin:[REDACTED]@docker:2375\n\
             acme:\n  email: ops@example.com\n\
             key: |\n  [REDACTED]\n[REDACTED]\n[REDACTED]\n\
             2026-10-26T04:02:58Z token: [REDACTED]\n"
        );
        assert_eq!(Redactor::default().text("no newline"), "no newline");
    }

    #[test]
    fn an_unterminated_pem_block_ends_after_a_bound() {
        let mut text = String::from("-----BEGIN CERTIFICATE-----\n");
        for _ in 0..PEM_MAX_LINES + 5 {
            text.push_str("QUJD\n");
        }
        text.push_str("visible again");
        let lines = Redactor::default().lines(&text);
        assert!(lines[..PEM_MAX_LINES].iter().all(|l| l.line == REDACTED));
        assert_eq!(lines[PEM_MAX_LINES].line, "QUJD");
        assert_eq!(lines.last().unwrap().line, "visible again");
    }

    #[test]
    fn timestamps_and_colors_are_split_off() {
        let lines = Redactor::default().lines(
            "2026-10-26T04:03:06.876302561Z \x1b[31mERROR\x1b[0m boom\r\nplain deploy line\n2026-10-26T04:03:06Z \n",
        );
        assert_eq!(
            lines,
            [
                LogLine {
                    ts: Some("2026-10-26T04:03:06.876302561Z".into()),
                    line: "ERROR boom".into()
                },
                LogLine {
                    ts: None,
                    line: "plain deploy line".into()
                },
                LogLine {
                    ts: Some("2026-10-26T04:03:06Z".into()),
                    line: String::new()
                },
            ]
        );
    }
}
