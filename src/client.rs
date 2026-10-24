use crate::config::InstanceConfig;
use anyhow::{Context, Result, bail};
use reqwest::{Client, Method};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;
use url::Url;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Clone)]
pub struct DokployClient {
    client: Client,
    base_url: Url,
    api_key: String,
}

impl DokployClient {
    pub fn new(instance: &InstanceConfig) -> Result<Self> {
        let api_key = instance.api_key()?;
        Ok(Self {
            client: http_client(instance)?,
            base_url: instance.base_url.clone(),
            api_key,
        })
    }

    pub async fn get(&self, operation: ReadOperation, query: &[(&str, &str)]) -> Result<Value> {
        self.get_procedure(operation.endpoint(), query).await
    }

    pub async fn post(&self, endpoint: WriteEndpoint, body: Value) -> Result<Value> {
        self.post_procedure(&endpoint.path(), body).await
    }

    /// GET /api/<procedure>. In Dokploy's tRPC API a GET can only run a query,
    /// never a mutation, so any well-formed procedure name is safe to read.
    pub async fn get_procedure(&self, procedure: &str, query: &[(&str, &str)]) -> Result<Value> {
        validate_procedure(procedure)?;
        self.request(Method::GET, procedure, query, None).await
    }

    /// POST /api/<procedure>. Only called from a reviewed plan.
    pub async fn post_procedure(&self, procedure: &str, body: Value) -> Result<Value> {
        validate_procedure(procedure)?;
        if is_destructive(procedure) {
            bail!(
                "refusing destructive procedure {procedure}: deletes are run by a person from the Dokploy panel"
            );
        }
        self.request(Method::POST, procedure, &[], Some(body)).await
    }

    /// Status code of a GET without reading the body; used to probe which
    /// read procedures exist on this panel.
    pub async fn probe(&self, procedure: &str) -> Result<u16> {
        validate_procedure(procedure)?;
        let response = self
            .client
            .get(self.url(procedure)?)
            .header("x-api-key", &self.api_key)
            .send()
            .await
            .map_err(|error| connection_error(&self.base_url, error))?;
        Ok(response.status().as_u16())
    }

    fn url(&self, procedure: &str) -> Result<Url> {
        self.base_url
            .join(&format!("api/{procedure}"))
            .context("invalid Dokploy API URL")
    }

    async fn request(
        &self,
        method: Method,
        procedure: &str,
        query: &[(&str, &str)],
        body: Option<Value>,
    ) -> Result<Value> {
        let request = self
            .client
            .request(method, self.url(procedure)?)
            .header("x-api-key", &self.api_key)
            .query(query);
        let response = match body {
            Some(body) => request.json(&body).send().await,
            None => request.send().await,
        }
        .map_err(|error| connection_error(&self.base_url, error))?;
        let status = response.status();
        let bytes = response
            .bytes()
            .await
            .context("cannot read Dokploy response")?;
        if !status.is_success() {
            // The body is withheld: a proxy or server could echo request data back.
            bail!("{procedure}: {}", status_hint(status.as_u16()));
        }
        if bytes.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_slice(&bytes).context("Dokploy returned non-JSON data")
    }
}

/// HTTP client used for every request: no redirects (the key must not follow
/// one to another host), HTTPS enforced for https instances, bounded timeout.
pub fn http_client(instance: &InstanceConfig) -> Result<Client> {
    Ok(Client::builder()
        .https_only(instance.base_url.scheme() == "https")
        .redirect(reqwest::redirect::Policy::none())
        .timeout(REQUEST_TIMEOUT)
        .user_agent(concat!("dokploy-agent/", env!("CARGO_PKG_VERSION")))
        .build()?)
}

fn status_hint(status: u16) -> String {
    match status {
        401 | 403 => format!(
            "HTTP {status}: the API key was rejected (check this instance's api_key_env or api_key_file; response body withheld)"
        ),
        404 => format!(
            "HTTP {status}: this procedure does not exist on this Dokploy version (list the real ones with `api`)"
        ),
        400 => format!("HTTP {status}: Dokploy rejected the parameters (response body withheld)"),
        _ => format!("HTTP {status} (response body withheld)"),
    }
}

fn connection_error(base_url: &Url, error: reqwest::Error) -> anyhow::Error {
    let host = base_url.host_str().unwrap_or("?");
    if error.is_timeout() {
        anyhow::anyhow!(
            "{host} did not answer in time. Run `doctor`: on a private panel this is usually the VPN"
        )
    } else if error.is_connect() {
        anyhow::anyhow!(
            "cannot connect to {host}. Run `doctor`: if the name does not resolve, the VPN is down"
        )
    } else {
        anyhow::anyhow!("Dokploy request failed: {error}")
    }
}

/// Procedure names look like `router.procedure` (`compose.one`, `settings.getDokployVersion`).
pub fn validate_procedure(procedure: &str) -> Result<()> {
    let mut parts = procedure.split('.');
    let valid = |part: Option<&str>| {
        part.is_some_and(|p| {
            !p.is_empty()
                && p.len() <= 64
                && p.starts_with(|c: char| c.is_ascii_lowercase())
                && p.chars().all(|c| c.is_ascii_alphanumeric())
        })
    };
    if !(valid(parts.next()) && valid(parts.next()) && parts.next().is_none()) {
        bail!("invalid procedure name {procedure:?}: expected router.procedure");
    }
    Ok(())
}

/// Procedures that delete something that does not come back by itself.
pub fn is_destructive(procedure: &str) -> bool {
    let action = procedure
        .split_once('.')
        .map_or(procedure, |(_, action)| action)
        .to_ascii_lowercase();
    [
        "remove", "delete", "destroy", "drop", "clean", "purge", "prune", "reset",
    ]
    .iter()
    .any(|word| action.contains(word))
}

#[derive(Clone, Copy)]
pub enum ReadOperation {
    Projects,
    Servers,
    Server,
    ServerServices,
    Compose,
}
impl ReadOperation {
    pub fn endpoint(self) -> &'static str {
        match self {
            Self::Projects => "project.all",
            Self::Servers => "server.all",
            Self::Server => "server.one",
            Self::ServerServices => "server.getServices",
            Self::Compose => "compose.one",
        }
    }
}

/// The kinds of service Dokploy runs, with their API router and id parameter.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ServiceKind {
    Application,
    Compose,
    Postgres,
    Mysql,
    Mariadb,
    Mongo,
    Redis,
    Libsql,
}

impl ServiceKind {
    pub const ALL: [Self; 8] = [
        Self::Application,
        Self::Compose,
        Self::Postgres,
        Self::Mysql,
        Self::Mariadb,
        Self::Mongo,
        Self::Redis,
        Self::Libsql,
    ];

    pub fn router(self) -> &'static str {
        match self {
            Self::Application => "application",
            Self::Compose => "compose",
            Self::Postgres => "postgres",
            Self::Mysql => "mysql",
            Self::Mariadb => "mariadb",
            Self::Mongo => "mongo",
            Self::Redis => "redis",
            Self::Libsql => "libsql",
        }
    }

    pub fn id_param(self) -> &'static str {
        match self {
            Self::Application => "applicationId",
            Self::Compose => "composeId",
            Self::Postgres => "postgresId",
            Self::Mysql => "mysqlId",
            Self::Mariadb => "mariadbId",
            Self::Mongo => "mongoId",
            Self::Redis => "redisId",
            Self::Libsql => "libsqlId",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Application => "app",
            other => other.router(),
        }
    }

    /// Whether Dokploy exposes `<router>.<action>` for this kind.
    pub fn supports(self, action: ServiceAction) -> bool {
        match action {
            ServiceAction::Deploy | ServiceAction::Start | ServiceAction::Stop => {
                self != Self::Libsql
            }
            ServiceAction::Redeploy => matches!(self, Self::Application | Self::Compose),
        }
    }

    pub fn has_environment(self) -> bool {
        self != Self::Libsql
    }

    /// Dokploy keeps a deployment history only for applications and composes.
    pub fn deployments_procedure(self) -> Option<&'static str> {
        match self {
            Self::Application => Some("deployment.all"),
            Self::Compose => Some("deployment.allByCompose"),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ServiceAction {
    Deploy,
    Redeploy,
    Start,
    Stop,
}

impl ServiceAction {
    pub fn name(self) -> &'static str {
        match self {
            Self::Deploy => "deploy",
            Self::Redeploy => "redeploy",
            Self::Start => "start",
            Self::Stop => "stop",
        }
    }
}

/// Every mutation a plan can perform. There is no free-form POST except
/// `Raw`, which is limited to `security.raw_post_allowlist`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum WriteEndpoint {
    ComposeUpdate,
    ComposeCreate,
    PostgresCreate,
    SaveEnvironment(ServiceKind),
    Action(ServiceKind, ServiceAction),
    Raw(String),
}

impl WriteEndpoint {
    pub fn path(&self) -> String {
        match self {
            Self::ComposeUpdate => "compose.update".into(),
            Self::ComposeCreate => "compose.create".into(),
            Self::PostgresCreate => "postgres.create".into(),
            Self::SaveEnvironment(kind) => format!("{}.saveEnvironment", kind.router()),
            Self::Action(kind, action) => format!("{}.{}", kind.router(), action.name()),
            Self::Raw(procedure) => procedure.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn procedure_names_are_validated() {
        for ok in ["project.all", "settings.getDokployVersion", "compose.one"] {
            assert!(validate_procedure(ok).is_ok(), "{ok}");
        }
        for bad in [
            "project",
            "a.b.c",
            "../x.y",
            "compose.one?x=1",
            "Compose.one",
            "compose.",
            ".one",
        ] {
            assert!(validate_procedure(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn destructive_procedures_are_detected() {
        for destructive in [
            "compose.delete",
            "application.remove",
            "volumeBackups.removeVolumeBackup",
            "docker.cleanDockerBuilder",
        ] {
            assert!(is_destructive(destructive), "{destructive}");
        }
        for safe in [
            "compose.deploy",
            "compose.update",
            "domain.create",
            "compose.stop",
        ] {
            assert!(!is_destructive(safe), "{safe}");
        }
    }

    #[test]
    fn endpoints_map_to_real_procedures() {
        assert_eq!(
            WriteEndpoint::Action(ServiceKind::Compose, ServiceAction::Deploy).path(),
            "compose.deploy"
        );
        assert_eq!(
            WriteEndpoint::SaveEnvironment(ServiceKind::Application).path(),
            "application.saveEnvironment"
        );
        assert!(!ServiceKind::Postgres.supports(ServiceAction::Redeploy));
    }
}
