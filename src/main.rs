use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use directories::ProjectDirs;
use dokploy_agent::{
    approval,
    client::{
        DokployClient, ReadOperation, ServiceAction, http_client, is_destructive,
        validate_procedure,
    },
    config::{ApprovalMode, Config, InstanceConfig, Selection},
    inventory::{self, Service},
    net,
    plan::{self, Plan, PlannedAction},
    print_json,
    redact::{self, env_keys},
};
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};
use tokio::task::JoinSet;

#[derive(Parser)]
#[command(
    name = "dokploy-agent",
    version,
    about = "Security-first Dokploy bridge for AI harnesses"
)]
struct Cli {
    /// TOML configuration with every Dokploy instance. Defaults to
    /// $XDG_CONFIG_HOME/dokploy-agent/config.toml (~/.config/dokploy-agent/config.toml).
    #[arg(long, env = "DOKPLOY_AGENT_CONFIG", global = true)]
    config: Option<PathBuf>,
    /// Local protected storage for plans, backups and audit events.
    #[arg(long, global = true)]
    state_dir: Option<PathBuf>,
    #[command(subcommand)]
    command: CommandGroup,
}

#[derive(Subcommand)]
enum CommandGroup {
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    Targets,
    /// Which instance commands run against from here, and why.
    Context(Target),
    /// Network, DNS, credentials, panel version and inventory size.
    Doctor(Target),
    Get {
        #[command(subcommand)]
        command: GetCommand,
    },
    /// Read procedures this panel answers, and the mutations this tool can plan.
    Api {
        #[command(flatten)]
        target: Target,
        /// Only list procedures containing this text.
        filter: Option<String>,
    },
    Plan {
        #[command(subcommand)]
        command: PlanCommand,
    },
    Apply(ApplyArgs),
    Backup {
        #[command(subcommand)]
        command: BackupCommand,
    },
}
#[derive(Subcommand)]
enum ConfigCommand {
    Check,
}

/// The instance a command talks to. Without flags it comes from
/// DOKPLOY_AGENT_TARGET, then from the working directory (the instance whose
/// `paths` contain it), then from `default = true`, then from a lone instance.
#[derive(Args, Clone, Default)]
struct Target {
    #[arg(long)]
    org: Option<String>,
    #[arg(long)]
    instance: Option<String>,
}
impl Target {
    fn selection<'a>(&self, config: &'a Config) -> Result<Selection<'a>> {
        let env_target = std::env::var("DOKPLOY_AGENT_TARGET").ok();
        let cwd = std::env::current_dir().ok();
        config.select(
            self.org.as_deref(),
            self.instance.as_deref(),
            env_target.as_deref(),
            cwd.as_deref(),
        )
    }
    fn resolve<'a>(&self, config: &'a Config) -> Result<&'a InstanceConfig> {
        Ok(self.selection(config)?.instance)
    }
}

fn config_path(argument: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = argument {
        return Ok(path);
    }
    let base = match std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        Some(dir) => PathBuf::from(dir),
        None => directories::BaseDirs::new()
            .context("cannot determine the home directory; pass --config")?
            .home_dir()
            .join(".config"),
    };
    Ok(base.join("dokploy-agent").join("config.toml"))
}

#[derive(Subcommand)]
enum GetCommand {
    /// Projects with their number of services.
    Projects(Target),
    /// Servers registered in the panel.
    Servers(Target),
    Server {
        #[command(flatten)]
        target: Target,
        #[arg(long)]
        id: String,
    },
    ServerServices {
        #[command(flatten)]
        target: Target,
        #[arg(long)]
        id: String,
    },
    /// Every service (apps, composes, databases) with its environment and status.
    Services {
        #[command(flatten)]
        target: Target,
        /// Only services whose project, environment, name or kind contain this text.
        filter: Option<String>,
    },
    /// Detail of one service: `name`, `environment/name` or `project/environment/name`.
    Service {
        #[command(flatten)]
        target: Target,
        query: String,
        /// The full redacted API response instead of the summary.
        #[arg(long)]
        raw: bool,
    },
    /// The env keys of a service. Values never reach stdout.
    Env {
        #[command(flatten)]
        target: Target,
        query: String,
        /// Save the real env block to a new owner-only file (absolute path that must not exist).
        #[arg(long)]
        write_to: Option<PathBuf>,
    },
    Compose {
        #[command(flatten)]
        target: Target,
        /// Compose id. Use --service to find it by name instead.
        #[arg(long, required_unless_present = "service", conflicts_with = "service")]
        id: Option<String>,
        /// Compose name: `name`, `environment/name` or `project/environment/name`.
        #[arg(long)]
        service: Option<String>,
        /// Include a sanitized Compose definition; environment and secret blocks are removed.
        #[arg(long)]
        show_compose: bool,
        /// Save the original Compose, including any secrets, to a new owner-only file.
        /// The path must be absolute and must not already exist.
        #[arg(long)]
        write_to: Option<PathBuf>,
    },
    /// Domains in Dokploy's registry (routing defined in Traefik labels is not listed here).
    Domains {
        #[command(flatten)]
        target: Target,
        query: String,
    },
    /// Latest deployments of an application or Compose.
    Deployments {
        #[command(flatten)]
        target: Target,
        query: String,
        #[arg(long, default_value_t = 15)]
        limit: usize,
    },
    /// Docker containers the panel sees.
    Containers {
        #[command(flatten)]
        target: Target,
        /// Server id; the panel's own host when omitted.
        #[arg(long)]
        server_id: Option<String>,
    },
    /// Any read procedure, redacted: `get raw project.one --param projectId=…`.
    Raw {
        #[command(flatten)]
        target: Target,
        procedure: String,
        /// Query parameter as key=value; repeatable.
        #[arg(long = "param")]
        params: Vec<String>,
    },
}

#[derive(Subcommand)]
enum PlanCommand {
    ComposeUpdate(ComposeUpdateArgs),
    PostgresCreate(PostgresCreateArgs),
    /// Deploy a service.
    Deploy(ServiceArgs),
    /// Redeploy an application or Compose.
    Redeploy(ServiceArgs),
    /// Start a stopped service.
    Start(ServiceArgs),
    /// Stop a service.
    Stop(ServiceArgs),
    /// Replace ALL env variables of a service with the content of a file.
    EnvSet(EnvSetArgs),
    /// Create a raw Compose from a file.
    ComposeCreate(ComposeCreateArgs),
    /// Change a Compose's source type, name or description.
    ComposeSettings(ComposeSettingsArgs),
    /// POST to a procedure listed in security.raw_post_allowlist.
    RawPost(RawPostArgs),
}
#[derive(Args)]
struct ComposeUpdateArgs {
    #[command(flatten)]
    target: Target,
    #[arg(long, required_unless_present = "service", conflicts_with = "service")]
    compose_id: Option<String>,
    /// Compose name: `name`, `environment/name` or `project/environment/name`.
    #[arg(long)]
    service: Option<String>,
    #[arg(long)]
    file: PathBuf,
}
#[derive(Args)]
struct PostgresCreateArgs {
    #[command(flatten)]
    target: Target,
    #[arg(long)]
    environment_id: String,
    #[arg(long)]
    name: String,
    #[arg(long)]
    database_name: String,
    #[arg(long)]
    database_user: String,
    #[arg(long)]
    password_env: String,
    #[arg(long)]
    docker_image: Option<String>,
    #[arg(long)]
    server_id: Option<String>,
}
#[derive(Args)]
struct ServiceArgs {
    #[command(flatten)]
    target: Target,
    /// `name`, `environment/name` or `project/environment/name`.
    service: String,
}
#[derive(Args)]
struct EnvSetArgs {
    #[command(flatten)]
    target: Target,
    service: String,
    /// dotenv file with the complete new env block.
    #[arg(long)]
    file: PathBuf,
}
#[derive(Args)]
struct ComposeCreateArgs {
    #[command(flatten)]
    target: Target,
    /// Environment id, or `project/environment` (e.g. landing/production).
    #[arg(long)]
    environment: String,
    /// Server id or name; the panel's own host when omitted.
    #[arg(long)]
    server: Option<String>,
    #[arg(long)]
    name: String,
    #[arg(long)]
    description: Option<String>,
    #[arg(long)]
    file: PathBuf,
}
#[derive(Clone, Copy, ValueEnum)]
enum SourceType {
    Raw,
    Github,
    Gitlab,
    Bitbucket,
    Gitea,
    Git,
}
impl SourceType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Github => "github",
            Self::Gitlab => "gitlab",
            Self::Bitbucket => "bitbucket",
            Self::Gitea => "gitea",
            Self::Git => "git",
        }
    }
}
#[derive(Args)]
struct ComposeSettingsArgs {
    #[command(flatten)]
    target: Target,
    service: String,
    #[arg(long)]
    source_type: Option<SourceType>,
    #[arg(long)]
    name: Option<String>,
    #[arg(long)]
    description: Option<String>,
}
#[derive(Args)]
struct RawPostArgs {
    #[command(flatten)]
    target: Target,
    procedure: String,
    /// JSON object sent as the request body.
    #[arg(long)]
    body_file: PathBuf,
}
#[derive(Args)]
struct ApplyArgs {
    #[arg(long)]
    plan: String,
    #[arg(long)]
    approve: String,
}
#[derive(Subcommand)]
enum BackupCommand {
    Compose(BackupComposeArgs),
}
#[derive(Args)]
struct BackupComposeArgs {
    #[command(flatten)]
    target: Target,
    #[arg(long)]
    compose_id: String,
    #[arg(long)]
    version: String,
    #[arg(long)]
    commit: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = Config::load(&config_path(cli.config)?)?;
    let state = state_dir(cli.state_dir)?;
    match cli.command {
        CommandGroup::Config { command: ConfigCommand::Check } => print_json(&json!({"ok": true, "instances": config.instances.len(), "message": "Configuration is structurally valid. Credentials were not read."})),
        CommandGroup::Targets => print_json(&config.instances.iter().map(|i| json!({
            "organization": i.organization, "instance": i.name, "base_url": i.base_url,
            "api_key": i.key_source(), "approval": format!("{:?}", i.approval(&config.security)).to_lowercase(),
            "default": i.default, "paths": i.paths
        })).collect::<Vec<_>>()),
        CommandGroup::Context(target) => {
            let selection = target.selection(&config)?;
            print_json(&json!({
                "target": selection.instance.label(), "base_url": selection.instance.base_url,
                "selected_by": selection.selected_by,
                "working_directory": std::env::current_dir().ok(),
                "approval": format!("{:?}", selection.instance.approval(&config.security)).to_lowercase()
            }))
        }
        CommandGroup::Doctor(target) => doctor(&config, &target).await,
        CommandGroup::Get { command } => get(&config, command).await,
        CommandGroup::Api { target, filter } => api(&config, &target, filter.as_deref()).await,
        CommandGroup::Plan { command } => create_plan(&config, &state, command).await,
        CommandGroup::Apply(args) => apply(&config, &state, args).await,
        CommandGroup::Backup { command: BackupCommand::Compose(args) } => backup_compose(&config, args).await,
    }
}

fn state_dir(argument: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = argument {
        if !path.is_absolute() {
            bail!("--state-dir must be absolute");
        }
        return Ok(path);
    }
    let directories = ProjectDirs::from("dev", "dokploy", "dokploy-agent")
        .context("cannot determine platform state directory")?;
    directories
        .state_dir()
        .or_else(|| Some(directories.data_local_dir()))
        .map(Path::to_path_buf)
        .context("platform has no writable state directory; provide --state-dir")
}

fn envelope(instance: &InstanceConfig, data: Value) -> Value {
    json!({"organization": instance.organization, "instance": instance.name, "data": data})
}

// ------------------------------------------------------------------- doctor

async fn doctor(config: &Config, target: &Target) -> Result<()> {
    let selection = target.selection(config)?;
    let instance = selection.instance;
    let mut checks = Vec::new();
    let mut ok = true;
    let host = instance.base_url.host_str().unwrap_or_default().to_owned();
    let port = instance.base_url.port_or_known_default().unwrap_or(443);
    checks.push(json!({"check": "target", "ok": true, "selected_by": selection.selected_by}));

    let key = instance.api_key();
    let key_present = key.is_ok();
    checks.push(json!({
        "check": "config", "ok": key_present,
        "base_url": instance.base_url, "api_key": instance.key_source(),
        "approval": format!("{:?}", instance.approval(&config.security)).to_lowercase(),
        "hint": key.err().map(|e| e.to_string())
    }));
    ok &= key_present;

    // A private panel only resolves inside the VPN: DNS is diagnosed first.
    match tokio::net::lookup_host((host.as_str(), port)).await {
        Ok(addresses) => {
            let addresses: Vec<_> = addresses.map(|a| a.ip()).collect();
            let public_http = instance.base_url.scheme() == "http"
                && addresses.iter().any(|ip| !net::is_private_ip(*ip));
            checks.push(json!({
                "check": "dns", "ok": !public_http, "host": host,
                "addresses": addresses.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "hint": if public_http { json!("an http panel resolves to a public address: the API key would leave the private network") } else { Value::Null }
            }));
            ok &= !public_http;
        }
        Err(_) => {
            checks.push(json!({"check": "dns", "ok": false, "host": host,
                "hint": "the name does not resolve; for a .internal panel, connect to the VPN"}));
            return finish_doctor(instance, checks, false);
        }
    }

    match http_client(instance)?
        .get(instance.base_url.clone())
        .send()
        .await
    {
        Ok(response) => checks
            .push(json!({"check": "panel", "ok": true, "http_status": response.status().as_u16()})),
        Err(_) => {
            checks.push(json!({"check": "panel", "ok": false,
                "hint": "the name resolves but nothing answers: is the VPN routing to it, is the panel up?"}));
            return finish_doctor(instance, checks, false);
        }
    }

    if !key_present {
        return finish_doctor(instance, checks, false);
    }
    let client = DokployClient::new(instance)?;
    if let Ok(version) = client
        .get_procedure("settings.getDokployVersion", &[])
        .await
    {
        checks.push(json!({"check": "version", "ok": true, "version": version}));
    }
    match inventory::load(&client).await {
        Ok(services) => {
            let projects: std::collections::BTreeSet<_> =
                services.iter().map(|s| s.project.clone()).collect();
            checks.push(json!({"check": "api", "ok": true, "projects": projects.len(), "services": services.len()}));
        }
        Err(error) => {
            checks.push(json!({"check": "api", "ok": false, "error": error.to_string()}));
            ok = false;
        }
    }
    finish_doctor(instance, checks, ok)
}

fn finish_doctor(instance: &InstanceConfig, checks: Vec<Value>, ok: bool) -> Result<()> {
    print_json(
        &json!({"organization": instance.organization, "instance": instance.name, "ok": ok, "checks": checks}),
    )?;
    if !ok {
        std::process::exit(1);
    }
    Ok(())
}

// --------------------------------------------------------------------- reads

async fn get(config: &Config, command: GetCommand) -> Result<()> {
    match command {
        GetCommand::Projects(target) => {
            let instance = target.resolve(config)?;
            let client = DokployClient::new(instance)?;
            let projects = client.get(ReadOperation::Projects, &[]).await?;
            let services = inventory::flatten(&projects);
            let rows: Vec<Value> = projects
                .as_array()
                .into_iter()
                .flatten()
                .map(|p| {
                    let name = p.get("name").and_then(Value::as_str).unwrap_or_default();
                    json!({
                        "project": name, "project_id": p.get("projectId"),
                        "environments": p.get("environments").and_then(Value::as_array)
                            .map(|e| e.iter().map(|e| json!({"name": e.get("name"), "environment_id": e.get("environmentId")})).collect::<Vec<_>>()),
                        "services": services.iter().filter(|s| s.project == name).count()
                    })
                })
                .collect();
            print_json(&envelope(instance, json!(rows)))
        }
        GetCommand::Servers(target) => {
            let instance = target.resolve(config)?;
            let servers = DokployClient::new(instance)?
                .get(ReadOperation::Servers, &[])
                .await?;
            let rows: Vec<Value> = servers
                .as_array()
                .into_iter()
                .flatten()
                .map(|s| json!({"name": s.get("name"), "ip": s.get("ipAddress"), "user": s.get("username"), "status": s.get("serverStatus"), "server_id": s.get("serverId")}))
                .collect();
            print_json(&envelope(instance, json!(rows)))
        }
        GetCommand::Server { target, id } => {
            raw_read(
                config,
                &target,
                ReadOperation::Server.endpoint(),
                &[("serverId", id)],
            )
            .await
        }
        GetCommand::ServerServices { target, id } => {
            raw_read(
                config,
                &target,
                ReadOperation::ServerServices.endpoint(),
                &[("serverId", id)],
            )
            .await
        }
        GetCommand::Services { target, filter } => {
            let instance = target.resolve(config)?;
            let client = DokployClient::new(instance)?;
            let mut services = inventory::load(&client).await?;
            services.sort_by(|a, b| {
                (&a.project, &a.environment, &a.name).cmp(&(&b.project, &b.environment, &b.name))
            });
            let shown: Vec<&Service> = match filter.as_deref() {
                Some(filter) => inventory::filter(&services, filter),
                None => services.iter().collect(),
            };
            print_json(&envelope(instance, json!(shown)))
        }
        GetCommand::Service { target, query, raw } => {
            let instance = target.resolve(config)?;
            let client = DokployClient::new(instance)?;
            let (service, detail) = resolve_detail(&client, &query).await?;
            let data = if raw {
                redact::redact(detail)
            } else {
                service_summary(&client, &service, &detail).await
            };
            print_json(&envelope(instance, data))
        }
        GetCommand::Env {
            target,
            query,
            write_to,
        } => {
            let instance = target.resolve(config)?;
            let client = DokployClient::new(instance)?;
            let (service, detail) = resolve_detail(&client, &query).await?;
            if !service.kind.has_environment() {
                bail!(
                    "{} is a {}: Dokploy keeps no env block for it",
                    service.label(),
                    service.kind.label()
                );
            }
            let env = detail
                .get("env")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let mut data = json!({
                "service": service.label(), "variables": env_keys(env),
                "values": "hidden; use --write-to to save them to an owner-only file"
            });
            if let Some(path) = write_to {
                ensure_new_absolute(&path)?;
                write_private(&path, env.as_bytes())?;
                data["written_to"] = json!(path);
                data["env_sha256"] = json!(plan::content_sha256(env));
            }
            print_json(&envelope(instance, data))
        }
        GetCommand::Compose {
            target,
            id,
            service,
            show_compose,
            write_to,
        } => {
            let instance = target.resolve(config)?;
            let client = DokployClient::new(instance)?;
            let compose_id = match (id, service) {
                (Some(id), _) => id,
                (None, Some(query)) => compose_by_name(&client, &query).await?.id,
                (None, None) => bail!("pass --id or --service"),
            };
            let result = client
                .get(
                    ReadOperation::Compose,
                    &[("composeId", compose_id.as_str())],
                )
                .await?;
            let downloaded_to = write_to
                .as_deref()
                .map(|path| export_compose(&result, path))
                .transpose()?;
            print_json(&envelope(
                instance,
                compose_output(result, show_compose, downloaded_to.as_deref()),
            ))
        }
        GetCommand::Domains { target, query } => {
            let instance = target.resolve(config)?;
            let client = DokployClient::new(instance)?;
            let (service, detail) = resolve_detail(&client, &query).await?;
            let domains: Vec<Value> = detail.get("domains").and_then(Value::as_array).into_iter().flatten()
                .map(|d| json!({"host": d.get("host"), "path": d.get("path"), "port": d.get("port"), "https": d.get("https"), "service_name": d.get("serviceName")}))
                .collect();
            let note = if domains.is_empty() {
                json!(
                    "no domains in Dokploy's registry; routing may live in Traefik labels inside the Compose"
                )
            } else {
                Value::Null
            };
            print_json(&envelope(
                instance,
                json!({"service": service.label(), "domains": domains, "note": note}),
            ))
        }
        GetCommand::Deployments {
            target,
            query,
            limit,
        } => {
            let instance = target.resolve(config)?;
            let client = DokployClient::new(instance)?;
            let services = inventory::load(&client).await?;
            let service = inventory::resolve(&services, &query)?.clone();
            let Some(procedure) = service.kind.deployments_procedure() else {
                bail!(
                    "{} is a {}: Dokploy keeps no deployment history for it; see `get service`",
                    service.label(),
                    service.kind.label()
                );
            };
            let deployments = client
                .get_procedure(procedure, &[(service.kind.id_param(), service.id.as_str())])
                .await?;
            let rows: Vec<Value> = deployments.as_array().into_iter().flatten().take(limit)
                .map(|d| json!({"created_at": d.get("createdAt"), "status": d.get("status"), "title": d.get("title"), "description": d.get("description"), "deployment_id": d.get("deploymentId")}))
                .collect();
            print_json(&envelope(
                instance,
                json!({"service": service.label(), "deployments": rows}),
            ))
        }
        GetCommand::Containers { target, server_id } => {
            let instance = target.resolve(config)?;
            let query: Vec<(&str, &str)> = server_id
                .as_deref()
                .map(|id| vec![("serverId", id)])
                .unwrap_or_default();
            let containers = DokployClient::new(instance)?
                .get_procedure("docker.getContainers", &query)
                .await?;
            let rows: Vec<Value> = containers.as_array().into_iter().flatten()
                .map(|c| json!({"name": c.get("name"), "state": c.get("state").or_else(|| c.get("status")), "image": c.get("image"), "container_id": c.get("containerId")}))
                .collect();
            print_json(&envelope(instance, json!(rows)))
        }
        GetCommand::Raw {
            target,
            procedure,
            params,
        } => {
            let params = params
                .iter()
                .map(|p| {
                    p.split_once('=')
                        .map(|(k, v)| (k.to_owned(), v.to_owned()))
                        .with_context(|| format!("--param must be key=value, got {p:?}"))
                })
                .collect::<Result<Vec<_>>>()?;
            raw_read(config, &target, &procedure, &params).await
        }
    }
}

async fn raw_read<K: AsRef<str>, V: AsRef<str>>(
    config: &Config,
    target: &Target,
    procedure: &str,
    params: &[(K, V)],
) -> Result<()> {
    let instance = target.resolve(config)?;
    let query: Vec<(&str, &str)> = params
        .iter()
        .map(|(k, v)| (k.as_ref(), v.as_ref()))
        .collect();
    let result = DokployClient::new(instance)?
        .get_procedure(procedure, &query)
        .await?;
    print_json(&envelope(instance, redact::redact(result)))
}

async fn resolve_service(client: &DokployClient, query: &str) -> Result<Service> {
    let services = inventory::load(client).await?;
    Ok(inventory::resolve(&services, query)?.clone())
}

async fn resolve_detail(client: &DokployClient, query: &str) -> Result<(Service, Value)> {
    let service = resolve_service(client, query).await?;
    let detail = client
        .get_procedure(
            &format!("{}.one", service.kind.router()),
            &[(service.kind.id_param(), service.id.as_str())],
        )
        .await?;
    Ok((service, detail))
}

async fn compose_by_name(client: &DokployClient, query: &str) -> Result<Service> {
    let service = resolve_service(client, query).await?;
    if service.kind != dokploy_agent::client::ServiceKind::Compose {
        bail!(
            "{} is a {}, not a Compose",
            service.label(),
            service.kind.label()
        );
    }
    Ok(service)
}

async fn server_name(client: &DokployClient, server_id: &str) -> Value {
    if server_id.is_empty() {
        return Value::Null;
    }
    let servers = client
        .get(ReadOperation::Servers, &[])
        .await
        .unwrap_or(Value::Null);
    let name = servers
        .as_array()
        .into_iter()
        .flatten()
        .find(|s| s.get("serverId").and_then(Value::as_str) == Some(server_id))
        .and_then(|s| s.get("name").cloned());
    json!({"server_id": server_id, "name": name})
}

async fn service_summary(client: &DokployClient, service: &Service, detail: &Value) -> Value {
    let field = |key: &str| detail.get(key).cloned().unwrap_or(Value::Null);
    let repository = detail
        .get("repository")
        .and_then(Value::as_str)
        .map(|repo| {
            format!(
                "{}/{} @ {}",
                detail
                    .get("owner")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
                repo,
                detail.get("branch").and_then(Value::as_str).unwrap_or("?")
            )
        });
    let server_id = detail
        .get("serverId")
        .and_then(Value::as_str)
        .unwrap_or(&service.server_id)
        .to_owned();
    json!({
        "service": service.label(), "project": service.project, "environment": service.environment,
        "kind": service.kind, "name": field("name"), "app_name": field("appName"), "description": field("description"),
        "status": inventory::status_of(detail),
        "build_type": detail.get("buildType").or_else(|| detail.get("composeType")),
        "source_type": field("sourceType"), "image": field("dockerImage"), "repository": repository,
        "compose_path": field("composePath"), "replicas": field("replicas"), "command": field("command"),
        "server": server_name(client, &server_id).await,
        "created_at": field("createdAt"), "id": service.id,
        "env_keys": detail.get("env").and_then(Value::as_str).map(|env| env_keys(env).into_iter().map(|l| l.key).collect::<Vec<_>>()),
        "domains": detail.get("domains").and_then(Value::as_array).map(|d| d.iter().map(|d| json!({"host": d.get("host"), "path": d.get("path"), "port": d.get("port")})).collect::<Vec<_>>()),
        "mounts": detail.get("mounts").and_then(Value::as_array).map(|m| m.iter().map(|m| json!({"type": m.get("type"), "source": m.get("hostPath").or_else(|| m.get("volumeName")), "mount_path": m.get("mountPath")})).collect::<Vec<_>>()),
        "ports": detail.get("ports").and_then(Value::as_array).map(|p| p.iter().map(|p| json!({"published": p.get("publishedPort"), "target": p.get("targetPort"), "protocol": p.get("protocol")})).collect::<Vec<_>>()),
    })
}

// ----------------------------------------------------------------------- api

/// Read procedures probed with a GET. A GET never runs a mutation in tRPC.
const API_READS: &[&str] = &[
    "project.all",
    "project.one",
    "settings.getDokployVersion",
    "settings.health",
    "server.all",
    "server.one",
    "server.getServices",
    "docker.getContainers",
    "docker.getConfig",
    "docker.getContainersByAppNameMatch",
    "compose.one",
    "compose.allServices",
    "application.one",
    "application.readAppMonitoring",
    "postgres.one",
    "mysql.one",
    "mariadb.one",
    "mongo.one",
    "redis.one",
    "libsql.one",
    "deployment.all",
    "deployment.allByCompose",
    "deployment.allByServer",
    "environment.one",
    "environment.byProjectId",
    "domain.byComposeId",
    "domain.byApplicationId",
    "destination.all",
    "registry.all",
    "sshKey.all",
    "certificates.all",
    "organization.all",
    "user.get",
    "schedule.list",
    "notification.all",
    "gitProvider.getAll",
    "backup.one",
    "mounts.allNamedByApplicationId",
];

async fn api(config: &Config, target: &Target, filter: Option<&str>) -> Result<()> {
    let instance = target.resolve(config)?;
    let client = DokployClient::new(instance)?;
    let mut tasks = JoinSet::new();
    for procedure in API_READS {
        let client = client.clone();
        tasks.spawn(async move { (*procedure, client.probe(procedure).await) });
    }
    let mut reads = Vec::new();
    while let Some(Ok((procedure, status))) = tasks.join_next().await {
        let status = match status {
            Ok(200) => "ok".to_owned(),
            Ok(400) => "ok, needs parameters".to_owned(),
            Ok(405) => "post only".to_owned(),
            Ok(404) => continue,
            Ok(code) => format!("HTTP {code}"),
            Err(error) => format!("error: {error}"),
        };
        reads.push(json!({"procedure": procedure, "status": status}));
    }
    reads.sort_by(|a, b| a["procedure"].as_str().cmp(&b["procedure"].as_str()));
    let mutations = json!([
        {"plan": "deploy | redeploy | start | stop", "procedures": "<router>.deploy|redeploy|start|stop"},
        {"plan": "env-set", "procedures": "<router>.saveEnvironment"},
        {"plan": "compose-create", "procedures": "compose.create + compose.update (sourceType raw)"},
        {"plan": "compose-update | compose-settings", "procedures": "compose.update"},
        {"plan": "postgres-create", "procedures": "postgres.create"},
        {"plan": "raw-post", "procedures": config.security.raw_post_allowlist},
    ]);
    let keep =
        |v: &Value| filter.is_none_or(|f| v.to_string().to_lowercase().contains(&f.to_lowercase()));
    print_json(&envelope(
        instance,
        json!({
            "reads": reads.into_iter().filter(keep).collect::<Vec<_>>(),
            "mutations": mutations.as_array().unwrap().iter().filter(|v| keep(v)).collect::<Vec<_>>(),
            "destructive": "never available: deletes are run by a person from the Dokploy panel"
        }),
    ))
}

// --------------------------------------------------------------------- plans

async fn create_plan(config: &Config, state: &Path, command: PlanCommand) -> Result<()> {
    let selected_by = plan_target(&command).selection(config)?.selected_by;
    let (instance, action) = match command {
        PlanCommand::ComposeUpdate(args) => {
            let instance = args.target.resolve(config)?;
            let client = DokployClient::new(instance)?;
            let compose_id = match (args.compose_id, args.service) {
                (Some(id), _) => required("compose_id", id)?,
                (None, Some(query)) => compose_by_name(&client, &query).await?.id,
                (None, None) => bail!("pass --compose-id or --service"),
            };
            let content = fs::read_to_string(&args.file)
                .with_context(|| format!("cannot read {}", args.file.display()))?;
            validate_compose(&content)?;
            let digest = plan::content_sha256(&content);
            let remote = client
                .get(
                    ReadOperation::Compose,
                    &[("composeId", compose_id.as_str())],
                )
                .await?;
            let remote_compose = remote
                .get("composeFile")
                .and_then(Value::as_str)
                .context("Dokploy response contains no composeFile")?;
            (
                instance,
                PlannedAction::ComposeUpdate {
                    compose_id,
                    compose_file: content,
                    content_sha256: digest,
                    base_remote_sha256: plan::content_sha256(remote_compose),
                },
            )
        }
        PlanCommand::PostgresCreate(args) => {
            let instance = args.target.resolve(config)?;
            dokploy_agent::config::validate_env_name(&args.password_env)?;
            (
                instance,
                PlannedAction::PostgresCreate {
                    environment_id: required("environment_id", args.environment_id)?,
                    name: required("name", args.name)?,
                    database_name: required("database_name", args.database_name)?,
                    database_user: required("database_user", args.database_user)?,
                    password_env: args.password_env,
                    docker_image: args.docker_image.filter(|s| !s.trim().is_empty()),
                    server_id: args.server_id.filter(|s| !s.trim().is_empty()),
                },
            )
        }
        PlanCommand::Deploy(args) => service_action(config, args, ServiceAction::Deploy).await?,
        PlanCommand::Redeploy(args) => {
            service_action(config, args, ServiceAction::Redeploy).await?
        }
        PlanCommand::Start(args) => service_action(config, args, ServiceAction::Start).await?,
        PlanCommand::Stop(args) => service_action(config, args, ServiceAction::Stop).await?,
        PlanCommand::EnvSet(args) => {
            let instance = args.target.resolve(config)?;
            let client = DokployClient::new(instance)?;
            let (service, detail) = resolve_detail(&client, &args.service).await?;
            if !service.kind.has_environment() {
                bail!(
                    "{} is a {}: Dokploy keeps no env block for it",
                    service.label(),
                    service.kind.label()
                );
            }
            let env = fs::read_to_string(&args.file)
                .with_context(|| format!("cannot read {}", args.file.display()))?;
            let keys = env_keys(&env)
                .into_iter()
                .map(|line| line.key)
                .collect::<Vec<_>>();
            if keys.is_empty() {
                bail!(
                    "{} has no KEY=value lines; refusing to wipe every variable",
                    args.file.display()
                );
            }
            let current = detail
                .get("env")
                .and_then(Value::as_str)
                .unwrap_or_default();
            (
                instance,
                PlannedAction::EnvSet {
                    service_kind: service.kind,
                    service_id: service.id.clone(),
                    label: service.label(),
                    env_sha256: plan::content_sha256(&env),
                    env,
                    keys,
                    base_env_sha256: plan::content_sha256(current),
                },
            )
        }
        PlanCommand::ComposeCreate(args) => {
            let instance = args.target.resolve(config)?;
            let client = DokployClient::new(instance)?;
            let content = fs::read_to_string(&args.file)
                .with_context(|| format!("cannot read {}", args.file.display()))?;
            validate_compose(&content)?;
            let environment_id = resolve_environment(&client, &args.environment).await?;
            let server_id = match args.server.as_deref() {
                Some(server) => Some(resolve_server(&client, server).await?),
                None => None,
            };
            (
                instance,
                PlannedAction::ComposeCreate {
                    environment_id,
                    server_id,
                    name: required("name", args.name)?,
                    description: args.description.filter(|d| !d.trim().is_empty()),
                    content_sha256: plan::content_sha256(&content),
                    compose_file: content,
                },
            )
        }
        PlanCommand::ComposeSettings(args) => {
            let instance = args.target.resolve(config)?;
            let client = DokployClient::new(instance)?;
            if args.source_type.is_none() && args.name.is_none() && args.description.is_none() {
                bail!("nothing to change: pass --source-type, --name or --description");
            }
            let service = compose_by_name(&client, &args.service).await?;
            (
                instance,
                PlannedAction::ComposeSettings {
                    compose_id: service.id.clone(),
                    label: service.label(),
                    source_type: args.source_type.map(|s| s.as_str().to_owned()),
                    name: args.name,
                    description: args.description,
                },
            )
        }
        PlanCommand::RawPost(args) => {
            let instance = args.target.resolve(config)?;
            validate_procedure(&args.procedure)?;
            if is_destructive(&args.procedure) {
                bail!(
                    "{} is destructive: deletes are run by a person from the Dokploy panel",
                    args.procedure
                );
            }
            if !config.security.raw_post_allowlist.contains(&args.procedure) {
                bail!(
                    "{} is not in security.raw_post_allowlist; add it there after reviewing its schema, or use a typed plan",
                    args.procedure
                );
            }
            let body: Value = serde_json::from_str(
                &fs::read_to_string(&args.body_file)
                    .with_context(|| format!("cannot read {}", args.body_file.display()))?,
            )
            .context("--body-file must contain JSON")?;
            if !body.is_object() {
                bail!("--body-file must contain a JSON object");
            }
            (
                instance,
                PlannedAction::RawPost {
                    procedure: args.procedure,
                    body,
                },
            )
        }
    };
    let plan = Plan::new(
        instance.organization.clone(),
        instance.name.clone(),
        action,
        config.security.plan_ttl_seconds,
    )?;
    plan::save(state, &plan)?;
    let mut output = plan.safe_output();
    // Which Dokploy this plan changes, and why: the operator approves this too.
    output["target"] = json!({
        "instance": instance.label(), "base_url": instance.base_url, "selected_by": selected_by
    });
    if instance.approval(&config.security) == ApprovalMode::Terminal {
        output["approval"] = json!(format!(
            "terminal: a person must run `dokploy-agent apply --plan {} --approve <token>` in an interactive terminal and retype {}",
            plan.id,
            approval::short_id(&plan)
        ));
    }
    print_json(&output)
}

fn plan_target(command: &PlanCommand) -> &Target {
    match command {
        PlanCommand::ComposeUpdate(a) => &a.target,
        PlanCommand::PostgresCreate(a) => &a.target,
        PlanCommand::Deploy(a)
        | PlanCommand::Redeploy(a)
        | PlanCommand::Start(a)
        | PlanCommand::Stop(a) => &a.target,
        PlanCommand::EnvSet(a) => &a.target,
        PlanCommand::ComposeCreate(a) => &a.target,
        PlanCommand::ComposeSettings(a) => &a.target,
        PlanCommand::RawPost(a) => &a.target,
    }
}

async fn service_action(
    config: &Config,
    args: ServiceArgs,
    action: ServiceAction,
) -> Result<(&InstanceConfig, PlannedAction)> {
    let instance = args.target.resolve(config)?;
    let client = DokployClient::new(instance)?;
    let service = resolve_service(&client, &args.service).await?;
    if !service.kind.supports(action) {
        bail!(
            "{} is a {}: Dokploy has no {} for it",
            service.label(),
            service.kind.label(),
            action.name()
        );
    }
    Ok((
        instance,
        PlannedAction::ServiceAction {
            service_kind: service.kind,
            service_id: service.id.clone(),
            label: service.label(),
            action,
        },
    ))
}

/// An environment id, or the id of `project/environment`.
async fn resolve_environment(client: &DokployClient, query: &str) -> Result<String> {
    let projects = client.get(ReadOperation::Projects, &[]).await?;
    let mut matches = Vec::new();
    for project in projects.as_array().into_iter().flatten() {
        let project_name = project
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        for environment in project
            .get("environments")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let id = environment
                .get("environmentId")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let name = environment
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if id == query || format!("{project_name}/{name}").eq_ignore_ascii_case(query) {
                matches.push(id.to_owned());
            }
        }
    }
    match matches.as_slice() {
        [only] => Ok(only.clone()),
        [] => bail!(
            "no environment matches {query:?}; use an id or project/environment (see `get projects`)"
        ),
        _ => bail!("{query:?} matches several environments; use the environment id"),
    }
}

/// A server id, or the id of the server with that name.
async fn resolve_server(client: &DokployClient, query: &str) -> Result<String> {
    let servers = client.get(ReadOperation::Servers, &[]).await?;
    let matches: Vec<String> = servers
        .as_array()
        .into_iter()
        .flatten()
        .filter(|s| {
            s.get("serverId").and_then(Value::as_str) == Some(query)
                || s.get("name")
                    .and_then(Value::as_str)
                    .is_some_and(|n| n.eq_ignore_ascii_case(query))
        })
        .filter_map(|s| s.get("serverId").and_then(Value::as_str).map(str::to_owned))
        .collect();
    match matches.as_slice() {
        [only] => Ok(only.clone()),
        [] => bail!("no server matches {query:?}; see `get servers`"),
        _ => bail!("{query:?} matches several servers; use the server id"),
    }
}

// --------------------------------------------------------------------- apply

async fn apply(config: &Config, state: &Path, args: ApplyArgs) -> Result<()> {
    // Everything that can refuse happens before the plan is claimed, so a
    // refusal leaves it runnable; once claimed it can never run twice.
    let reviewed = plan::load(state, &args.plan)?;
    reviewed.verify()?;
    if args.approve != reviewed.digest {
        bail!("approval token does not match the reviewed plan");
    }
    let instance = config.instance(&reviewed.organization, &reviewed.instance)?;
    if instance.approval(&config.security) == ApprovalMode::Terminal {
        approval::confirm_in_terminal(&reviewed)?;
    }
    let plan = plan::claim(state, &args.plan)?;
    if plan.digest != reviewed.digest {
        bail!("plan changed between review and claim");
    }
    let client = DokployClient::new(instance)?;
    match execute(&client, state, &plan).await {
        Ok(mut output) => {
            plan::audit_success(state, &plan)?;
            output["target"] = json!({"instance": instance.label(), "base_url": instance.base_url});
            print_json(&output)
        }
        Err(error) => {
            plan::audit_failure(state, &plan, &error.to_string())?;
            Err(error)
        }
    }
}

async fn execute(client: &DokployClient, state: &Path, plan: &Plan) -> Result<Value> {
    let mut extra = serde_json::Map::new();
    match &plan.action {
        PlannedAction::ComposeUpdate {
            compose_id,
            base_remote_sha256,
            ..
        } => {
            let remote = client
                .get(
                    ReadOperation::Compose,
                    &[("composeId", compose_id.as_str())],
                )
                .await?;
            let remote_compose = remote
                .get("composeFile")
                .and_then(Value::as_str)
                .context("Dokploy response contains no composeFile")?;
            if plan::content_sha256(remote_compose) != *base_remote_sha256 {
                bail!(
                    "remote Compose changed since this plan was created; download, review, and create a new plan"
                );
            }
        }
        PlannedAction::EnvSet {
            service_kind,
            service_id,
            label,
            base_env_sha256,
            ..
        } => {
            let detail = client
                .get_procedure(
                    &format!("{}.one", service_kind.router()),
                    &[(service_kind.id_param(), service_id.as_str())],
                )
                .await?;
            let current = detail
                .get("env")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if plan::content_sha256(current) != *base_env_sha256 {
                bail!("the env of {label} changed since this plan was created; create a new plan");
            }
            let backup = backup_env(state, label, current)?;
            extra.insert("previous_env_backup".into(), json!(backup));
            extra.insert(
                "next_step".into(),
                json!("the new env applies on the next deploy"),
            );
        }
        PlannedAction::ComposeCreate { .. } => {
            let created = client
                .post(plan.action.endpoint(), plan::request_body(plan)?)
                .await?;
            let compose_id = created.get("composeId").and_then(Value::as_str).context(
                "compose.create answered without a composeId; check the panel before retrying",
            )?;
            // Dokploy creates a Compose with a git source; a raw one needs this second call.
            let settings = client
                .post_procedure("compose.update", json!({"composeId": compose_id, "sourceType": "raw"}))
                .await
                .with_context(|| format!("Compose {compose_id} was created but setting sourceType raw failed; fix it with plan compose-settings"))?;
            return Ok(json!({
                "ok": true, "plan_id": plan.id, "operation": plan.action.operation_name(),
                "compose_id": compose_id, "source_type": settings.get("sourceType"),
                "next_step": "deploy it with plan deploy"
            }));
        }
        _ => {}
    }
    let response = client
        .post(plan.action.endpoint(), plan::request_body(plan)?)
        .await?;
    let mut output = json!({"ok": true, "plan_id": plan.id, "operation": plan.action.operation_name(), "response": redact::redact(response)});
    for (key, value) in extra {
        output[key] = value;
    }
    Ok(output)
}

/// Saves the env a plan is about to replace, owner-only, under the state dir.
fn backup_env(state: &Path, label: &str, env: &str) -> Result<PathBuf> {
    let directory = state.join("backups");
    fs::create_dir_all(&directory)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
    }
    let name: String = label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let path = directory.join(format!(
        "{name}-{}.env",
        chrono::Utc::now().format("%Y%m%dT%H%M%S%.3fZ")
    ));
    write_private(&path, env.as_bytes())?;
    Ok(path)
}

// -------------------------------------------------------------------- backup

async fn backup_compose(config: &Config, args: BackupComposeArgs) -> Result<()> {
    let backup = config
        .compose_backup
        .as_ref()
        .context("compose_backup is not configured")?;
    if !backup.repository_path.join(".git").is_dir() {
        bail!("compose_backup.repository_path must be an existing Git checkout");
    }
    if let Some(expected_url) = &backup.repository_url {
        if git_output(&backup.repository_path, &["remote", "get-url", "origin"])? != *expected_url {
            bail!("backup repository origin does not match compose_backup.repository_url");
        }
    }
    if git_output(&backup.repository_path, &["branch", "--show-current"])? != backup.branch {
        bail!(
            "backup repository is not on configured branch {:?}",
            backup.branch
        );
    }
    let instance = args.target.resolve(config)?;
    let result = DokployClient::new(instance)?
        .get(
            ReadOperation::Compose,
            &[("composeId", args.compose_id.as_str())],
        )
        .await?;
    let content = result
        .get("composeFile")
        .and_then(|v| v.as_str())
        .context("Dokploy response contains no composeFile")?;
    validate_compose(content)?;
    let directory = backup
        .repository_path
        .join("dokploy")
        .join(safe_segment(&instance.organization)?)
        .join(safe_segment(&instance.name)?)
        .join(safe_segment(&args.compose_id)?);
    fs::create_dir_all(&directory)?;
    let file = directory.join(format!("{}.yaml", safe_segment(&args.version)?));
    if file.exists() {
        bail!("snapshot already exists: {}", file.display());
    }
    write_private(&file, content.as_bytes())?;
    if args.commit {
        git(
            &backup.repository_path,
            &[
                "add",
                "--",
                file.strip_prefix(&backup.repository_path)?
                    .to_str()
                    .context("non-UTF8 path")?,
            ],
        )?;
        git(
            &backup.repository_path,
            &[
                "commit",
                "-m",
                &format!(
                    "backup({}): {} {}",
                    instance.organization, args.compose_id, args.version
                ),
            ],
        )?;
    }
    print_json(
        &json!({"ok": true, "snapshot": file, "sha256": plan::content_sha256(content), "committed": args.commit, "branch": backup.branch, "pushed": false}),
    )
}

fn git(dir: &Path, arguments: &[&str]) -> Result<()> {
    let status = Command::new("git")
        .current_dir(dir)
        .env("GIT_TERMINAL_PROMPT", "0")
        .args(["-c", "core.hooksPath=/dev/null"])
        .args(arguments)
        .status()
        .context("cannot invoke git")?;
    if !status.success() {
        bail!("git command failed");
    }
    Ok(())
}
fn git_output(dir: &Path, arguments: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .current_dir(dir)
        .env("GIT_TERMINAL_PROMPT", "0")
        .args(["-c", "core.hooksPath=/dev/null"])
        .args(arguments)
        .output()
        .context("cannot invoke git")?;
    if !output.status.success() {
        bail!("git command failed");
    }
    Ok(String::from_utf8(output.stdout)
        .context("git emitted non-UTF8 output")?
        .trim()
        .to_owned())
}

// ------------------------------------------------------------------- helpers

fn ensure_new_absolute(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        bail!("--write-to must be an absolute path");
    }
    if path.exists() {
        bail!("refusing to overwrite existing file: {}", path.display());
    }
    Ok(())
}
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
fn validate_compose(content: &str) -> Result<()> {
    let yaml: serde_yaml::Value =
        serde_yaml::from_str(content).context("Compose YAML is invalid")?;
    if yaml.get("services").is_none() {
        bail!("Compose YAML must contain a top-level services mapping");
    }
    Ok(())
}
fn required(name: &str, value: String) -> Result<String> {
    if value.trim().is_empty() {
        bail!("{name} cannot be empty")
    } else {
        Ok(value)
    }
}
fn safe_segment(value: &str) -> Result<&str> {
    if value.is_empty()
        || value.len() > 120
        || !value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
    {
        bail!("backup path values must contain only letters, numbers, dot, underscore, or hyphen")
    }
    Ok(value)
}

fn compose_output(response: Value, show_compose: bool, downloaded_to: Option<&Path>) -> Value {
    let mut output = serde_json::Map::new();
    for key in [
        "composeId",
        "name",
        "appName",
        "description",
        "serverId",
        "environmentId",
        "sourceType",
        "composeType",
        "composeStatus",
        "createdAt",
        "updatedAt",
    ] {
        if let Some(value) = response.get(key) {
            output.insert(key.into(), value.clone());
        }
    }
    if show_compose {
        let view = response
            .get("composeFile")
            .and_then(Value::as_str)
            .map(safe_compose_view)
            .unwrap_or_else(|| Value::String("[REDACTED: Compose unavailable]".into()));
        output.insert("compose".into(), view);
    } else {
        output.insert(
            "compose".into(),
            Value::String("[REDACTED: pass --show-compose for a sanitized service view]".into()),
        );
    }
    if let Some(path) = downloaded_to {
        output.insert(
            "downloaded_to".into(),
            Value::String(path.display().to_string()),
        );
        if let Some(content) = response.get("composeFile").and_then(Value::as_str) {
            output.insert(
                "compose_sha256".into(),
                Value::String(plan::content_sha256(content)),
            );
        }
    }
    Value::Object(output)
}

fn export_compose(response: &Value, path: &Path) -> Result<PathBuf> {
    ensure_new_absolute(path)?;
    let content = response
        .get("composeFile")
        .and_then(Value::as_str)
        .context("Dokploy response contains no composeFile")?;
    validate_compose(content)?;
    write_private(path, content.as_bytes())?;
    Ok(path.to_path_buf())
}

/// Services of a Compose with only non-secret fields. Labels are included:
/// they carry Traefik routing (hosts, ports), which is what operators check.
fn safe_compose_view(content: &str) -> Value {
    let Ok(yaml) = serde_yaml::from_str::<serde_yaml::Value>(content) else {
        return Value::String("[REDACTED: Compose could not be safely parsed]".into());
    };
    let Some(services) = yaml.get("services").and_then(serde_yaml::Value::as_mapping) else {
        return Value::String("[REDACTED: Compose has no services mapping]".into());
    };
    let mut output = serde_json::Map::new();
    for (name, service) in services {
        let mut details = serde_json::Map::new();
        if let Some(mapping) = service.as_mapping() {
            for field in [
                "image",
                "ports",
                "volumes",
                "networks",
                "restart",
                "depends_on",
                "deploy",
                "labels",
                "healthcheck",
            ] {
                if let Some(value) = mapping.get(serde_yaml::Value::String(field.into())) {
                    if let Ok(json) = serde_json::to_value(value) {
                        let json = if field == "labels" {
                            redact::redact_labels(json)
                        } else {
                            redact::redact(json)
                        };
                        details.insert(field.into(), json);
                    }
                }
            }
            if mapping.contains_key(serde_yaml::Value::String("environment".into()))
                || mapping.contains_key(serde_yaml::Value::String("env_file".into()))
            {
                details.insert("environment".into(), Value::String(redact::REDACTED.into()));
            }
        }
        output.insert(
            name.as_str().unwrap_or("unnamed").into(),
            Value::Object(details),
        );
    }
    json!({"services": output})
}
