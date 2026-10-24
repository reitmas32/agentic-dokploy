use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::{
    env, fs,
    path::{Path, PathBuf},
};
use url::Url;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub security: SecurityConfig,
    /// Instances declared in TOML. Most setups use one env file per instance
    /// in `instances_dir` instead.
    #[serde(default)]
    pub instances: Vec<InstanceConfig>,
    /// Directory of `<organization>.env` files, one per Dokploy. Defaults to
    /// `instances/` next to the configuration file.
    pub instances_dir: Option<PathBuf>,
    pub compose_backup: Option<ComposeBackupConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SecurityConfig {
    /// Allows `http://` URLs, but only towards private hosts (see `net`).
    #[serde(default)]
    pub allow_http: bool,
    #[serde(default = "default_plan_ttl")]
    pub plan_ttl_seconds: u64,
    /// Default approval mode for instances that do not set their own.
    #[serde(default)]
    pub approval: ApprovalMode,
    /// Procedures that `plan raw-post` may call. Empty by default: every other
    /// mutation goes through a typed plan. Destructive names are never accepted.
    #[serde(default)]
    pub raw_post_allowlist: Vec<String>,
}

/// Who can turn a reviewed plan into a real change.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalMode {
    /// `apply` with the plan's approval token. A harness can run it after the
    /// operator approves the plan in conversation: the token proves the plan
    /// was not changed, not that a human typed it.
    #[default]
    Token,
    /// `apply` also needs an interactive terminal where the operator retypes
    /// the plan's short id. A harness without a TTY cannot complete it.
    Terminal,
}

fn default_plan_ttl() -> u64 {
    900
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            allow_http: false,
            plan_ttl_seconds: default_plan_ttl(),
            approval: ApprovalMode::default(),
            raw_post_allowlist: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct InstanceConfig {
    pub organization: String,
    pub name: String,
    pub base_url: Url,
    /// Environment variable holding the API key. Set this or `api_key_file`.
    pub api_key_env: Option<String>,
    /// Owner-only file holding the API key (absolute path, mode 0600, not a symlink).
    pub api_key_file: Option<PathBuf>,
    /// Overrides `security.approval` for this instance (e.g. `terminal` for production).
    pub approval: Option<ApprovalMode>,
    /// Used when nothing else selects an instance. At most one instance may set it.
    #[serde(default)]
    pub default: bool,
    /// Working directories that belong to this instance: a command run inside
    /// one of them (or below) targets it. The deepest match wins.
    #[serde(default)]
    pub paths: Vec<PathBuf>,
    /// Accepts an `http://` URL for this instance (still private hosts only).
    #[serde(default)]
    pub allow_http: bool,
    /// The env file this instance was loaded from; its DOKPLOY_API_KEY is read
    /// when a request needs it, never kept in memory with the config.
    #[serde(skip)]
    pub env_file: Option<PathBuf>,
}

impl InstanceConfig {
    pub fn approval(&self, security: &SecurityConfig) -> ApprovalMode {
        self.approval.unwrap_or(security.approval)
    }

    pub fn label(&self) -> String {
        format!("{}/{}", self.organization, self.name)
    }

    /// Where the API key comes from, for display (never the key itself).
    pub fn key_source(&self) -> String {
        if let Some(path) = &self.env_file {
            return format!("env_file:{}", path.display());
        }
        match (&self.api_key_env, &self.api_key_file) {
            (Some(name), _) => format!("env:{name}"),
            (None, Some(path)) => format!("file:{}", path.display()),
            (None, None) => "none".into(),
        }
    }

    /// The API key, from the instance's env file, the environment or the
    /// protected key file.
    pub fn api_key(&self) -> Result<String> {
        if let Some(path) = &self.env_file {
            return crate::envfile::api_key(path);
        }
        match (&self.api_key_env, &self.api_key_file) {
            (Some(name), _) => secret_from_env(name),
            (None, Some(path)) => secret_from_file(path),
            (None, None) => bail!("{} has no api_key_env or api_key_file", self.label()),
        }
    }
}

/// Why a command targets the instance it targets.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectedBy {
    Flags,
    /// `DOKPLOY_AGENT_TARGET=organization/instance`.
    Environment,
    /// The working directory is inside one of the instance's `paths`.
    Path(PathBuf),
    Default,
    OnlyInstance,
}

pub struct Selection<'a> {
    pub instance: &'a InstanceConfig,
    pub selected_by: SelectedBy,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ComposeBackupConfig {
    pub repository_path: PathBuf,
    /// Expected `origin` URL of the already-cloned backup repository.
    /// This is an identifier, not a credential-bearing URL.
    pub repository_url: Option<String>,
    #[serde(default = "default_branch")]
    pub branch: String,
}

fn default_branch() -> String {
    "main".into()
}

impl Config {
    /// Loads the TOML configuration (optional when an instances directory
    /// exists) and every `<organization>.env` file of the instances directory.
    pub fn load(path: &Path) -> Result<Self> {
        let mut config: Self = if fs::symlink_metadata(path).is_ok() {
            assert_secure_config_file(path)?;
            let text = fs::read_to_string(path)
                .with_context(|| format!("cannot read config {}", path.display()))?;
            toml::from_str(&text).context("invalid TOML configuration")?
        } else {
            Self {
                security: SecurityConfig::default(),
                instances: Vec::new(),
                instances_dir: None,
                compose_backup: None,
            }
        };
        let directory = config
            .instances_dir
            .clone()
            .unwrap_or_else(|| path.parent().unwrap_or(Path::new(".")).join("instances"));
        if fs::symlink_metadata(&directory).is_ok() {
            let home = directories::BaseDirs::new()
                .map(|b| b.home_dir().to_path_buf())
                .context("cannot determine the home directory")?;
            config
                .instances
                .extend(crate::envfile::load_dir(&directory, &home)?);
        } else if config.instances.is_empty() {
            bail!(
                "no instances: create {} with one <organization>.env per Dokploy, or write {}",
                directory.display(),
                path.display()
            );
        }
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.instances.is_empty() {
            bail!("configuration must contain at least one instance");
        }
        if !(60..=3600).contains(&self.security.plan_ttl_seconds) {
            bail!("security.plan_ttl_seconds must be between 60 and 3600");
        }
        for instance in &self.instances {
            if instance.organization.trim().is_empty() || instance.name.trim().is_empty() {
                bail!("instance organization and name cannot be empty");
            }
            if !matches!(instance.base_url.scheme(), "https" | "http") {
                bail!(
                    "{} / {} has unsupported URL scheme",
                    instance.organization,
                    instance.name
                );
            }
            if instance.base_url.scheme() == "http" {
                if !self.security.allow_http && !instance.allow_http {
                    bail!(
                        "{} / {} uses HTTP; set allow_http (DOKPLOY_ALLOW_HTTP=true in its env file) only on a trusted private network",
                        instance.organization,
                        instance.name
                    );
                }
                // The API key travels in a header: in clear text only inside a private network.
                if !crate::net::is_private_host(&instance.base_url) {
                    bail!(
                        "{} / {} uses HTTP towards a non-private host; the API key would travel in clear text. Use HTTPS",
                        instance.organization,
                        instance.name
                    );
                }
            }
            if instance.base_url.host_str().is_none() {
                bail!("instance URL must include a host");
            }
            match (&instance.api_key_env, &instance.api_key_file) {
                _ if instance.env_file.is_some() => {}
                (Some(name), None) => validate_env_name(name)?,
                (None, Some(path)) if path.is_absolute() => {}
                (None, Some(_)) => bail!("{}: api_key_file must be absolute", instance.label()),
                _ => bail!(
                    "{}: set exactly one of api_key_env or api_key_file",
                    instance.label()
                ),
            }
            for path in &instance.paths {
                if !path.is_absolute() {
                    bail!(
                        "{}: paths must be absolute ({})",
                        instance.label(),
                        path.display()
                    );
                }
            }
        }
        for (index, instance) in self.instances.iter().enumerate() {
            for path in &instance.paths {
                if let Some(other) = self.instances[..index]
                    .iter()
                    .find(|o| o.paths.contains(path))
                {
                    bail!(
                        "{} is mapped to both {} and {}",
                        path.display(),
                        other.label(),
                        instance.label()
                    );
                }
            }
        }
        if self.instances.iter().filter(|i| i.default).count() > 1 {
            bail!("only one instance can set default = true");
        }
        for procedure in &self.security.raw_post_allowlist {
            crate::client::validate_procedure(procedure)?;
            if crate::client::is_destructive(procedure) {
                bail!("raw_post_allowlist cannot contain destructive procedure {procedure:?}");
            }
        }
        for (index, instance) in self.instances.iter().enumerate() {
            if self.instances[..index].iter().any(|other| {
                other.organization == instance.organization && other.name == instance.name
            }) {
                bail!(
                    "{} is defined twice (TOML and an env file, or two env files)",
                    instance.label()
                );
            }
        }
        if let Some(backup) = &self.compose_backup {
            if !backup.repository_path.is_absolute() {
                bail!("compose_backup.repository_path must be absolute");
            }
            if backup.branch.trim().is_empty() {
                bail!("compose_backup.branch cannot be empty");
            }
            if backup
                .repository_url
                .as_deref()
                .is_some_and(|url| url.trim().is_empty() || url.contains(['\r', '\n']))
            {
                bail!("compose_backup.repository_url must be a single non-empty line");
            }
        }
        Ok(())
    }

    /// The instance a command targets, in this order:
    /// 1. `--org` and `--instance`;
    /// 2. `DOKPLOY_AGENT_TARGET=organization/instance`;
    /// 3. the instance whose `paths` contain the working directory (deepest wins);
    /// 4. the instance marked `default = true`;
    /// 5. the only instance, when there is just one.
    pub fn select(
        &self,
        organization: Option<&str>,
        name: Option<&str>,
        env_target: Option<&str>,
        cwd: Option<&Path>,
    ) -> Result<Selection<'_>> {
        let selection = |instance, selected_by| {
            Ok(Selection {
                instance,
                selected_by,
            })
        };
        match (organization, name) {
            (Some(organization), Some(name)) => {
                return selection(self.instance(organization, name)?, SelectedBy::Flags);
            }
            (None, None) => {}
            _ => bail!("pass both --org and --instance, or neither"),
        }
        if let Some(target) = env_target.filter(|t| !t.trim().is_empty()) {
            let (organization, name) = target
                .split_once('/')
                .context("DOKPLOY_AGENT_TARGET must be organization/instance")?;
            return selection(self.instance(organization, name)?, SelectedBy::Environment);
        }
        if let Some(cwd) = cwd {
            let cwd = canonical(cwd);
            let mut best: Vec<(&InstanceConfig, &PathBuf, usize)> = Vec::new();
            for instance in &self.instances {
                for path in &instance.paths {
                    let root = canonical(path);
                    if cwd.starts_with(&root) {
                        let depth = root.components().count();
                        match best.first().map(|(_, _, d)| *d) {
                            Some(d) if depth < d => {}
                            Some(d) if depth == d => best.push((instance, path, depth)),
                            _ => best = vec![(instance, path, depth)],
                        }
                    }
                }
            }
            match best.as_slice() {
                [(instance, path, _)] => {
                    return selection(instance, SelectedBy::Path((*path).clone()));
                }
                [] => {}
                many => bail!(
                    "{} is inside paths of several instances ({}); pass --org and --instance",
                    cwd.display(),
                    many.iter()
                        .map(|(i, _, _)| i.label())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            }
        }
        if let Some(default) = self.instances.iter().find(|i| i.default) {
            return selection(default, SelectedBy::Default);
        }
        // Once directories are mapped, an unmapped directory picks nothing: a
        // lone instance must not become the target of work on another project.
        let mapped = self.instances.iter().any(|i| !i.paths.is_empty());
        match self.instances.as_slice() {
            [only] if !mapped => selection(only, SelectedBy::OnlyInstance),
            _ => bail!(
                "no instance matches this directory: pass --org and --instance, set DOKPLOY_AGENT_TARGET, add the directory to an instance's paths, or mark one default = true"
            ),
        }
    }

    /// `select` without directory or environment context; used by tests and
    /// by callers that already know the target.
    pub fn target(
        &self,
        organization: Option<&str>,
        name: Option<&str>,
    ) -> Result<&InstanceConfig> {
        Ok(self.select(organization, name, None, None)?.instance)
    }

    pub fn instance(&self, organization: &str, name: &str) -> Result<&InstanceConfig> {
        self.instances
            .iter()
            .find(|item| item.organization == organization && item.name == name)
            .with_context(|| {
                format!(
                    "no instance configured for organization={organization:?}, instance={name:?}"
                )
            })
    }
}

fn assert_secure_config_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("cannot inspect config {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("configuration must be a regular file, not a symbolic link");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o022 != 0 {
            bail!("configuration is group/world writable; set permissions to 0600 or 0644");
        }
    }
    Ok(())
}

/// Resolves symlinks (e.g. /tmp → /private/tmp) when the path exists.
fn canonical(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Reads an API key from an owner-only regular file.
pub fn secret_from_file(path: &Path) -> Result<String> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("cannot read API key file {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!(
            "API key file {} must be a regular file, not a symbolic link",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!(
                "API key file {} must be owner-only (chmod 600)",
                path.display()
            );
        }
    }
    let value = fs::read_to_string(path)
        .with_context(|| format!("cannot read API key file {}", path.display()))?;
    let value = value.trim();
    if value.is_empty() {
        bail!("API key file {} is empty", path.display());
    }
    Ok(value.to_owned())
}

pub fn secret_from_env(name: &str) -> Result<String> {
    validate_env_name(name)?;
    let value = env::var(name)
        .with_context(|| format!("required secret environment variable {name} is not set"))?;
    if value.trim().is_empty() {
        bail!("secret environment variable {name} is empty");
    }
    Ok(value)
}

pub fn validate_env_name(name: &str) -> Result<()> {
    if name.is_empty()
        || !name
            .bytes()
            .enumerate()
            .all(|(i, ch)| ch == b'_' || ch.is_ascii_uppercase() || (i > 0 && ch.is_ascii_digit()))
    {
        bail!(
            "environment variable references must use uppercase letters, digits, and underscores"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn http_requires_explicit_opt_in() {
        let parsed: Config = toml::from_str(
            r#"
            [[instances]]
            organization = "a"
            name = "prod"
            base_url = "http://dokploy.local"
            api_key_env = "DOKPLOY_KEY"
        "#,
        )
        .unwrap();
        assert!(parsed.validate().is_err());
    }
    #[test]
    fn http_is_only_accepted_towards_private_hosts() {
        let config = |url: &str| {
            toml::from_str::<Config>(&format!(
                r#"
                [security]
                allow_http = true
                [[instances]]
                organization = "a"
                name = "prod"
                base_url = "{url}"
                api_key_env = "DOKPLOY_KEY"
            "#
            ))
            .unwrap()
        };
        assert!(config("http://dokploy.acme.internal").validate().is_ok());
        assert!(config("http://100.64.12.34").validate().is_ok());
        assert!(config("http://dokploy.example.com").validate().is_err());
    }

    #[test]
    fn target_falls_back_to_default_or_single_instance() {
        let single: Config = toml::from_str(
            r#"
            [[instances]]
            organization = "a"
            name = "prod"
            base_url = "https://dokploy.example"
            api_key_env = "DOKPLOY_KEY"
        "#,
        )
        .unwrap();
        assert_eq!(single.target(None, None).unwrap().name, "prod");
        assert!(single.target(Some("a"), None).is_err());

        let several: Config = toml::from_str(
            r#"
            [[instances]]
            organization = "a"
            name = "dev"
            base_url = "https://dev.example"
            api_key_env = "DEV_KEY"
            [[instances]]
            organization = "a"
            name = "prod"
            base_url = "https://prod.example"
            api_key_env = "PROD_KEY"
            approval = "terminal"
            default = true
        "#,
        )
        .unwrap();
        let target = several.target(None, None).unwrap();
        assert_eq!(target.name, "prod");
        assert_eq!(target.approval(&several.security), ApprovalMode::Terminal);
    }

    #[test]
    fn raw_post_allowlist_rejects_destructive_procedures() {
        let config: Config = toml::from_str(
            r#"
            [security]
            raw_post_allowlist = ["compose.delete"]
            [[instances]]
            organization = "a"
            name = "prod"
            base_url = "https://dokploy.example"
            api_key_env = "DOKPLOY_KEY"
        "#,
        )
        .unwrap();
        assert!(config.validate().is_err());
    }

    fn multi_org() -> Config {
        toml::from_str(
            r#"
            [security]
            allow_http = true
            [[instances]]
            organization = "acme"
            name = "production"
            base_url = "http://dokploy.acme.internal"
            api_key_env = "ACME_KEY"
            paths = ["/work/acme"]
            [[instances]]
            organization = "globex"
            name = "production"
            base_url = "https://dokploy.globex.example"
            api_key_file = "/keys/globex"
            paths = ["/work/globex"]
            [[instances]]
            organization = "globex"
            name = "staging"
            base_url = "https://staging.globex.example"
            api_key_env = "GLOBEX_STAGING_KEY"
            paths = ["/work/globex/staging-app"]
        "#,
        )
        .unwrap()
    }

    #[test]
    fn selection_follows_flags_env_then_directory() {
        let config = multi_org();
        config.validate().unwrap();
        let pick = |org: Option<&str>, name: Option<&str>, env: Option<&str>, cwd: Option<&str>| {
            config
                .select(org, name, env, cwd.map(Path::new))
                .map(|s| (s.instance.label(), s.selected_by))
        };
        let (label, by) = pick(None, None, None, Some("/work/acme/platform/docs")).unwrap();
        assert_eq!(label, "acme/production");
        assert_eq!(by, SelectedBy::Path("/work/acme".into()));
        // The deepest mapped directory wins.
        assert_eq!(
            pick(None, None, None, Some("/work/globex/staging-app/src"))
                .unwrap()
                .0,
            "globex/staging"
        );
        assert_eq!(
            pick(None, None, None, Some("/work/globex/api")).unwrap().0,
            "globex/production"
        );
        // The environment variable beats the directory, flags beat both.
        assert_eq!(
            pick(None, None, Some("globex/production"), Some("/work/acme")).unwrap(),
            ("globex/production".into(), SelectedBy::Environment)
        );
        assert_eq!(
            pick(
                Some("acme"),
                Some("production"),
                Some("globex/production"),
                Some("/work/globex")
            )
            .unwrap(),
            ("acme/production".into(), SelectedBy::Flags)
        );
        // Outside every mapped directory, with no default, nothing is guessed.
        assert!(pick(None, None, None, Some("/work/tabwm")).is_err());
        // A path prefix that is not a directory boundary does not match.
        assert!(pick(None, None, None, Some("/work/acme-old")).is_err());
    }

    #[test]
    fn a_lone_mapped_instance_is_not_picked_outside_its_paths() {
        let mut config = multi_org();
        config.instances.truncate(1);
        assert!(
            config
                .select(None, None, None, Some(Path::new("/work/globex")))
                .is_err()
        );
        assert_eq!(
            config
                .select(None, None, None, Some(Path::new("/work/acme/x")))
                .unwrap()
                .instance
                .label(),
            "acme/production"
        );
        // Without mapped paths, a lone instance is still the implicit target.
        config.instances[0].paths.clear();
        assert!(
            config
                .select(None, None, None, Some(Path::new("/work/globex")))
                .is_ok()
        );
    }

    #[test]
    fn a_directory_cannot_belong_to_two_instances() {
        let mut config = multi_org();
        config.instances[1].paths.push("/work/acme".into());
        assert!(config.validate().is_err());
    }

    #[test]
    fn exactly_one_key_source_is_required() {
        let mut config = multi_org();
        config.instances[0].api_key_file = Some("/keys/acme".into());
        assert!(config.validate().is_err());
        config.instances[0].api_key_env = None;
        config.instances[0].api_key_file = None;
        assert!(config.validate().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn key_files_must_be_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("key");
        fs::write(&file, "secret-key\n").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(secret_from_file(&file).is_err());
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(secret_from_file(&file).unwrap(), "secret-key");
    }

    #[test]
    fn picks_exact_instance() {
        let config: Config = toml::from_str(
            r#"
            [[instances]]
            organization = "a"
            name = "prod"
            base_url = "https://dokploy.example"
            api_key_env = "DOKPLOY_KEY"
        "#,
        )
        .unwrap();
        assert_eq!(
            config.instance("a", "prod").unwrap().api_key_env.as_deref(),
            Some("DOKPLOY_KEY")
        );
    }
}
