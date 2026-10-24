use crate::{
    audit,
    client::{ServiceAction, ServiceKind, WriteEndpoint},
};
use anyhow::{Context, Result, bail};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    pub version: u8,
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub organization: String,
    pub instance: String,
    pub action: PlannedAction,
    pub digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PlannedAction {
    ComposeUpdate {
        compose_id: String,
        compose_file: String,
        content_sha256: String,
        base_remote_sha256: String,
    },
    PostgresCreate {
        environment_id: String,
        name: String,
        database_name: String,
        database_user: String,
        password_env: String,
        docker_image: Option<String>,
        server_id: Option<String>,
    },
    /// deploy, redeploy, start or stop one service.
    ServiceAction {
        service_kind: ServiceKind,
        service_id: String,
        label: String,
        action: ServiceAction,
    },
    /// Replaces the whole env block of a service. The current block is backed
    /// up (owner-only) right before the change, and the change is refused if
    /// the remote env moved since the plan was made.
    EnvSet {
        service_kind: ServiceKind,
        service_id: String,
        label: String,
        env: String,
        keys: Vec<String>,
        env_sha256: String,
        base_env_sha256: String,
    },
    /// Creates a raw Compose. Dokploy creates it with a git source, so apply
    /// also sets `sourceType: raw` on the new Compose.
    ComposeCreate {
        environment_id: String,
        server_id: Option<String>,
        name: String,
        description: Option<String>,
        compose_file: String,
        content_sha256: String,
    },
    /// Changes Compose settings that are not its file: source type, name, description.
    ComposeSettings {
        compose_id: String,
        label: String,
        source_type: Option<String>,
        name: Option<String>,
        description: Option<String>,
    },
    /// A POST to a procedure listed in `security.raw_post_allowlist`.
    RawPost { procedure: String, body: Value },
}

impl PlannedAction {
    pub fn endpoint(&self) -> WriteEndpoint {
        match self {
            Self::ComposeUpdate { .. } | Self::ComposeSettings { .. } => {
                WriteEndpoint::ComposeUpdate
            }
            Self::PostgresCreate { .. } => WriteEndpoint::PostgresCreate,
            Self::ServiceAction {
                service_kind,
                action,
                ..
            } => WriteEndpoint::Action(*service_kind, *action),
            Self::EnvSet { service_kind, .. } => WriteEndpoint::SaveEnvironment(*service_kind),
            Self::ComposeCreate { .. } => WriteEndpoint::ComposeCreate,
            Self::RawPost { procedure, .. } => WriteEndpoint::Raw(procedure.clone()),
        }
    }
    pub fn operation_name(&self) -> String {
        self.endpoint().path()
    }
    pub fn safe_summary(&self) -> Value {
        match self {
            Self::ComposeUpdate {
                compose_id,
                content_sha256,
                base_remote_sha256,
                ..
            } => {
                json!({"compose_id": compose_id, "content_sha256": content_sha256, "base_remote_sha256": base_remote_sha256})
            }
            Self::PostgresCreate {
                environment_id,
                name,
                database_name,
                database_user,
                password_env,
                docker_image,
                server_id,
            } => json!({
                "environment_id": environment_id, "name": name, "database_name": database_name, "database_user": database_user,
                "password_env": password_env, "docker_image": docker_image, "server_id": server_id
            }),
            Self::ServiceAction {
                service_kind,
                service_id,
                label,
                action,
            } => {
                json!({"service": label, "kind": service_kind, "service_id": service_id, "action": action})
            }
            Self::EnvSet {
                service_kind,
                service_id,
                label,
                keys,
                env_sha256,
                base_env_sha256,
                ..
            } => json!({
                "service": label, "kind": service_kind, "service_id": service_id,
                "replaces_all_variables_with": keys, "env_sha256": env_sha256, "base_env_sha256": base_env_sha256,
                "note": "values stay in the protected plan file; the current env is backed up before the change and applies on the next deploy"
            }),
            Self::ComposeCreate {
                environment_id,
                server_id,
                name,
                description,
                compose_file,
                content_sha256,
            } => json!({
                "name": name, "description": description, "environment_id": environment_id, "server_id": server_id,
                "content_sha256": content_sha256, "services": compose_services(compose_file), "source_type": "raw"
            }),
            Self::ComposeSettings {
                compose_id,
                label,
                source_type,
                name,
                description,
            } => {
                json!({"service": label, "compose_id": compose_id, "source_type": source_type, "name": name, "description": description})
            }
            Self::RawPost { procedure, body } => {
                json!({"procedure": procedure, "body": crate::redact::redact(body.clone())})
            }
        }
    }
}

/// Service names of a Compose file, for a plan summary that shows what will
/// run without printing the file (which can embed secrets).
fn compose_services(content: &str) -> Vec<String> {
    serde_yaml::from_str::<serde_yaml::Value>(content)
        .ok()
        .and_then(|yaml| yaml.get("services").and_then(|s| s.as_mapping()).cloned())
        .map(|services| {
            services
                .keys()
                .filter_map(|key| key.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

impl Plan {
    pub fn new(
        organization: String,
        instance: String,
        action: PlannedAction,
        ttl_seconds: u64,
    ) -> Result<Self> {
        let created_at = Utc::now();
        let expires_at = created_at + Duration::seconds(ttl_seconds.try_into()?);
        let id = Uuid::new_v4();
        let digest = digest_fields(
            1,
            id,
            created_at,
            expires_at,
            &organization,
            &instance,
            &action,
        )?;
        Ok(Self {
            version: 1,
            id,
            created_at,
            expires_at,
            organization,
            instance,
            action,
            digest,
        })
    }
    pub fn verify(&self) -> Result<()> {
        if self.version != 1 {
            bail!("unsupported plan version");
        }
        if self.expires_at <= Utc::now() {
            bail!("plan has expired; generate and review a new plan");
        }
        let expected = digest_fields(
            self.version,
            self.id,
            self.created_at,
            self.expires_at,
            &self.organization,
            &self.instance,
            &self.action,
        )?;
        if expected != self.digest {
            bail!("plan integrity check failed");
        }
        Ok(())
    }
    pub fn safe_output(&self) -> Value {
        json!({
            "plan_id": self.id, "expires_at": self.expires_at, "organization": self.organization, "instance": self.instance,
            "operation": self.action.operation_name(), "changes": self.action.safe_summary(), "approval_token_sha256": self.digest,
            "next_step": "A human must review this plan, then use apply with the exact approval_token_sha256 before expiry."
        })
    }
}

fn digest_fields(
    version: u8,
    id: Uuid,
    created: DateTime<Utc>,
    expires: DateTime<Utc>,
    org: &str,
    instance: &str,
    action: &PlannedAction,
) -> Result<String> {
    #[derive(Serialize)]
    struct Signed<'a> {
        version: u8,
        id: Uuid,
        created: DateTime<Utc>,
        expires: DateTime<Utc>,
        org: &'a str,
        instance: &'a str,
        action: &'a PlannedAction,
    }
    let bytes = serde_json::to_vec(&Signed {
        version,
        id,
        created,
        expires,
        org,
        instance,
        action,
    })?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

pub fn content_sha256(content: &str) -> String {
    format!("{:x}", Sha256::digest(content.as_bytes()))
}

pub fn save(root: &Path, plan: &Plan) -> Result<PathBuf> {
    let directory = root.join("plans");
    fs::create_dir_all(&directory)?;
    let path = directory.join(format!("{}.json", plan.id));
    let temporary = directory.join(format!(".{}.tmp", plan.id));
    let contents = serde_json::to_vec(plan)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .context("cannot create protected plan")?;
    restrict(&file)?;
    file.write_all(&contents)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, &path)?;
    Ok(path)
}

pub fn load(root: &Path, id: &str) -> Result<Plan> {
    let id = Uuid::parse_str(id).context("plan must be a UUID")?;
    let path = root.join("plans").join(format!("{id}.json"));
    let metadata = fs::symlink_metadata(&path).context("plan not found")?;
    if metadata.file_type().is_symlink() {
        bail!("refusing to load symbolic-link plan");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("refusing plan with group/world permissions");
        }
    }
    let mut file = File::open(path)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;
    serde_json::from_slice(&contents).context("invalid plan file")
}

/// Atomically removes a plan from the runnable directory before a remote
/// mutation. Failures leave it in `inflight/` to prevent unsafe replays.
pub fn claim(root: &Path, id: &str) -> Result<Plan> {
    let id = Uuid::parse_str(id).context("plan must be a UUID")?;
    let source = root.join("plans").join(format!("{id}.json"));
    let destination_dir = root.join("inflight");
    fs::create_dir_all(&destination_dir)?;
    let destination = destination_dir.join(format!("{id}.json"));
    fs::rename(&source, &destination)
        .context("plan is unavailable, already claimed, or not found")?;
    let metadata = fs::symlink_metadata(&destination)?;
    if metadata.file_type().is_symlink() {
        bail!("refusing symbolic-link plan");
    }
    let mut content = Vec::new();
    File::open(destination)?.read_to_end(&mut content)?;
    let plan: Plan = serde_json::from_slice(&content).context("invalid plan file")?;
    plan.verify()?;
    Ok(plan)
}

pub fn request_body(plan: &Plan) -> Result<Value> {
    match &plan.action {
        PlannedAction::ComposeUpdate {
            compose_id,
            compose_file,
            ..
        } => Ok(json!({"composeId": compose_id, "composeFile": compose_file})),
        PlannedAction::PostgresCreate {
            environment_id,
            name,
            database_name,
            database_user,
            password_env,
            docker_image,
            server_id,
        } => {
            let password = crate::config::secret_from_env(password_env)?;
            let mut body = json!({"environmentId": environment_id, "name": name, "databaseName": database_name, "databaseUser": database_user, "databasePassword": password});
            if let Some(image) = docker_image {
                body["dockerImage"] = json!(image);
            }
            if let Some(server) = server_id {
                body["serverId"] = json!(server);
            }
            Ok(body)
        }
        PlannedAction::ServiceAction {
            service_kind,
            service_id,
            ..
        } => Ok(json!({ service_kind.id_param(): service_id })),
        PlannedAction::EnvSet {
            service_kind,
            service_id,
            env,
            ..
        } => Ok(json!({ service_kind.id_param(): service_id, "env": env })),
        PlannedAction::ComposeCreate {
            environment_id,
            server_id,
            name,
            description,
            compose_file,
            ..
        } => {
            let mut body = json!({
                "name": name, "environmentId": environment_id,
                "composeType": "docker-compose", "composeFile": compose_file
            });
            if let Some(server) = server_id {
                body["serverId"] = json!(server);
            }
            if let Some(description) = description {
                body["description"] = json!(description);
            }
            Ok(body)
        }
        PlannedAction::ComposeSettings {
            compose_id,
            source_type,
            name,
            description,
            ..
        } => {
            let mut body = json!({"composeId": compose_id});
            if let Some(source_type) = source_type {
                body["sourceType"] = json!(source_type);
            }
            if let Some(name) = name {
                body["name"] = json!(name);
            }
            if let Some(description) = description {
                body["description"] = json!(description);
            }
            Ok(body)
        }
        PlannedAction::RawPost { body, .. } => Ok(body.clone()),
    }
}

pub fn audit_success(root: &Path, plan: &Plan) -> Result<()> {
    audit::append(
        &root.join("audit.jsonl"),
        &audit::AuditEvent {
            timestamp: Utc::now(),
            organization: &plan.organization,
            instance: &plan.instance,
            operation: &plan.action.operation_name(),
            plan_id: &plan.id.to_string(),
            outcome: "applied",
            error: None,
        },
    )
}

pub fn audit_failure(root: &Path, plan: &Plan, error: &str) -> Result<()> {
    audit::append(
        &root.join("audit.jsonl"),
        &audit::AuditEvent {
            timestamp: Utc::now(),
            organization: &plan.organization,
            instance: &plan.instance,
            operation: &plan.action.operation_name(),
            plan_id: &plan.id.to_string(),
            outcome: "failed",
            error: Some(error),
        },
    )
}

#[cfg(unix)]
fn restrict(file: &File) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(())
}
#[cfg(not(unix))]
fn restrict(_: &File) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn plan_rejects_tampering() {
        let mut plan = Plan::new(
            "org".into(),
            "prod".into(),
            PlannedAction::PostgresCreate {
                environment_id: "env".into(),
                name: "db".into(),
                database_name: "db".into(),
                database_user: "user".into(),
                password_env: "DATABASE_PASSWORD".into(),
                docker_image: None,
                server_id: None,
            },
            300,
        )
        .unwrap();
        plan.instance = "other".into();
        assert!(plan.verify().is_err());
    }
    #[test]
    fn env_set_summary_never_contains_values() {
        let plan = Plan::new(
            "org".into(),
            "prod".into(),
            PlannedAction::EnvSet {
                service_kind: ServiceKind::Compose,
                service_id: "c1".into(),
                label: "landing/production/docs".into(),
                env: "SECRET_TOKEN=super-secret-value".into(),
                keys: vec!["SECRET_TOKEN".into()],
                env_sha256: content_sha256("SECRET_TOKEN=super-secret-value"),
                base_env_sha256: content_sha256(""),
            },
            300,
        )
        .unwrap();
        let shown = plan.safe_output().to_string();
        assert!(shown.contains("SECRET_TOKEN"));
        assert!(!shown.contains("super-secret-value"));
        let body = request_body(&plan).unwrap();
        assert_eq!(body["composeId"], "c1");
        assert_eq!(plan.action.operation_name(), "compose.saveEnvironment");
    }

    #[test]
    fn compose_create_summary_lists_services_not_the_file() {
        let file =
            "services:\n  web:\n    image: nginx\n    environment:\n      TOKEN: hidden-value\n";
        let plan = Plan::new(
            "org".into(),
            "prod".into(),
            PlannedAction::ComposeCreate {
                environment_id: "e1".into(),
                server_id: Some("s1".into()),
                name: "docs".into(),
                description: None,
                compose_file: file.into(),
                content_sha256: content_sha256(file),
            },
            300,
        )
        .unwrap();
        let shown = plan.safe_output().to_string();
        assert!(shown.contains("\"web\""));
        assert!(!shown.contains("hidden-value"));
        assert_eq!(request_body(&plan).unwrap()["serverId"], "s1");
    }

    #[test]
    fn service_action_targets_the_right_procedure() {
        let plan = Plan::new(
            "org".into(),
            "prod".into(),
            PlannedAction::ServiceAction {
                service_kind: ServiceKind::Application,
                service_id: "a1".into(),
                label: "Dev/production/core-api".into(),
                action: ServiceAction::Redeploy,
            },
            300,
        )
        .unwrap();
        assert_eq!(plan.action.operation_name(), "application.redeploy");
        assert_eq!(request_body(&plan).unwrap(), json!({"applicationId": "a1"}));
    }

    #[test]
    fn compose_content_is_hashed() {
        assert_ne!(content_sha256("a"), content_sha256("b"));
    }
    #[test]
    fn claiming_a_plan_prevents_replay() {
        let temporary = tempfile::tempdir().unwrap();
        let plan = Plan::new(
            "org".into(),
            "prod".into(),
            PlannedAction::ComposeUpdate {
                compose_id: "compose".into(),
                compose_file: "services: {}".into(),
                content_sha256: content_sha256("services: {}"),
                base_remote_sha256: content_sha256("services: {}"),
            },
            300,
        )
        .unwrap();
        save(temporary.path(), &plan).unwrap();
        let claimed = claim(temporary.path(), &plan.id.to_string()).unwrap();
        assert_eq!(claimed.id, plan.id);
        assert!(claim(temporary.path(), &plan.id.to_string()).is_err());
    }
}
