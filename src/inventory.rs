//! The services of an instance as one flat list, and name resolution.
//!
//! `project.all` nests services under projects and, since Dokploy v0.2x, under
//! environments (development, staging, production), so the same name exists
//! once per environment with a different id. A query accepts `service`,
//! `environment/service`, `project/service` or `project/environment/service`,
//! and an ambiguous one fails listing the candidates instead of guessing.

use crate::client::{DokployClient, ServiceKind};
use anyhow::{Result, bail};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeSet;
use tokio::task::JoinSet;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Service {
    pub project: String,
    pub environment: String,
    pub kind: ServiceKind,
    pub name: String,
    pub app_name: String,
    pub status: String,
    pub server_id: String,
    pub id: String,
}

impl Service {
    pub fn label(&self) -> String {
        if self.environment.is_empty() {
            format!("{}/{}", self.project, self.name)
        } else {
            format!("{}/{}/{}", self.project, self.environment, self.name)
        }
    }
}

/// Flattens a `project.all` response. Native databases come back with only
/// their id; their `name` is left empty for `complete_names` to fill.
pub fn flatten(projects: &Value) -> Vec<Service> {
    let mut services = Vec::new();
    let projects = match projects {
        Value::Array(items) => items.iter().collect::<Vec<_>>(),
        other => vec![other],
    };
    for project in projects {
        let Some(project_name) = project.get("name").and_then(Value::as_str) else {
            continue;
        };
        if project.get("projectId").is_none() {
            continue;
        }
        match project.get("environments").and_then(Value::as_array) {
            Some(environments) => {
                for environment in environments {
                    let environment_name = environment
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    collect(environment, project_name, environment_name, &mut services);
                }
            }
            None => collect(project, project_name, "", &mut services),
        }
    }
    let mut seen = BTreeSet::new();
    services.retain(|service| seen.insert(service.id.clone()));
    services
}

fn kind_of(object: &serde_json::Map<String, Value>) -> Option<(ServiceKind, String)> {
    ServiceKind::ALL.into_iter().find_map(|kind| {
        object
            .get(kind.id_param())
            .and_then(Value::as_str)
            .map(|id| (kind, id.to_owned()))
    })
}

fn text(object: &serde_json::Map<String, Value>, keys: &[&str]) -> String {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str))
        .unwrap_or_default()
        .to_owned()
}

fn collect(node: &Value, project: &str, environment: &str, out: &mut Vec<Service>) {
    match node {
        Value::Object(object) => {
            // A service has a name; a bare native database reference is a
            // single id key. Anything else carrying an id (a domain, a mount, a
            // deployment) belongs to a service and is skipped.
            if let Some((kind, id)) = kind_of(object) {
                if object.contains_key("name") || object.len() == 1 {
                    out.push(Service {
                        project: project.to_owned(),
                        environment: environment.to_owned(),
                        kind,
                        name: text(object, &["name"]),
                        app_name: text(object, &["appName"]),
                        status: status_of(node),
                        server_id: text(object, &["serverId"]),
                        id,
                    });
                }
            }
            for value in object.values() {
                collect(value, project, environment, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect(item, project, environment, out);
            }
        }
        _ => {}
    }
}

pub fn status_of(service: &Value) -> String {
    ["applicationStatus", "composeStatus", "status"]
        .iter()
        .find_map(|key| service.get(*key).and_then(Value::as_str))
        .unwrap_or("?")
        .to_owned()
}

/// Fetches `<router>.one` for every service listed without a name (native
/// databases), in parallel, and fills in its name, app name and status.
pub async fn complete_names(client: &DokployClient, services: &mut [Service]) {
    let mut tasks = JoinSet::new();
    for (index, service) in services.iter().enumerate() {
        if !service.name.is_empty() {
            continue;
        }
        let client = client.clone();
        let (kind, id) = (service.kind, service.id.clone());
        tasks.spawn(async move {
            let detail = client
                .get_procedure(
                    &format!("{}.one", kind.router()),
                    &[(kind.id_param(), id.as_str())],
                )
                .await;
            (index, detail)
        });
    }
    while let Some(Ok((index, detail))) = tasks.join_next().await {
        let service = &mut services[index];
        match detail {
            Ok(detail) => {
                service.name = detail
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or(&service.id)
                    .to_owned();
                if let Some(app_name) = detail.get("appName").and_then(Value::as_str) {
                    service.app_name = app_name.to_owned();
                }
                if let Some(server_id) = detail.get("serverId").and_then(Value::as_str) {
                    service.server_id = server_id.to_owned();
                }
                service.status = status_of(&detail);
            }
            Err(_) => service.name = service.id.clone(),
        }
    }
}

/// Loads the inventory of an instance.
pub async fn load(client: &DokployClient) -> Result<Vec<Service>> {
    let projects = client.get_procedure("project.all", &[]).await?;
    let mut services = flatten(&projects);
    complete_names(client, &mut services).await;
    Ok(services)
}

/// Services whose project, environment, name, app name or kind contain `filter`.
pub fn filter<'a>(services: &'a [Service], filter: &str) -> Vec<&'a Service> {
    let filter = filter.to_lowercase();
    services
        .iter()
        .filter(|s| {
            format!(
                "{} {} {} {} {}",
                s.project,
                s.environment,
                s.name,
                s.app_name,
                s.kind.label()
            )
            .to_lowercase()
            .contains(&filter)
        })
        .collect()
}

/// The single service a query names, or an error that lists the candidates.
pub fn resolve<'a>(services: &'a [Service], query: &str) -> Result<&'a Service> {
    let segments: Vec<&str> = query.split('/').collect();
    let environments: BTreeSet<String> = services
        .iter()
        .map(|s| s.environment.to_lowercase())
        .filter(|e| !e.is_empty())
        .collect();
    let (project, environment, name) = match segments.as_slice() {
        [name] => (None, None, *name),
        [head, name] if environments.contains(&head.to_lowercase()) => (None, Some(*head), *name),
        [head, name] => (Some(*head), None, *name),
        [project, environment, name] => (Some(*project), Some(*environment), *name),
        _ => bail!(
            "invalid service query {query:?}: use service, environment/service or project/environment/service"
        ),
    };
    if name.is_empty() {
        bail!("invalid service query {query:?}");
    }
    let pool: Vec<&Service> = services
        .iter()
        .filter(|s| project.is_none_or(|p| s.project.eq_ignore_ascii_case(p)))
        .filter(|s| environment.is_none_or(|e| s.environment.eq_ignore_ascii_case(e)))
        .collect();
    let exact: Vec<&Service> = pool
        .iter()
        .copied()
        .filter(|s| s.id == name || s.name == name || s.app_name == name)
        .collect();
    let hits = if exact.is_empty() {
        let needle = name.to_lowercase();
        pool.into_iter()
            .filter(|s| {
                s.name.to_lowercase().contains(&needle)
                    || s.app_name.to_lowercase().contains(&needle)
            })
            .collect()
    } else {
        exact
    };
    match hits.as_slice() {
        [only] => Ok(only),
        [] => bail!("no service matches {query:?}; list them with `get services`"),
        many => bail!(
            "{query:?} matches {} services; repeat with project/environment/service:\n{}",
            many.len(),
            many.iter()
                .map(|s| format!("  {}", s.label()))
                .collect::<Vec<_>>()
                .join("\n")
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> Value {
        json!([
            {
                "projectId": "p1",
                "name": "landing",
                "environments": [
                    {
                        "environmentId": "e1",
                        "name": "production",
                        "compose": [{
                            "composeId": "c1", "name": "docs", "appName": "compose-docs-1",
                            "composeStatus": "done", "serverId": "s3",
                            "domains": [{"domainId": "d1", "composeId": "c1", "host": "docs.example.com"}],
                            "deployments": [{"deploymentId": "x", "composeId": "c1", "title": "t"}]
                        }],
                        "postgres": [{"postgresId": "pg1"}]
                    },
                    {
                        "environmentId": "e2",
                        "name": "development",
                        "compose": [{"composeId": "c2", "name": "docs", "appName": "compose-docs-2", "composeStatus": "idle"}]
                    }
                ]
            },
            {
                "projectId": "p2",
                "name": "Dev",
                "environments": [{
                    "environmentId": "e3", "name": "production",
                    "applications": [{"applicationId": "a1", "name": "core-api", "appName": "core-api-x", "applicationStatus": "done"}]
                }]
            }
        ])
    }

    #[test]
    fn flatten_finds_services_and_skips_nested_references() {
        let services = flatten(&fixture());
        let ids: Vec<_> = services.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(ids, ["c1", "pg1", "c2", "a1"]);
        assert_eq!(services[0].environment, "production");
        assert_eq!(services[0].status, "done");
        assert_eq!(services[1].kind, ServiceKind::Postgres);
        assert!(services[1].name.is_empty());
        assert_eq!(services[3].kind, ServiceKind::Application);
    }

    #[test]
    fn resolve_requires_disambiguation() {
        let services = flatten(&fixture());
        let error = resolve(&services, "docs").unwrap_err().to_string();
        assert!(
            error.contains("landing/production/docs") && error.contains("landing/development/docs")
        );
        assert_eq!(resolve(&services, "production/docs").unwrap().id, "c1");
        assert_eq!(
            resolve(&services, "landing/development/docs").unwrap().id,
            "c2"
        );
        assert_eq!(resolve(&services, "Dev/core-api").unwrap().id, "a1");
        assert_eq!(resolve(&services, "c2").unwrap().id, "c2");
        assert_eq!(resolve(&services, "core").unwrap().id, "a1");
        assert!(resolve(&services, "nothing").is_err());
    }

    #[test]
    fn filter_matches_any_field() {
        let services = flatten(&fixture());
        assert_eq!(filter(&services, "development").len(), 1);
        assert_eq!(filter(&services, "compose").len(), 2);
    }
}
