//! Errors a harness can act on without parsing prose: each failure has a
//! stable `kind`, a process exit code, a message and optional structured
//! details (candidates, instances). `main` prints it as JSON on stdout:
//!
//! ```json
//! {"ok": false, "error": {"kind": "service_ambiguous", "exit_code": 5, "message": "…", "details": {…}}}
//! ```

use serde::Serialize;
use serde_json::Value;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// Anything without a more specific kind.
    Error,
    /// Invalid configuration or instance file.
    Config,
    /// The working directory maps to no instance.
    TargetUnmapped,
    /// The working directory maps to several instances.
    TargetAmbiguous,
    /// `--org/--instance` or DOKPLOY_AGENT_TARGET name no configured instance.
    TargetUnknown,
    /// No service matches the query.
    ServiceNotFound,
    /// Several services match the query.
    ServiceAmbiguous,
    /// DNS, connection or timeout: usually the VPN.
    Network,
    /// The API key was rejected.
    Auth,
    /// Dokploy answered with another error status.
    Api,
    /// The tool refuses by policy: destructive, not allowlisted, unsupported.
    Refused,
    /// Applying needs a person at an interactive terminal.
    TerminalApprovalRequired,
    /// The approval token does not match the plan.
    ApprovalMismatch,
    /// The plan does not exist, was already applied, or expired.
    PlanUnavailable,
    /// The remote state changed since the plan was made.
    Drift,
}

impl Kind {
    pub fn exit_code(self) -> i32 {
        match self {
            Self::Error => 1,
            Self::Config => 2,
            Self::TargetUnmapped | Self::TargetAmbiguous | Self::TargetUnknown => 3,
            Self::ServiceNotFound => 4,
            Self::ServiceAmbiguous => 5,
            Self::Network => 10,
            Self::Auth => 11,
            Self::Api => 12,
            Self::Refused => 20,
            Self::TerminalApprovalRequired => 21,
            Self::ApprovalMismatch => 22,
            Self::PlanUnavailable => 23,
            Self::Drift => 24,
        }
    }
}

#[derive(Debug)]
pub struct Failure {
    pub kind: Kind,
    pub message: String,
    pub details: Option<Value>,
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Failure {}

/// An error of a given kind, to return with `?` or `Err(...)`.
pub fn fail(kind: Kind, message: impl Into<String>) -> anyhow::Error {
    Failure {
        kind,
        message: message.into(),
        details: None,
    }
    .into()
}

/// An error of a given kind with structured details for the harness.
pub fn fail_with(kind: Kind, message: impl Into<String>, details: Value) -> anyhow::Error {
    Failure {
        kind,
        message: message.into(),
        details: Some(details),
    }
    .into()
}

/// The JSON a failed command prints, and its exit code. The message keeps
/// anyhow's context chain so nothing useful is lost.
pub fn report(error: &anyhow::Error) -> (Value, i32) {
    let failure = error.chain().find_map(|e| e.downcast_ref::<Failure>());
    let kind = failure.map_or(Kind::Error, |f| f.kind);
    let message = error
        .chain()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(": ");
    let mut body = serde_json::json!({
        "kind": kind, "exit_code": kind.exit_code(), "message": message
    });
    if let Some(details) = failure.and_then(|f| f.details.clone()) {
        body["details"] = details;
    }
    (
        serde_json::json!({"ok": false, "error": body}),
        kind.exit_code(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;

    #[test]
    fn report_keeps_kind_details_and_context() {
        let error = Err::<(), _>(fail_with(
            Kind::ServiceAmbiguous,
            "\"docs\" matches 2 services",
            serde_json::json!({"candidates": ["a/prod/docs", "a/dev/docs"]}),
        ))
        .context("resolving the service")
        .unwrap_err();
        let (json, code) = report(&error);
        assert_eq!(code, 5);
        assert_eq!(json["ok"], false);
        assert_eq!(json["error"]["kind"], "service_ambiguous");
        assert_eq!(json["error"]["details"]["candidates"][1], "a/dev/docs");
        assert!(
            json["error"]["message"]
                .as_str()
                .unwrap()
                .starts_with("resolving the service: ")
        );
    }

    #[test]
    fn plain_errors_are_generic() {
        let (json, code) = report(&anyhow::anyhow!("boom"));
        assert_eq!(code, 1);
        assert_eq!(json["error"]["kind"], "error");
    }
}
