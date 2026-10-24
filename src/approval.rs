//! The human step of `apply` on instances with `approval = "terminal"`.
//!
//! The approval token proves a plan was not changed after review, but whoever
//! holds the plan output can pass it. Terminal approval adds a step only a
//! person at a real terminal can take: retyping the plan's short id. A harness
//! runs without a TTY, so it cannot complete it.

use crate::plan::Plan;
use anyhow::{Result, bail};
use std::io::{BufRead, IsTerminal, Write};

/// The first 8 characters of the plan id: what the operator retypes.
pub fn short_id(plan: &Plan) -> String {
    plan.id.simple().to_string()[..8].to_owned()
}

/// Shows the plan on stderr and waits for the operator to retype its short id.
pub fn confirm_in_terminal(plan: &Plan) -> Result<()> {
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        bail!(
            "this instance requires terminal approval: a person must run `apply` from an interactive terminal (no TTY here)"
        );
    }
    let mut stderr = std::io::stderr();
    writeln!(
        stderr,
        "Plan {} on {}/{}",
        plan.id, plan.organization, plan.instance
    )?;
    writeln!(stderr, "  operation: {}", plan.action.operation_name())?;
    writeln!(
        stderr,
        "  changes:   {}",
        serde_json::to_string_pretty(&plan.action.safe_summary())?
    )?;
    write!(stderr, "Type {} to apply it: ", short_id(plan))?;
    stderr.flush()?;
    let mut answer = String::new();
    std::io::stdin().lock().read_line(&mut answer)?;
    if !answer_matches(&answer, &short_id(plan)) {
        bail!("approval not confirmed; nothing was changed");
    }
    Ok(())
}

fn answer_matches(answer: &str, expected: &str) -> bool {
    answer.trim() == expected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_exact_short_id_confirms() {
        assert!(answer_matches("ab12cd34\n", "ab12cd34"));
        assert!(!answer_matches("yes\n", "ab12cd34"));
        assert!(!answer_matches("ab12cd3\n", "ab12cd34"));
        assert!(!answer_matches("\n", "ab12cd34"));
    }
}
