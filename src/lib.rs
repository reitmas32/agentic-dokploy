pub mod approval;
pub mod audit;
pub mod client;
pub mod config;
pub mod envfile;
pub mod failure;
pub mod inventory;
pub mod net;
pub mod plan;
pub mod redact;

use anyhow::Result;
use serde::Serialize;

pub fn print_json<T: Serialize>(value: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}
