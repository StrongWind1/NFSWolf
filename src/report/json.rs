//! JSON output  --  serialises `AnalysisResult` slice to compact pretty JSON.
//!
//! This is intentionally a thin wrapper: `AnalysisResult` already derives
//! `serde::Serialize`, so the only work here is choosing the writer path.

use std::io::Write;

use crate::engine::analyzer::AnalysisResult;

/// Write `results` as a pretty-printed JSON array to `out`.
///
/// The consumer is expected to pipe the output into jq or save it as the
/// input file for a subsequent `export` command invocation.
pub fn render(results: &[AnalysisResult], out: &mut dyn Write) -> anyhow::Result<()> {
    serde_json::to_writer_pretty(out, results)?;
    Ok(())
}
