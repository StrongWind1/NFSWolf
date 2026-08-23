# Convert

The `convert` subcommand renders a previously saved `analyze --json` dump into any supported presentation format. It is purely offline -- no NFS server is contacted. This avoids re-executing analysis checks (some of which write to the server, such as squash detection probes) and lets you produce multiple output formats from a single analysis run.

## Usage

```bash
nfswolf convert -i <JSON_FILE> --format <FORMAT> [-o <OUTPUT_FILE>]
```

### Examples

```bash
# Capture analysis data once
nfswolf analyze 10.0.0.1 --json results.json

# Render to self-contained HTML
nfswolf convert -i results.json --format html -o report.html

# Render to GitHub-flavored Markdown with a custom title
nfswolf convert -i results.json --format markdown -o findings.md --title "Q3 NFS Audit"

# Export findings as CSV for spreadsheet import
nfswolf convert -i results.json --format csv -o findings.csv

# Plain text for email or logging
nfswolf convert -i results.json --format txt -o summary.txt

# Print to terminal with ANSI colors (no -o needed)
nfswolf convert -i results.json --format console
```

## Output formats

| Format | Flag value | Description | Typical use |
|--------|-----------|-------------|-------------|
| HTML | `html` | Self-contained HTML with embedded CSS and severity charts | Stakeholder reports, offline viewing |
| Markdown | `markdown` | GitHub-flavored Markdown tables and headings | GitHub issues, wikis, PR descriptions |
| CSV | `csv` | One row per finding with severity, ID, and description columns | Spreadsheet import, SIEM ingestion, bulk analysis |
| Text | `txt` | Plain text with no formatting or colors | Email attachments, logging, text-only terminals |
| Console | `console` | ANSI-colored terminal output | Quick review, piping to `less -R` |
| JSON | `json` | Re-export of the analyzer result as JSON | Round-tripping, API consumption |

## Input format

The input file must contain the JSON produced by `nfswolf analyze --json`. Both a single `AnalysisResult` object and an array of results (from multi-host scans) are accepted. The output report aggregates all hosts and findings from the input.

## Flags reference

| Flag | Default | Description |
|------|---------|-------------|
| `-i, --input FILE` | *(required)* | Path to the JSON input file. |
| `--format FORMAT` | `html` | Output format: `html`, `markdown`, `csv`, `txt`, `console`, `json`. |
| `-o, --output FILE` | -- | Output file path. Omit for stdout (useful with `--format console`). |
| `--title TEXT` | `NFS Security Assessment` | Report title embedded in the output (HTML heading, Markdown title, etc.). |

## Workflow

The intended workflow separates data collection from presentation:

```bash
# 1. Run the analysis once (touches the server)
nfswolf analyze 10.0.0.1 --json results.json

# 2. Generate as many output formats as needed (offline)
nfswolf convert -i results.json --format html -o report.html
nfswolf convert -i results.json --format csv -o findings.csv
nfswolf convert -i results.json --format markdown -o findings.md
```

This avoids re-running the 30+ security checks (and the associated RPC traffic) for every output format you need.

## Related pages

- [Analyze](analyze.md) -- the analysis engine that produces the JSON input
- [Scan](scan.md) -- discovery step that precedes analysis
- [Global Options](global-options.md) -- flags that apply across all subcommands
