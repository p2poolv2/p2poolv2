// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The dashboard's stylesheet, inlined into every page so the node serves
//! no separate files.

pub(crate) const STYLE: &str = r#"
:root {
  color-scheme: dark;
  --bg: #12151b; --panel: #1b2029; --line: #2a313d; --text: #e6e9ef;
  --muted: #9aa3b2; --accent: #0ac18e; --pool: #0ac18e; --local: #22d3ee;
  --network: #a78bfa; --block: #f5b942;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text);
  font: 15px/1.45 system-ui, -apple-system, "Segoe UI", Roboto, Ubuntu, sans-serif; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
header { display: flex; flex-wrap: wrap; align-items: baseline; gap: 12px;
  padding: 16px 24px; border-bottom: 1px solid var(--line); }
header h1 { margin: 0; font-size: 20px; }
header h1 span { color: var(--accent); }
header .network { color: var(--muted); }
header nav { margin-left: auto; }
main { max-width: 1100px; margin: 0 auto; padding: 20px 24px 40px; }
h2 { font-size: 16px; margin: 28px 0 10px; color: var(--muted); font-weight: 600; }
.kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; }
.kpi { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 12px 14px; }
.kpi .label { color: var(--muted); font-size: 13px; }
.kpi .value { font-size: 22px; font-weight: 600; margin-top: 2px; }
.kpi .note { color: var(--muted); font-size: 12px; }
.panel { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 14px; }
.chart svg { width: 100%; height: auto; display: block; }
.chart .grid { stroke: var(--line); stroke-width: 1; }
.chart .axis { fill: var(--muted); font-size: 11px; }
.chart .line { fill: none; stroke-width: 2; }
.chart .dot { stroke: none; opacity: 0.85; }
.chart .dot:hover { opacity: 1; }
.chart figcaption { display: flex; gap: 16px; color: var(--muted); font-size: 13px; padding-top: 6px; }
.chart .key::before { content: ""; display: inline-block; width: 10px; height: 10px;
  border-radius: 2px; margin-right: 6px; background: currentColor; }
.line.pool { stroke: var(--pool); } .dot.pool, .key.pool { fill: var(--pool); color: var(--pool); }
.line.local { stroke: var(--local); } .dot.local, .key.local { fill: var(--local); color: var(--local); }
.line.network { stroke: var(--network); } .dot.network, .key.network { fill: var(--network); color: var(--network); }
.chart figure, figure.chart { margin: 0; }
p.empty { color: var(--muted); margin: 8px 0; }
table { width: 100%; border-collapse: collapse; font-size: 14px; }
th, td { text-align: left; padding: 7px 8px; border-bottom: 1px solid var(--line); }
th { color: var(--muted); font-weight: 500; }
td.mono, .mono { font-family: ui-monospace, "SF Mono", Consolas, monospace; font-size: 13px; }
.badge { display: inline-block; padding: 1px 7px; border-radius: 9px; font-size: 12px;
  background: var(--block); color: #12151b; font-weight: 600; }
form.lookup { display: flex; gap: 8px; flex-wrap: wrap; }
form.lookup input { flex: 1 1 340px; padding: 8px 10px; border-radius: 8px;
  border: 1px solid var(--line); background: var(--bg); color: var(--text); }
form.lookup button { padding: 8px 16px; border-radius: 8px; border: 0;
  background: var(--accent); color: #0b0d11; font-weight: 600; cursor: pointer; }
dl.fields { display: grid; grid-template-columns: max-content 1fr; gap: 6px 16px; margin: 0; }
dl.fields dt { color: var(--muted); }
dl.fields dd { margin: 0; overflow-wrap: anywhere; }
.error { border-color: #b4474f; }
footer { color: var(--muted); font-size: 12px; text-align: center; padding: 20px; }
"#;
