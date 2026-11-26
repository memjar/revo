# Fleet Static Parser — Revo Provider Rebuild

Owner: Cortana (spec + acceptance). Team: Cursor, Hermes, Operator, Claude.
Date: 2026-11-26. Status: OPEN — tasking issued.

## Why
REA's built-in static JavaScript analyzer failed on a real production target:
PhantomBuster's shipped homepage bundle (index-C4QGcfrY.js, 3.2 MB minified
Vite SPA). Live run, evidence ev_43e22ad39f75901ea224aa5deba5d2d8d4597c61cfa27d2cd44f95dd3bf9b0aa:
parsed_javascript_files 0, parse_failures 1, visited_ast_nodes 0, routes 0,
coverage partial. The run completed and catalogued the artifact but extracted
no code structure. We do not ship a fleet RE capability that depends on an
upstream parser we cannot fix.

## What we build
A fleet-owned static parser for production JavaScript bundles, living INSIDE
the Revo repo (memjar/revo) as a provider the REA tooling can call — not a
side script. Working name: rea-fleet-static.

Requirements:
1. Parses large minified bundles (5 MB+) without choking: streaming/chunked
   parse, memory-bounded, no full-AST blow-up on pathological files.
2. Extracts what RE actually needs from a bundle: route patterns, string
   literals of interest (API base URLs, endpoint paths, feature flags),
   module/chunk graph, framework fingerprints (Vite/Webpack/Rollup markers),
   source-map discovery and recovery hooks.
3. Emits output in REA's evidence/graph shape (JavaScriptApplicationGraph-
   compatible) so it drops into Revo's existing providers and evidence
   bundles unchanged.
4. Fail-soft: a file it cannot parse degrades to string/endpoint extraction
   with the failure recorded — never a silent zero like the current parser.

## Acceptance test
Run against the PhantomBuster bundle (copy in Cortana's workspace,
/tmp/pb-demo/pb-index.js, sha in the evidence bundle above):
- parsed files >= 1, AST nodes > 0
- routes or endpoint literals extracted > 0 (REA scored 0)
- evidence bundle produced in REA format
Secondary targets: one Webpack bundle and one unminified app of the team's
choosing, to prove it is not a one-target hack.

## Roles (Jamie's tasking, 2026-11-26)
- Cursor — parser core: chunking, AST walk, extraction passes.
- Claude — route/string/endpoint extraction + the acceptance test suite.
- Operator — architecture review + verification plan (panel-for-panel
  against REA's graph schema).
- Hermes — coordination: relay onboarding so Cursor and Claude can join the
  work live (mints already tasked), board tracking, fold-in of results.
- Cortana — spec, acceptance target + evidence, final integration review,
  reporting to Jamie.

## Rules
- Work lands in memjar/revo on a team branch; no silent main pushes.
- Every claim of done carries a run artifact (evidence bundle or test log).
- Board is the source of truth for task state; RepoChat is the working
  channel until everyone is on the relay.
