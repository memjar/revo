import { createHash } from "node:crypto";

import {
  createJavaScriptApplicationGraph,
  createJavaScriptApplicationNode,
  type JavaScriptApplicationGraph,
} from "./javascriptApplicationGraph.js";
import { completeApplicationCoverage } from "./javascriptApplicationEvidenceSchemas.js";
import {
  parseJavaScriptSource,
  type ParsedJavaScriptSource,
} from "./javascriptSourceParser.js";
import { traverseJavaScriptAst } from "./javascriptSemanticTraversal.js";

/** Bytes aimed at for one Babel parse. Larger bundles are split on statement boundaries. */
const CHUNK_TARGET = 160_000;
/** Hard cap so a missing boundary cannot hand Babel an unbounded window. */
const CHUNK_HARD_CAP = CHUNK_TARGET * 2;
/** Stop walking one chunk after this many nodes and record a truncation. */
const NODE_BUDGET = 200_000;
const MAX_STRINGS = 200;

export interface FleetStaticChunk {
  readonly start: number;
  readonly end: number;
  readonly text: string;
}

export interface FleetStaticResult {
  readonly schema: "rea-fleet-static";
  readonly statistics: {
    readonly parsed_javascript_files: number;
    readonly visited_ast_nodes: number;
    readonly parse_failures: number;
    readonly chunks: number;
    readonly routes: number;
  };
  readonly endpoints: readonly string[];
  readonly modules: readonly string[];
  readonly fingerprints: readonly string[];
  readonly source_maps: readonly string[];
  readonly limitations: readonly string[];
  readonly graph: JavaScriptApplicationGraph;
}

interface ScanState {
  quote: "'" | '"' | "`" | null;
  escape: boolean;
  lineComment: boolean;
  blockComment: boolean;
  brace: number;
  paren: number;
  bracket: number;
  templateBrace: number;
}

const freshScan = (): ScanState => ({
  quote: null,
  escape: false,
  lineComment: false,
  blockComment: false,
  brace: 0,
  paren: 0,
  bracket: 0,
  templateBrace: 0,
});

/** Split source on top-level statement boundaries, never inside strings or comments. */
export const chunkJavaScriptSource = (
  source: string,
  target = CHUNK_TARGET,
): FleetStaticChunk[] => {
  const chunks: FleetStaticChunk[] = [];
  let start = 0;
  const state = freshScan();
  for (let index = 0; index < source.length; index += 1) {
    const current = source[index] ?? "";
    const next = source[index + 1] ?? "";
    advanceScan(state, current, next);
    const span = index + 1 - start;
    const atBoundary =
      state.quote === null &&
      !state.lineComment &&
      !state.blockComment &&
      state.brace === 0 &&
      state.paren === 0 &&
      state.bracket === 0 &&
      (current === ";" || current === "}");
    if ((atBoundary && span >= target) || span >= CHUNK_HARD_CAP) {
      pushChunk(chunks, source, start, index + 1);
      start = index + 1;
    }
  }
  if (start < source.length || chunks.length === 0) {
    pushChunk(chunks, source, start, source.length);
  }
  return chunks;
};

const pushChunk = (
  chunks: FleetStaticChunk[],
  source: string,
  start: number,
  end: number,
): void => {
  if (end <= start && chunks.length > 0) return;
  chunks.push({ start, end, text: source.slice(start, end) });
};

const advanceScan = (state: ScanState, current: string, next: string): void => {
  if (state.lineComment) {
    if (current === "\n") state.lineComment = false;
    return;
  }
  if (state.blockComment) {
    if (current === "*" && next === "/") state.blockComment = false;
    return;
  }
  if (state.quote !== null) {
    if (state.escape) {
      state.escape = false;
      return;
    }
    if (current === "\\") {
      state.escape = true;
      return;
    }
    if (current === state.quote) state.quote = null;
    return;
  }
  if (current === "/" && next === "/") {
    state.lineComment = true;
    return;
  }
  if (current === "/" && next === "*") {
    state.blockComment = true;
    return;
  }
  if (current === "'" || current === '"' || current === "`") {
    state.quote = current;
    return;
  }
  if (current === "{") state.brace += 1;
  else if (current === "}") state.brace = Math.max(0, state.brace - 1);
  else if (current === "(") state.paren += 1;
  else if (current === ")") state.paren = Math.max(0, state.paren - 1);
  else if (current === "[") state.bracket += 1;
  else if (current === "]") state.bracket = Math.max(0, state.bracket - 1);
};

const interestingString = (value: string): boolean => {
  if (value.length < 2 || value.length > 180) return false;
  if (/^https?:\/\//u.test(value)) return true;
  if (value.includes("/api/") || value.includes("/v1/")) return true;
  return /^\/[A-Za-z0-9_.:~/-]+$/u.test(value) && /[A-Za-z]/u.test(value);
};

const quotedStrings = (source: string): string[] => {
  const found: string[] = [];
  const pattern = /["'`](\/[^"'`\n]{1,160}|https?:\/\/[^"'`\s]{1,160})["'`]/gu;
  for (const match of source.matchAll(pattern)) {
    const value = match[1];
    if (value !== undefined && interestingString(value)) found.push(value);
  }
  return found;
};

const walkStrings = (file: ParsedJavaScriptSource, into: Set<string>): number => {
  let visited = 0;
  let stop = false;
  traverseJavaScriptAst(file, {
    enter: (node) => {
      if (stop) return;
      visited += 1;
      if (visited > NODE_BUDGET) {
        stop = true;
        return;
      }
      if (node.type === "StringLiteral" && interestingString(node.value)) {
        into.add(node.value);
      }
      if (node.type === "TemplateLiteral") {
        for (const quasi of node.quasis) {
          const cooked = quasi.value.cooked ?? "";
          if (interestingString(cooked)) into.add(cooked);
        }
      }
    },
  });
  return visited;
};

const moduleSpecifiers = (file: ParsedJavaScriptSource): string[] => {
  const names: string[] = [];
  traverseJavaScriptAst(file, {
    enter: (node) => {
      if (
        (node.type === "ImportDeclaration" ||
          node.type === "ExportAllDeclaration" ||
          (node.type === "ExportNamedDeclaration" && node.source !== null)) &&
        node.source?.type === "StringLiteral"
      ) {
        names.push(node.source.value);
      }
    },
  });
  return names;
};

const fingerprintsOf = (source: string): string[] => {
  const sample = source.length > 250_000 ? source.slice(0, 200_000) + source.slice(-40_000) : source;
  const marks: Array<[string, string]> = [
    ["vite", "__vite"],
    ["vite", "import.meta"],
    ["webpack", "__webpack_require__"],
    ["webpack", "webpackJsonp"],
    ["rollup", "__rollup"],
  ];
  return [...new Set(marks.filter(([, needle]) => sample.includes(needle)).map(([name]) => name))];
};

const sourceMapsOf = (source: string): string[] => {
  const found = new Set<string>();
  for (const match of source.matchAll(/sourceMappingURL=(\S+)/gu)) {
    const url = match[1];
    if (url !== undefined) found.add(url);
  }
  return [...found];
};

const sha256 = (value: string): string => createHash("sha256").update(value).digest("hex");

const evidenceFor = (
  operation: string,
  digest: string,
  location:
    | { kind: "artifact-path"; path: string }
    | { kind: "file-offset-range"; start: number; end: number },
) => ({
  authority: "ast-static-analysis" as const,
  state: "observed" as const,
  confidence: "high" as const,
  artifact: {
    available: true as const,
    artifact_id: `art_${digest}`,
    sha256: digest,
  },
  location: {
    available: true as const,
    value: location,
  },
  extractor: {
    name: "rea-fleet-static",
    version: "1",
    operation,
    executable_sha256: null,
  },
  coverage: completeApplicationCoverage(),
  limitations: ["chunked-parse"],
  evidence_ids: [] as string[],
});

const buildGraph = (
  source: string,
  path: string,
  endpoints: readonly string[],
  limitations: readonly string[],
): JavaScriptApplicationGraph => {
  const digest = sha256(source);
  const asset = createJavaScriptApplicationNode({
    kind: "javascript-asset",
    identity: {
      strategy: "canonical-path",
      stability: "artifact-version",
      artifact_sha256: digest,
      path,
    },
    observations: [
      {
        label: path,
        properties: { bytes: source.length, endpoints: endpoints.length },
        evidence: evidenceFor("parse", digest, {
          kind: "artifact-path",
          path,
        }),
      },
    ],
  });
  const endpointNodes = endpoints.slice(0, 40).map((endpoint) => {
    const endpointDigest = sha256(endpoint);
    return createJavaScriptApplicationNode({
      kind: "endpoint",
      identity: {
        strategy: "content-digest",
        stability: "global-exact",
        sha256: endpointDigest,
      },
      observations: [
        {
          label: endpoint,
          properties: { path: endpoint },
          evidence: evidenceFor("extract-endpoint", endpointDigest, {
            kind: "file-offset-range",
            start: 0,
            end: endpoint.length,
          }),
        },
      ],
    });
  });
  return createJavaScriptApplicationGraph({
    schema: "JavaScriptApplicationGraph",
    root_node_ids: [asset.node_id],
    nodes: [asset, ...endpointNodes],
    edges: [],
    coverage: completeApplicationCoverage(),
    limitations: limitations.length > 0 ? [...limitations] : ["none"],
  });
};

/**
 * Parse one production bundle in bounded chunks, walk each AST, and extract
 * the strings, modules, and fingerprints RE needs. A chunk that will not
 * parse degrades to quoted-string extraction and is counted as a failure.
 */
export const analyzeFleetStaticSource = (
  source: string,
  sourcePath = "bundle.js",
): FleetStaticResult => {
  const chunks = chunkJavaScriptSource(source);
  const endpoints = new Set<string>();
  const modules = new Set<string>();
  let visited = 0;
  let failures = 0;
  let parsed = 0;
  const limitations = new Set<string>();

  for (const chunk of chunks) {
    const file = parseJavaScriptSource(chunk.text, sourcePath);
    if (file === null) {
      failures += 1;
      limitations.add("string-fallback");
      for (const value of quotedStrings(chunk.text)) endpoints.add(value);
      continue;
    }
    parsed += 1;
    const seen = walkStrings(file, endpoints);
    visited += seen;
    if (seen > NODE_BUDGET) limitations.add("node-budget");
    for (const specifier of moduleSpecifiers(file)) modules.add(specifier);
  }

  const capped = [...endpoints].sort().slice(0, MAX_STRINGS);
  const limitationList = [...limitations].sort();
  return {
    schema: "rea-fleet-static",
    statistics: {
      parsed_javascript_files: parsed > 0 ? 1 : 0,
      visited_ast_nodes: visited,
      parse_failures: failures,
      chunks: chunks.length,
      routes: capped.length,
    },
    endpoints: capped,
    modules: [...modules].sort(),
    fingerprints: fingerprintsOf(source),
    source_maps: sourceMapsOf(source),
    limitations: limitationList,
    graph: buildGraph(source, sourcePath, capped, limitationList),
  };
};
