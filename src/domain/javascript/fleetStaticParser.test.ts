import { describe, expect, it } from "vitest";

import {
  analyzeFleetStaticSource,
  chunkJavaScriptSource,
} from "./fleetStaticParser.js";

describe("fleet static parser core", () => {
  it("walks an unminified module and extracts an endpoint literal", () => {
    const source = [
      'import router from "./router.js";',
      'const home = "/api/agents";',
      "export const boot = () => router.push(home);",
      "//# sourceMappingURL=app.js.map",
    ].join("\n");
    const result = analyzeFleetStaticSource(source, "app.js");
    expect(result.statistics.parsed_javascript_files).toBe(1);
    expect(result.statistics.visited_ast_nodes).toBeGreaterThan(0);
    expect(result.statistics.parse_failures).toBe(0);
    expect(result.endpoints).toContain("/api/agents");
    expect(result.modules).toContain("./router.js");
    expect(result.source_maps).toContain("app.js.map");
    expect(result.graph.schema).toBe("JavaScriptApplicationGraph");
    expect(result.graph.nodes.some((node) => node.kind === "endpoint")).toBe(true);
  });

  it("chunks a large minified bundle and still finds a late route", () => {
    const filler = Array.from({ length: 8_000 }, (_, index) => `function f${index}(){return ${index};}`).join("");
    const source = `${filler}const route="/campaigns/start";export default route;`;
    expect(source.length).toBeGreaterThan(160_000);
    expect(chunkJavaScriptSource(source).length).toBeGreaterThan(1);
    const result = analyzeFleetStaticSource(source, "index-min.js");
    expect(result.statistics.parsed_javascript_files).toBe(1);
    expect(result.statistics.visited_ast_nodes).toBeGreaterThan(0);
    expect(result.endpoints).toContain("/campaigns/start");
    expect(result.statistics.chunks).toBeGreaterThan(1);
  });

  it("degrades a broken chunk to string extraction instead of a silent zero", () => {
    const source = 'function ( { const path = "/api/fallback";';
    const result = analyzeFleetStaticSource(source, "broken.js");
    expect(result.statistics.parse_failures).toBeGreaterThan(0);
    expect(result.limitations).toContain("string-fallback");
    expect(result.endpoints).toContain("/api/fallback");
  });

  it("records webpack and vite fingerprints without retaining the bundle", () => {
    const source = 'const req = __webpack_require__(1); const hot = import.meta.hot; const url = "/api/flags";';
    const result = analyzeFleetStaticSource(source);
    expect(result.fingerprints).toEqual(expect.arrayContaining(["vite", "webpack"]));
    expect(result.endpoints).toContain("/api/flags");
  });
});
