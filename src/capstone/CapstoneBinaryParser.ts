import { execFileSync } from "node:child_process";
import type { JsonValue } from "../domain/jsonValue.js";

export class CapstoneBinaryParser {
  constructor(private readonly targetPath: string) {}

  parse(): JsonValue {
    try {
      const script = `
import lief, json, sys
b = lief.parse(sys.argv[1])
if b is None: print("null"); sys.exit(0)
out = {"format": str(b.format).split(".")[-1], "sections": [], "segments": [], "imports": [], "exports": [], "symbols": [], "strings": []}
for s in b.sections:
    out["sections"].append({"name": s.name, "size": s.size, "virtual_address": hex(s.virtual_address), "entropy": round(s.entropy, 4)})
if hasattr(b, "segments"):
    for s in b.segments:
        out["segments"].append({"type": str(s.type).split(".")[-1], "virtual_address": hex(s.virtual_address), "virtual_size": s.virtual_size, "file_offset": s.file_offset, "file_size": s.physical_size})
if hasattr(b, "imported_functions"):
    for f in b.imported_functions: out["imports"].append(f.name)
if hasattr(b, "exported_functions"):
    for f in b.exported_functions: out["exports"].append(f.name)
for s in b.symbols:
    out["symbols"].append({"name": s.name, "value": hex(s.value) if s.value else "0x0"})
if hasattr(b, "strings"):
    for s in list(b.strings)[:500]: out["strings"].append(s)
print(json.dumps(out))
`;
      const raw = execFileSync("python3", ["-c", script, this.targetPath], {
        timeout: 30000,
        encoding: "utf-8",
      });
      return JSON.parse(raw.trim());
    } catch (e: any) {
      return { error: e?.message ?? "LIEF parse failed" };
    }
  }

  sections(): JsonValue {
    const parsed = this.parse();
    return typeof parsed === "object" && parsed !== null && "sections" in parsed
      ? (parsed as any).sections
      : [];
  }

  segments(): JsonValue {
    const parsed = this.parse();
    return typeof parsed === "object" && parsed !== null && "segments" in parsed
      ? (parsed as any).segments
      : [];
  }

  imports(): JsonValue {
    const parsed = this.parse();
    return typeof parsed === "object" && parsed !== null && "imports" in parsed
      ? (parsed as any).imports
      : [];
  }

  exports(): JsonValue {
    const parsed = this.parse();
    return typeof parsed === "object" && parsed !== null && "exports" in parsed
      ? (parsed as any).exports
      : [];
  }
}
