import { execFileSync } from "node:child_process";
import type { JsonValue } from "../domain/jsonValue.js";

export interface AxeInstallationInspection {
  readonly installed: boolean;
  readonly version: string | null;
  readonly path: string | null;
  readonly hasRzGhidra: boolean;
  readonly hasRzBin: boolean;
}

export const inspectAxeInstallation = (): AxeInstallationInspection => {
  try {
    const version =
      execFileSync("axe", ["-v"], {
        timeout: 5000,
        encoding: "utf-8",
      })
        .trim()
        .split("\n")[0] ?? null;

    let path: string | null = null;
    try {
      path = execFileSync("which", ["axe"], {
        timeout: 3000,
        encoding: "utf-8",
      }).trim();
    } catch {}

    let hasRzGhidra = false;
    try {
      const plugins = execFileSync("axe", ["-qc", "Lc"], {
        timeout: 5000,
        encoding: "utf-8",
      });
      hasRzGhidra = plugins.includes("ghidra");
    } catch {}

    let hasRzBin = false;
    try {
      execFileSync("rz-bin", ["-v"], { timeout: 3000, encoding: "utf-8" });
      hasRzBin = true;
    } catch {}

    return { installed: true, version, path, hasRzGhidra, hasRzBin };
  } catch {
    return {
      installed: false,
      version: null,
      path: null,
      hasRzGhidra: false,
      hasRzBin: false,
    };
  }
};

export const axeInstallationDiagnostics = (
  inspection: AxeInstallationInspection,
): Record<string, JsonValue> => ({
  installed: inspection.installed,
  version: inspection.version,
  path: inspection.path,
  rz_ghidra: inspection.hasRzGhidra,
  rz_bin: inspection.hasRzBin,
});
