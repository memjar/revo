import { execFileSync } from "node:child_process";

export interface RizinInstallationInspection {
  readonly installed: boolean;
  readonly version: string | null;
  readonly path: string | null;
  readonly hasRzGhidra: boolean;
  readonly hasRzBin: boolean;
}

export const inspectRizinInstallation = (): RizinInstallationInspection => {
  try {
    const version =
      execFileSync("rizin", ["-v"], {
        timeout: 5000,
        encoding: "utf-8",
      })
        .trim()
        .split("\n")[0] ?? null;

    let path: string | null = null;
    try {
      path = execFileSync("which", ["rizin"], {
        timeout: 3000,
        encoding: "utf-8",
      }).trim();
    } catch {}

    let hasRzGhidra = false;
    try {
      const plugins = execFileSync("rizin", ["-qc", "Lc"], {
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

export const rizinInstallationDiagnostics = (
  inspection: RizinInstallationInspection,
): Record<string, unknown> => ({
  installed: inspection.installed,
  version: inspection.version,
  path: inspection.path,
  rz_ghidra: inspection.hasRzGhidra,
  rz_bin: inspection.hasRzBin,
});
