import { execFileSync } from "node:child_process";
import type { JsonValue } from "../domain/jsonValue.js";

export interface CapstoneInstallationInspection {
  readonly hasCapstone: boolean;
  readonly capstoneVersion: string | null;
  readonly hasLief: boolean;
  readonly hasRetdec: boolean;
  readonly retdecVersion: string | null;
}

export const inspectCapstoneInstallation =
  (): CapstoneInstallationInspection => {
    let hasCapstone = false;
    let capstoneVersion: string | null = null;
    try {
      capstoneVersion =
        execFileSync("cstool", ["-v"], {
          timeout: 5000,
          encoding: "utf-8",
        })
          .trim()
          .split("\n")[0] ?? null;
      hasCapstone = true;
    } catch {
      try {
        execFileSync(
          "python3",
          ["-c", "import capstone; print(capstone.cs_version())"],
          {
            timeout: 5000,
            encoding: "utf-8",
          },
        );
        hasCapstone = true;
        capstoneVersion = "python-binding";
      } catch {}
    }

    let hasLief = false;
    try {
      execFileSync("python3", ["-c", "import lief; print(lief.__version__)"], {
        timeout: 5000,
        encoding: "utf-8",
      });
      hasLief = true;
    } catch {}

    let hasRetdec = false;
    let retdecVersion: string | null = null;
    try {
      retdecVersion = execFileSync("retdec-decompiler", ["--version"], {
        timeout: 5000,
        encoding: "utf-8",
      }).trim();
      hasRetdec = true;
    } catch {}

    return { hasCapstone, capstoneVersion, hasLief, hasRetdec, retdecVersion };
  };

export const capstoneInstallationDiagnostics = (
  i: CapstoneInstallationInspection,
): Record<string, JsonValue> => ({
  capstone: i.hasCapstone,
  capstone_version: i.capstoneVersion,
  lief: i.hasLief,
  retdec: i.hasRetdec,
  retdec_version: i.retdecVersion,
});
