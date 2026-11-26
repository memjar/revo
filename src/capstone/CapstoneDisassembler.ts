import { execFileSync } from "node:child_process";

export type CapstoneArch =
  | "x86"
  | "x64"
  | "arm"
  | "arm64"
  | "mips"
  | "ppc"
  | "riscv";

const CSTOOL_ARCH_MAP: Record<CapstoneArch, string> = {
  x86: "x32",
  x64: "x64",
  arm: "arm",
  arm64: "arm64",
  mips: "mips",
  ppc: "ppc",
  riscv: "riscv32",
};

export class CapstoneDisassembler {
  constructor(private readonly arch: CapstoneArch = "x64") {}

  disassemble(hexBytes: string, offset = "0x0"): string {
    try {
      const mode = CSTOOL_ARCH_MAP[this.arch] ?? "x64";
      return execFileSync("cstool", [mode, hexBytes, offset], {
        timeout: 10000,
        encoding: "utf-8",
      }).trim();
    } catch {
      return this.#fallbackPython(hexBytes, offset);
    }
  }

  #fallbackPython(hexBytes: string, offset: string): string {
    const script = `
import capstone, sys
arch_map = {"x86": (capstone.CS_ARCH_X86, capstone.CS_MODE_32), "x64": (capstone.CS_ARCH_X86, capstone.CS_MODE_64), "arm": (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM), "arm64": (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM), "mips": (capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32)}
a, m = arch_map.get(sys.argv[3], (capstone.CS_ARCH_X86, capstone.CS_MODE_64))
md = capstone.Cs(a, m)
code = bytes.fromhex(sys.argv[1])
for i in md.disasm(code, int(sys.argv[2], 16)):
    print(f"0x{i.address:x}:\\t{i.mnemonic}\\t{i.op_str}")
`;
    try {
      return execFileSync(
        "python3",
        ["-c", script, hexBytes, offset, this.arch],
        {
          timeout: 10000,
          encoding: "utf-8",
        },
      ).trim();
    } catch (e: any) {
      return `disassembly failed: ${e?.message ?? "unknown"}`;
    }
  }
}
