import { spawn, type ChildProcess } from "node:child_process";
import type { JsonValue } from "../domain/jsonValue.js";

export class AxeClient {
  #process: ChildProcess | null = null;
  #buffer = "";

  constructor(
    private readonly targetPath: string,
    private readonly args: readonly string[] = [],
  ) {}

  async open(): Promise<void> {
    this.#process = spawn("axe", ["-q0", ...this.args, this.targetPath], {
      stdio: ["pipe", "pipe", "pipe"],
    });
    await new Promise<void>((resolve, reject) => {
      const onData = () => {
        this.#process?.stdout?.removeListener("data", onData);
        resolve();
      };
      this.#process?.stdout?.on("data", onData);
      this.#process?.on("error", reject);
      setTimeout(() => resolve(), 3000);
    });
  }

  async command(cmd: string): Promise<string> {
    if (!this.#process?.stdin || !this.#process?.stdout)
      throw new Error("Axe process not running");
    return new Promise((resolve, reject) => {
      let result = "";
      const onData = (chunk: Buffer) => {
        result += chunk.toString();
        if (result.includes("\0")) {
          this.#process?.stdout?.removeListener("data", onData);
          resolve(result.replace(/\0/g, "").trim());
        }
      };
      this.#process!.stdout!.on("data", onData);
      this.#process!.stdin!.write(cmd + "\n");
      setTimeout(() => {
        this.#process?.stdout?.removeListener("data", onData);
        resolve(result.trim());
      }, 30000);
    });
  }

  async commandJson(cmd: string): Promise<JsonValue> {
    const raw = await this.command(cmd);
    try {
      return JSON.parse(raw);
    } catch {
      return raw;
    }
  }

  async analyze(): Promise<void> {
    await this.command("aaa");
  }

  async listFunctions(): Promise<JsonValue> {
    return this.commandJson("aflj");
  }

  async listImports(): Promise<JsonValue> {
    return this.commandJson("iij");
  }

  async listExports(): Promise<JsonValue> {
    return this.commandJson("iEj");
  }

  async listStrings(): Promise<JsonValue> {
    return this.commandJson("izj");
  }

  async listSections(): Promise<JsonValue> {
    return this.commandJson("iSj");
  }

  async listSegments(): Promise<JsonValue> {
    return this.commandJson("iSSj");
  }

  async listSymbols(): Promise<JsonValue> {
    return this.commandJson("isj");
  }

  async disassembleFunction(name: string): Promise<string> {
    return this.command(`s ${name}; pdf`);
  }

  async decompileFunction(name: string): Promise<string> {
    return this.command(`s ${name}; pdg`);
  }

  async getXrefs(address: string): Promise<JsonValue> {
    return this.commandJson(`axtj ${address}`);
  }

  async readBytes(address: string, length: number): Promise<string> {
    return this.command(`px ${length} @ ${address}`);
  }

  async searchString(pattern: string): Promise<JsonValue> {
    return this.commandJson(`/j ${pattern}`);
  }

  async info(): Promise<JsonValue> {
    return this.commandJson("ij");
  }

  close(): void {
    if (this.#process) {
      this.#process.stdin?.end();
      this.#process.kill();
      this.#process = null;
    }
  }
}
