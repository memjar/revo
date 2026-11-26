#!/usr/bin/env node
import { createInterface } from "node:readline";
import { CapstoneDisassembler } from "./capstone/CapstoneDisassembler.js";
import { CapstoneBinaryParser } from "./capstone/CapstoneBinaryParser.js";
import { inspectCapstoneInstallation } from "./capstone/CapstoneInstallation.js";
import { inspectAxeInstallation } from "./axe/AxeInstallation.js";
import { createCounterDetectionKit } from "./composition/counterDetection.js";

interface RpcRequest {
  method: string;
  params?: Record<string, unknown>;
  id: number | string;
}

interface RpcResponse {
  result?: unknown;
  error?: { code: number; message: string };
  id: number | string;
}

const kit = createCounterDetectionKit();

function respond(id: number | string, result: unknown): void {
  const r: RpcResponse = { result, id };
  process.stdout.write(JSON.stringify(r) + "\n");
}

function respondError(id: number | string, message: string): void {
  const r: RpcResponse = { error: { code: -1, message }, id };
  process.stdout.write(JSON.stringify(r) + "\n");
}

async function dispatch(req: RpcRequest): Promise<void> {
  const { method, params = {}, id } = req;
  try {
    switch (method) {
      case "revo.ping":
        respond(id, { status: "ok", version: "0.1.0" });
        break;

      case "revo.providers": {
        const axeInst = inspectAxeInstallation();
        const cap = inspectCapstoneInstallation();
        respond(id, {
          axe: {
            available: axeInst.installed,
            path: axeInst.path,
            version: axeInst.version,
          },
          capstone: {
            available: cap.hasCapstone,
            version: cap.capstoneVersion,
            lief: cap.hasLief,
          },
        });
        break;
      }

      case "revo.disassemble": {
        const hex = String(params.hex ?? "");
        const arch = String(
          params.arch ?? "x64",
        ) as import("./capstone/CapstoneDisassembler.js").CapstoneArch;
        const offset = String(params.offset ?? "0x0");
        const dis = new CapstoneDisassembler(arch);
        respond(id, { assembly: dis.disassemble(hex, offset) });
        break;
      }

      case "revo.parse_binary": {
        const path = String(params.path ?? "");
        if (!path) {
          respondError(id, "path required");
          break;
        }
        const parser = new CapstoneBinaryParser(path);
        const info = parser.parse();
        respond(id, info);
        break;
      }

      case "revo.scrub_secrets": {
        const content = String(params.content ?? "");
        const report = kit.secretsScrub.scrubSecrets(content);
        respond(id, report);
        break;
      }

      case "revo.detect_decoys": {
        const targetPath = String(params.path ?? "");
        if (!targetPath) {
          respondError(id, "path required");
          break;
        }
        const report = kit.counterRe.detectDecoys(targetPath);
        respond(id, report);
        break;
      }

      case "revo.fingerprint": {
        const profile = kit.fingerprintEvade.generateProfile();
        respond(id, profile);
        break;
      }

      case "revo.strip_fingerprints": {
        const content = String(params.content ?? "");
        const stripped = kit.fingerprintEvade.stripToolFingerprints(content);
        respond(id, { content: stripped });
        break;
      }

      default:
        respondError(id, `unknown method: ${method}`);
    }
  } catch (e: any) {
    respondError(id, e?.message ?? "internal error");
  }
}

const rl = createInterface({ input: process.stdin });
rl.on("line", (line) => {
  if (!line.trim()) return;
  try {
    const req = JSON.parse(line) as RpcRequest;
    if (!req.method || req.id === undefined) {
      respondError(req.id ?? 0, "invalid request: method and id required");
      return;
    }
    void dispatch(req);
  } catch {
    process.stdout.write(
      JSON.stringify({
        error: { code: -32700, message: "parse error" },
        id: null,
      }) + "\n",
    );
  }
});
rl.on("close", () => process.exit(0));
