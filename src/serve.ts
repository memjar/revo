import {
  createServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import { spawn } from "node:child_process";
import { randomUUID, timingSafeEqual } from "node:crypto";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { writeFile, mkdir, unlink } from "node:fs/promises";
import { tmpdir } from "node:os";

interface Job {
  id: string;
  status: "pending" | "running" | "done" | "error";
  command: string;
  result?: unknown;
  error?: string;
  started: number;
  finished?: number;
}

const jobs = new Map<string, Job>();
const UPLOAD_DIR = resolve(tmpdir(), "revo-uploads");

function parseArgs(argv: string[]): { port: number; host: string } {
  let port = 8860;
  let host = "127.0.0.1";
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--port" && argv[i + 1]) port = parseInt(argv[i + 1]!, 10);
    if (argv[i] === "--host" && argv[i + 1]) host = argv[i + 1]!;
  }
  return { port, host };
}

function checkAuth(req: IncomingMessage): boolean {
  const fleetKey = process.env.AXE_FLEET_KEY;
  if (!fleetKey) return true;
  const provided =
    (req.headers["x-axe-key"] as string) ||
    (req.headers["authorization"] as string)?.replace("Bearer ", "");
  if (!provided) return false;
  if (provided.length !== fleetKey.length) return false;
  return timingSafeEqual(Buffer.from(provided), Buffer.from(fleetKey));
}

function json(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(payload),
  });
  res.end(payload);
}

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString();
}

function runCommand(
  command: string,
  args: string[] = [],
  timeout = 120_000,
): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const bin = process.argv[1]
      ? dirname(process.argv[1]) + "/revo.mjs"
      : "revo";
    const child = spawn("node", [bin, command, ...args, "--format", "json"], {
      env: process.env,
      timeout,
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d: Buffer) => (stdout += d));
    child.stderr.on("data", (d: Buffer) => (stderr += d));
    child.on("close", (code) => {
      if (code !== 0)
        return reject({ code, stderr: stderr.trim(), stdout: stdout.trim() });
      try {
        resolve(JSON.parse(stdout));
      } catch {
        resolve({ raw: stdout.trim() });
      }
    });
    child.on("error", reject);
  });
}

async function handleRequest(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  const url = new URL(req.url || "/", `http://${req.headers.host}`);
  const path = url.pathname;
  const method = req.method || "GET";

  if (path === "/health" && method === "GET") {
    json(res, 200, { service: "revo", status: "ok", version: "0.1.0" });
    return;
  }

  if (!checkAuth(req)) {
    json(res, 401, { error: "unauthorized" });
    return;
  }

  if (path === "/capabilities" && method === "GET") {
    try {
      const result = await runCommand("capabilities");
      json(res, 200, result);
    } catch (e: any) {
      json(res, 500, {
        error: "capabilities_failed",
        detail: e.stderr || String(e),
      });
    }
    return;
  }

  if (method === "POST") {
    if (
      path === "/upload" &&
      req.headers["content-type"]?.includes("application/octet-stream")
    ) {
      await mkdir(UPLOAD_DIR, { recursive: true });
      const filename = (req.headers["x-filename"] as string) || randomUUID();
      const dest = resolve(
        UPLOAD_DIR,
        filename.replace(/[^a-zA-Z0-9._-]/g, "_"),
      );
      const chunks: Buffer[] = [];
      for await (const chunk of req) chunks.push(chunk as Buffer);
      const data = Buffer.concat(chunks);
      await writeFile(dest, data);
      json(res, 200, { uploaded: dest, size: data.length });
      return;
    }

    let body: Record<string, unknown>;
    try {
      body = JSON.parse(await readBody(req));
    } catch {
      json(res, 400, { error: "invalid_json" });
      return;
    }

    const routes: Record<
      string,
      {
        command: string;
        requirePath?: boolean;
        argBuilder?: (b: Record<string, unknown>) => string[];
      }
    > = {
      "/inspect": { command: "inspect", requirePath: true },
      "/decompile": {
        command: "decompile",
        requirePath: true,
        argBuilder: (b) => {
          const a = [b.path as string];
          if (b.address) a.push(b.address as string);
          return a;
        },
      },
      "/function": {
        command: "function",
        requirePath: true,
        argBuilder: (b) => {
          const a = [b.path as string];
          if (b.address) a.push(b.address as string);
          return a;
        },
      },
      "/analyze": { command: "analyze", requirePath: true },
      "/analyze-js": {
        command: "analyze-javascript-application",
        requirePath: true,
      },
      "/inspect-binary-layout": {
        command: "inspect-binary-layout",
        requirePath: true,
      },
      "/extract-artifact": { command: "extract-artifact", requirePath: true },
      "/compare": {
        command: "compare",
        argBuilder: (b) => {
          if (!b.left || !b.right)
            throw new Error("left and right paths required");
          return [b.left as string, b.right as string];
        },
      },
    };

    const route = routes[path];
    if (route) {
      if (route.requirePath && !body.path) {
        json(res, 400, { error: "path required" });
        return;
      }
      try {
        const args = route.argBuilder
          ? route.argBuilder(body)
          : [body.path as string];
        const result = await runCommand(route.command, args);
        json(res, 200, result);
      } catch (e: any) {
        json(res, 500, {
          error: `${route.command}_failed`,
          detail: e.stderr || String(e),
        });
      }
      return;
    }

    if (path === "/run") {
      const { command, args: cmdArgs } = body as {
        command?: string;
        args?: string[];
      };
      if (!command) {
        json(res, 400, { error: "command required" });
        return;
      }
      try {
        const result = await runCommand(
          command as string,
          (cmdArgs || []) as string[],
        );
        json(res, 200, result);
      } catch (e: any) {
        json(res, 500, {
          error: "run_failed",
          command,
          detail: e.stderr || String(e),
        });
      }
      return;
    }

    if (path === "/jobs") {
      const { command, args: cmdArgs } = body as {
        command?: string;
        args?: string[];
      };
      if (!command) {
        json(res, 400, { error: "command required" });
        return;
      }
      const job: Job = {
        id: randomUUID(),
        status: "running",
        command: command as string,
        started: Date.now(),
      };
      jobs.set(job.id, job);
      runCommand(command as string, (cmdArgs || []) as string[], 600_000)
        .then((result) => {
          job.status = "done";
          job.result = result;
          job.finished = Date.now();
        })
        .catch((e: any) => {
          job.status = "error";
          job.error = e.stderr || String(e);
          job.finished = Date.now();
        });
      json(res, 202, { job_id: job.id, status: "running" });
      return;
    }
  }

  if (method === "GET") {
    const jobMatch = path.match(/^\/jobs\/([a-f0-9-]+)$/);
    if (jobMatch) {
      const job = jobs.get(jobMatch[1]!);
      if (!job) {
        json(res, 404, { error: "job_not_found" });
        return;
      }
      json(res, 200, job);
      return;
    }
  }

  json(res, 404, { error: "not_found", path });
}

export async function startApiServer(
  argv: string[],
  _opts: { packageRoot: string },
): Promise<void> {
  const { port, host } = parseArgs(argv);
  const server = createServer((req, res) => {
    handleRequest(req, res).catch((e) => {
      json(res, 500, { error: "internal", detail: String(e) });
    });
  });
  server.listen(port, host, () => {
    process.stdout.write(`revo api v0.1.0 listening on ${host}:${port}\n`);
    if (!process.env.AXE_FLEET_KEY)
      process.stderr.write("AXE_FLEET_KEY not set — running unauthenticated\n");
  });
}
