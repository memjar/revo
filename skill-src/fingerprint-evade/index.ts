import { createHash, randomBytes } from "node:crypto";

export interface FingerprintProfile {
  user_agent: string;
  timing_jitter_ms: number;
  request_pattern: "sequential" | "random" | "burst";
  header_order: string[];
}

const USER_AGENTS = [
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
];

const HEADER_ORDERS = [
  [
    "Host",
    "User-Agent",
    "Accept",
    "Accept-Language",
    "Accept-Encoding",
    "Connection",
  ],
  [
    "Host",
    "Connection",
    "Accept",
    "User-Agent",
    "Accept-Encoding",
    "Accept-Language",
  ],
  [
    "Host",
    "Accept",
    "User-Agent",
    "Accept-Language",
    "Connection",
    "Accept-Encoding",
  ],
];

export function generateProfile(): FingerprintProfile {
  const idx = Math.floor(Math.random() * USER_AGENTS.length);
  const hIdx = Math.floor(Math.random() * HEADER_ORDERS.length);
  return {
    user_agent: USER_AGENTS[idx]!,
    timing_jitter_ms: 200 + Math.floor(Math.random() * 2800),
    request_pattern: (["sequential", "random", "burst"] as const)[
      Math.floor(Math.random() * 3)
    ]!,
    header_order: HEADER_ORDERS[hIdx]!,
  };
}

export function jitteredDelay(baseMs: number): Promise<void> {
  const jitter = baseMs * (0.5 + Math.random());
  return new Promise((resolve) => setTimeout(resolve, jitter));
}

export function rotateIdentity(): { session_id: string; fingerprint: string } {
  const raw = randomBytes(16);
  return {
    session_id: raw.toString("hex"),
    fingerprint: createHash("sha256").update(raw).digest("hex").slice(0, 12),
  };
}

export function stripToolFingerprints(output: string): string {
  return output
    .replace(/claude[_-]?(code|session|agent)/gi, "")
    .replace(/anthropic/gi, "")
    .replace(/Co-Authored-By:.*$/gm, "")
    .replace(/Claude-Session:.*$/gm, "")
    .replace(/AI-Generated/gi, "")
    .replace(/\b(sk-ant-[a-zA-Z0-9_-]+)\b/g, "[REDACTED]")
    .replace(/\b(AKIA[0-9A-Z]{16})\b/g, "[REDACTED]")
    .trim();
}

export function obfuscateTimestamps(content: string): string {
  return content.replace(
    /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z?/g,
    () => {
      const d = new Date(Date.now() - Math.floor(Math.random() * 86400000));
      return d.toISOString();
    },
  );
}
