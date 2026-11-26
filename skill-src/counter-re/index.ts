import { execFileSync } from "node:child_process";
import { readFileSync, statSync } from "node:fs";
import { createHash } from "node:crypto";

export interface DecoySignal {
  type:
    | "honeypot_string"
    | "canary_token"
    | "resource_trap"
    | "fake_symbol"
    | "entropy_anomaly";
  location: string;
  confidence: number;
  description: string;
}

export interface CounterReReport {
  target: string;
  decoys_detected: DecoySignal[];
  safe_regions: string[];
  resource_budget: { estimated_tokens: number; trap_ratio: number };
  recommendation: "proceed" | "cautious" | "abort";
}

const CANARY_PATTERNS = [
  /canarytokens?\.(com|net|org)/i,
  /thinkst\.com/i,
  /[a-f0-9]{32}\.burpcollaborator\./i,
  /[a-f0-9]{32}\.(oast|interact)\./i,
  /webhook\.site/i,
  /requestbin\.(com|net)/i,
  /pipedream\.net/i,
  /ngrok\.(io|app)/i,
];

const HONEYPOT_NAMES = new Set([
  "password_backup",
  "admin_credentials",
  "secret_key_prod",
  "aws_access_key",
  "private_key_rsa",
  "database_dump",
  "ssh_keys_backup",
  "vault_token",
  "master_password",
  ".env.production",
  "credentials.json",
  "secrets.yaml",
]);

export function detectDecoys(targetPath: string): CounterReReport {
  const signals: DecoySignal[] = [];
  const safeRegions: string[] = [];
  let totalSize = 0;
  let trapSize = 0;

  try {
    const stat = statSync(targetPath);
    totalSize = stat.size;
    const content = readFileSync(targetPath, { encoding: "utf-8", flag: "r" });
    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] ?? "";
      for (const pattern of CANARY_PATTERNS) {
        if (pattern.test(line)) {
          signals.push({
            type: "canary_token",
            location: `line:${i + 1}`,
            confidence: 0.9,
            description: `Canary token pattern detected: ${pattern.source}`,
          });
          trapSize += line.length;
        }
      }

      const entropy = shannonEntropy(line);
      if (line.length > 40 && entropy > 5.5 && entropy < 6.5) {
        const looksLikeKey = /^[A-Za-z0-9+/=_-]{40,}$/.test(line.trim());
        if (looksLikeKey) {
          signals.push({
            type: "honeypot_string",
            location: `line:${i + 1}`,
            confidence: 0.7,
            description: "High-entropy string resembling planted credential",
          });
          trapSize += line.length;
        }
      }
    }

    for (const name of HONEYPOT_NAMES) {
      if (content.includes(name)) {
        signals.push({
          type: "honeypot_string",
          location: `content match: ${name}`,
          confidence: 0.6,
          description: `Common honeypot filename/variable: ${name}`,
        });
      }
    }
  } catch {}

  const trapRatio = totalSize > 0 ? trapSize / totalSize : 0;
  let recommendation: "proceed" | "cautious" | "abort" = "proceed";
  if (signals.length > 5 || trapRatio > 0.3) recommendation = "abort";
  else if (signals.length > 2 || trapRatio > 0.1) recommendation = "cautious";

  return {
    target: targetPath,
    decoys_detected: signals,
    safe_regions: safeRegions,
    resource_budget: { estimated_tokens: totalSize * 2, trap_ratio: trapRatio },
    recommendation,
  };
}

function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const c of s) freq.set(c, (freq.get(c) ?? 0) + 1);
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / s.length;
    if (p > 0) entropy -= p * Math.log2(p);
  }
  return entropy;
}

export function hashFingerprint(data: Buffer | string): string {
  return createHash("sha256").update(data).digest("hex").slice(0, 16);
}
