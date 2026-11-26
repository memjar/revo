export interface SecretMatch {
  type: string;
  line: number;
  value_preview: string;
  confidence: number;
}

export interface ScrubReport {
  secrets_found: SecretMatch[];
  clean: boolean;
  scrubbed_output: string;
}

const PATTERNS: Array<{ type: string; regex: RegExp; confidence: number }> = [
  { type: "aws_access_key", regex: /AKIA[0-9A-Z]{16}/g, confidence: 0.95 },
  {
    type: "aws_secret_key",
    regex: /(?:aws_secret_access_key|AWS_SECRET)["\s:=]+([A-Za-z0-9/+=]{40})/g,
    confidence: 0.9,
  },
  {
    type: "github_token",
    regex: /gh[ps]_[A-Za-z0-9_]{36,}/g,
    confidence: 0.95,
  },
  {
    type: "github_fine_grained",
    regex: /github_pat_[A-Za-z0-9_]{22,}/g,
    confidence: 0.95,
  },
  { type: "slack_token", regex: /xox[bprs]-[A-Za-z0-9-]+/g, confidence: 0.9 },
  {
    type: "stripe_key",
    regex: /[sr]k_(test|live)_[A-Za-z0-9]{20,}/g,
    confidence: 0.95,
  },
  {
    type: "private_key",
    regex: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
    confidence: 0.99,
  },
  {
    type: "jwt",
    regex: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    confidence: 0.85,
  },
  {
    type: "generic_api_key",
    regex:
      /(?:api[_-]?key|apikey|api[_-]?secret)["\s:=]+["']?([A-Za-z0-9_-]{20,})["']?/gi,
    confidence: 0.7,
  },
  {
    type: "generic_password",
    regex: /(?:password|passwd|pwd)["\s:=]+["']?([^\s"']{8,})["']?/gi,
    confidence: 0.6,
  },
  {
    type: "bearer_token",
    regex: /Bearer\s+[A-Za-z0-9._~+/=-]{20,}/g,
    confidence: 0.8,
  },
  {
    type: "ssh_key_fingerprint",
    regex: /SHA256:[A-Za-z0-9+/]{43}=/g,
    confidence: 0.85,
  },
  {
    type: "hex_secret_32",
    regex: /(?:secret|token|key)["\s:=]+["']?([a-f0-9]{32,64})["']?/gi,
    confidence: 0.65,
  },
];

export function scrubSecrets(content: string): ScrubReport {
  const matches: SecretMatch[] = [];
  const lines = content.split("\n");
  let scrubbed = content;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? "";
    for (const { type, regex, confidence } of PATTERNS) {
      regex.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = regex.exec(line)) !== null) {
        const val = match[1] ?? match[0];
        matches.push({
          type,
          line: i + 1,
          value_preview: val.slice(0, 6) + "***",
          confidence,
        });
        scrubbed = scrubbed.replace(match[0], `[REDACTED:${type}]`);
      }
    }
  }

  return {
    secrets_found: matches,
    clean: matches.length === 0,
    scrubbed_output: scrubbed,
  };
}

export function isClean(content: string): boolean {
  return scrubSecrets(content).clean;
}
