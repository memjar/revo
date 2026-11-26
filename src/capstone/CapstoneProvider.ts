import { snapshotEnvironment } from "../process/snapshotEnvironment.js";
import {
  createAnalysisExecution,
  type AnalysisClient,
  type AnalysisClientContext,
  type AnalysisProfileResolutionOptions,
  type AnalysisProviderCandidate,
  type AnalysisOperation,
  type CapabilityDescriptor,
  type ExecutionOptions,
  type ProviderAvailability,
  type ProviderIdentity,
  type ProviderTargetSupport,
} from "../application/AnalysisProvider.js";
import {
  createAnalysisProfile,
  type AnalysisProfileCommitment,
} from "../domain/analysisProfile.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import type { JsonValue } from "../domain/jsonValue.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { ok, err, type Result } from "../domain/result.js";
import type { AppConfig } from "../config/types.js";
import type { Logger } from "pino";
import { CapstoneBinaryParser } from "./CapstoneBinaryParser.js";
import { CapstoneDisassembler } from "./CapstoneDisassembler.js";
import {
  inspectCapstoneInstallation,
  capstoneInstallationDiagnostics,
  type CapstoneInstallationInspection,
} from "./CapstoneInstallation.js";
import {
  CAPABILITIES,
  CAPSTONE_PROVIDER_IDENTITY,
} from "./CapstoneProviderCapabilities.js";

export class CapstoneProvider implements AnalysisProviderCandidate {
  #installation: CapstoneInstallationInspection | undefined;
  private readonly environment: NodeJS.ProcessEnv;

  constructor(
    private readonly config: AppConfig,
    private readonly logger: Logger,
    environment: Readonly<NodeJS.ProcessEnv>,
  ) {
    this.environment = snapshotEnvironment(environment);
  }

  identity(): ProviderIdentity {
    return CAPSTONE_PROVIDER_IDENTITY;
  }

  capabilities(): readonly CapabilityDescriptor[] {
    return CAPABILITIES;
  }

  inspectAvailability(): ProviderAvailability {
    const i = this.#inspect();
    if (!i.hasCapstone && !i.hasLief)
      return {
        status: "unavailable",
        code: "executable_missing",
        reason:
          "Neither capstone nor LIEF found. Install: pip3 install capstone lief",
        diagnostics: capstoneInstallationDiagnostics(i),
      };
    return {
      status: "available",
      code: null,
      reason: null,
      diagnostics: capstoneInstallationDiagnostics(i),
    };
  }

  inspectTargetSupport(target: BinaryTarget): ProviderTargetSupport {
    if (target.kind !== "executable")
      return {
        status: "unsupported",
        code: "target_kind_unsupported",
        reason: `Capstone supports executables; got ${target.kind}`,
        diagnostics: {},
      };
    return { status: "supported", code: null, reason: null, diagnostics: {} };
  }

  async resolveAnalysisProfile(
    _target: BinaryTarget,
    _options?: AnalysisProfileResolutionOptions,
  ) {
    const i = this.#inspect();
    if (!i.hasCapstone && !i.hasLief) return ok({ profile: null });
    const profile = createAnalysisProfile(
      {
        ...CAPSTONE_PROVIDER_IDENTITY,
        version: i.capstoneVersion ?? "unknown",
      },
      {},
    );
    return ok({ profile });
  }

  createClient(
    target: BinaryTarget,
    profile?: AnalysisProfileCommitment,
    _context?: AnalysisClientContext,
  ): AnalysisClient {
    return new CapstoneAnalysisClient(target, profile, this.logger);
  }

  #inspect(): CapstoneInstallationInspection {
    if (!this.#installation) this.#installation = inspectCapstoneInstallation();
    return this.#installation;
  }
}

class CapstoneAnalysisClient implements AnalysisClient {
  #parser: CapstoneBinaryParser | null = null;
  #disasm: CapstoneDisassembler | null = null;

  constructor(
    private readonly target: BinaryTarget,
    private readonly profile: AnalysisProfileCommitment | undefined,
    private readonly logger: Logger,
  ) {}

  async execute(
    operation: AnalysisOperation,
    parameters: Readonly<Record<string, JsonValue>>,
    _options?: ExecutionOptions,
  ): Promise<Result<any, AnalysisError>> {
    try {
      const parser = this.#ensureParser();
      let result: JsonValue;

      switch (operation) {
        case "list_procedures":
        case "list_names":
        case "list_documents": {
          const parsed = parser.parse();
          result =
            typeof parsed === "object" && parsed !== null
              ? ((parsed as any).symbols ?? [])
              : [];
          break;
        }
        case "list_strings": {
          const parsed = parser.parse();
          result =
            typeof parsed === "object" && parsed !== null
              ? ((parsed as any).strings ?? [])
              : [];
          break;
        }
        case "list_segments": {
          result = parser.segments();
          break;
        }
        case "procedure_assembly":
        case "read_function_instructions": {
          const hex = (parameters.hex as string) ?? "";
          const addr = (parameters.address as string) ?? "0x0";
          const disasm = this.#ensureDisassembler();
          result = disasm.disassemble(hex, addr);
          break;
        }
        case "read_bytes": {
          const { readFileSync } = await import("node:fs");
          const offset = Number(parameters.offset ?? 0);
          const length = Number(parameters.length ?? 256);
          const buf = readFileSync(this.target.path);
          const slice = buf.subarray(offset, offset + length);
          result = Array.from(slice)
            .map((b) => b.toString(16).padStart(2, "0"))
            .join(" ");
          break;
        }
        case "analyze_function": {
          const full = parser.parse();
          result = full;
          break;
        }
        case "search_strings":
        case "search_procedures": {
          const pattern = (parameters.pattern as string) ?? "";
          const parsed = parser.parse();
          const strings: string[] =
            typeof parsed === "object" && parsed !== null
              ? ((parsed as any).strings ?? [])
              : [];
          const re = new RegExp(pattern, "i");
          result = strings.filter((s) => re.test(s));
          break;
        }
        case "health": {
          result = parser.parse();
          break;
        }
        default: {
          result = parser.parse();
        }
      }

      return ok(
        createAnalysisExecution(result, CAPSTONE_PROVIDER_IDENTITY, (this.profile ? { analysisProfile: this.profile } : {})),
      );
    } catch (error: any) {
      return err({
        operation,
        message: error?.message ?? String(error),
      } as any);
    }
  }

  async close() {
    this.#parser = null;
    this.#disasm = null;
    return ok(null);
  }

  #ensureParser(): CapstoneBinaryParser {
    if (!this.#parser)
      this.#parser = new CapstoneBinaryParser(this.target.path);
    return this.#parser;
  }

  #ensureDisassembler(): CapstoneDisassembler {
    if (!this.#disasm) this.#disasm = new CapstoneDisassembler();
    return this.#disasm;
  }
}
