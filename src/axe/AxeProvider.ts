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
import { AxeClient } from "./AxeClient.js";
import {
  inspectAxeInstallation,
  axeInstallationDiagnostics,
  type AxeInstallationInspection,
} from "./AxeInstallation.js";
import {
  CAPABILITIES,
  AXE_PROVIDER_IDENTITY,
} from "./AxeProviderCapabilities.js";

const SUPPORTED_ARCHITECTURES = new Set([
  "x86",
  "x86_64",
  "arm",
  "arm64",
  "mips",
  "ppc",
  "riscv",
]);

export class AxeProvider implements AnalysisProviderCandidate {
  #installation: AxeInstallationInspection | undefined;
  private readonly environment: NodeJS.ProcessEnv;

  constructor(
    private readonly config: AppConfig,
    private readonly logger: Logger,
    environment: Readonly<NodeJS.ProcessEnv>,
  ) {
    this.environment = snapshotEnvironment(environment);
  }

  identity(): ProviderIdentity {
    return AXE_PROVIDER_IDENTITY;
  }

  capabilities(): readonly CapabilityDescriptor[] {
    return CAPABILITIES;
  }

  inspectAvailability(): ProviderAvailability {
    const inspection = this.#inspect();
    if (!inspection.installed)
      return {
        status: "unavailable",
        code: "executable_missing",
        reason: "axe is not installed. Install via: brew install axe",
        diagnostics: axeInstallationDiagnostics(inspection),
      };
    return {
      status: "available",
      code: null,
      reason: null,
      diagnostics: axeInstallationDiagnostics(inspection),
    };
  }

  inspectTargetSupport(target: BinaryTarget): ProviderTargetSupport {
    if (target.kind !== "executable")
      return {
        status: "unsupported",
        code: "target_kind_unsupported",
        reason: `Axe supports executables; got ${target.kind}`,
        diagnostics: {},
      };
    if (
      target.architecture &&
      !SUPPORTED_ARCHITECTURES.has(target.architecture)
    )
      return {
        status: "unsupported",
        code: "architecture_unsupported",
        reason: `Unsupported architecture: ${target.architecture}`,
        diagnostics: { architecture: target.architecture },
      };
    return { status: "supported", code: null, reason: null, diagnostics: {} };
  }

  async resolveAnalysisProfile(
    target: BinaryTarget,
    _options?: AnalysisProfileResolutionOptions,
  ) {
    const inspection = this.#inspect();
    if (!inspection.installed) return ok({ profile: null });
    const profile = createAnalysisProfile(
      {
        ...AXE_PROVIDER_IDENTITY,
        version: inspection.version ?? "unknown",
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
    return new AxeAnalysisClient(target, profile, this.logger);
  }

  #inspect(): AxeInstallationInspection {
    if (!this.#installation) this.#installation = inspectAxeInstallation();
    return this.#installation;
  }
}

class AxeAnalysisClient implements AnalysisClient {
  #client: AxeClient | null = null;
  #initialized = false;

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
      const client = await this.#ensureClient();
      let result: JsonValue;

      switch (operation) {
        case "list_procedures":
          result = await client.listFunctions();
          break;
        case "list_names":
        case "list_documents":
          result = await client.listSymbols();
          break;
        case "list_strings":
          result = await client.listStrings();
          break;
        case "list_segments":
          result = await client.listSegments();
          break;
        case "procedure_assembly":
        case "read_function_instructions": {
          const name =
            (parameters.name as string) ??
            (parameters.address as string) ??
            "main";
          result = await client.disassembleFunction(name);
          break;
        }
        case "procedure_pseudo_code": {
          const name =
            (parameters.name as string) ??
            (parameters.address as string) ??
            "main";
          result = await client.decompileFunction(name);
          break;
        }
        case "xrefs": {
          const addr = (parameters.address as string) ?? "0x0";
          result = await client.getXrefs(addr);
          break;
        }
        case "read_bytes": {
          const addr = (parameters.address as string) ?? "0x0";
          const len = (parameters.length as number) ?? 256;
          result = await client.readBytes(addr, len);
          break;
        }
        case "search_procedures":
        case "search_strings": {
          const pattern =
            (parameters.pattern as string) ??
            (parameters.query as string) ??
            "";
          result = await client.searchString(pattern);
          break;
        }
        case "analyze_function": {
          const name =
            (parameters.name as string) ??
            (parameters.address as string) ??
            "main";
          const [asm, pseudo, xrefs] = await Promise.all([
            client.disassembleFunction(name),
            client.decompileFunction(name),
            client.getXrefs(name),
          ]);
          result = { assembly: asm, pseudocode: pseudo, xrefs };
          break;
        }
        case "health":
          result = await client.info();
          break;
        default:
          result = await client.commandJson(`?e Unsupported: ${operation}`);
      }

      return ok(
        createAnalysisExecution(
          result,
          AXE_PROVIDER_IDENTITY,
          this.profile ? { analysisProfile: this.profile } : {},
        ),
      );
    } catch (error: any) {
      return err({
        operation,
        message: error?.message ?? String(error),
      } as any);
    }
  }

  async close() {
    this.#client?.close();
    this.#client = null;
    return ok(null);
  }

  async #ensureClient(): Promise<AxeClient> {
    if (!this.#client) {
      this.#client = new AxeClient(this.target.path);
      await this.#client.open();
    }
    if (!this.#initialized) {
      await this.#client.analyze();
      this.#initialized = true;
    }
    return this.#client;
  }
}
