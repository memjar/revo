import type {
  CapabilityDescriptor,
  ProviderIdentity,
} from "../application/AnalysisProvider.js";

export const CAPSTONE_PROVIDER_IDENTITY: ProviderIdentity = Object.freeze({
  id: "capstone",
  name: "Capstone",
  version: null,
});

export const CAPSTONE_OPERATIONS = Object.freeze([
  "list_documents",
  "list_names",
  "list_procedures",
  "list_segments",
  "list_strings",
  "procedure_address",
  "procedure_assembly",
  "procedure_callees",
  "procedure_callers",
  "procedure_pseudo_code",
  "procedure_references",
  "read_function_instructions",
  "read_bytes",
  "address_to_file_offset",
  "resolve_containing_procedure",
  "search_procedures",
  "search_strings",
  "xrefs",
  "analyze_function",
] as const);

const HEALTH_LIMITATIONS = Object.freeze([
  "Capstone provides multi-arch disassembly without external dependencies.",
  "Binary parsing uses LIEF for Mach-O, ELF, and PE formats.",
  "Decompilation uses RetDec when available; falls back to annotated disassembly.",
]);

export const CAPABILITIES: readonly CapabilityDescriptor[] = Object.freeze(
  CAPSTONE_OPERATIONS.map((operation) =>
    Object.freeze({
      provider: CAPSTONE_PROVIDER_IDENTITY,
      operation,
      available: true,
      reason: null,
      cachePolicy: "snapshot" as const,
      effects: Object.freeze({
        mutatesArtifact: false,
        launchesProcess: true,
        mayShowUi: false,
        mayAccessNetwork: false,
        mayWriteFilesystem: false,
        changesPermissions: false,
        requiresRoot: false,
      }),
      limitations: Object.freeze([...HEALTH_LIMITATIONS]),
    }),
  ),
);
