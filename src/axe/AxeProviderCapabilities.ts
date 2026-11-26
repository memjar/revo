import type {
  CapabilityDescriptor,
  ProviderIdentity,
} from "../application/AnalysisProvider.js";

export const AXE_PROVIDER_IDENTITY: ProviderIdentity = Object.freeze({
  id: "axe",
  name: "Axe",
  version: null,
});

export const AXE_OPERATIONS = Object.freeze([
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
  "Axe performs headless analysis via rzpipe; no GUI required.",
  "Decompilation uses rz-ghidra plugin (libghidra, no JVM).",
  "Analysis database is ephemeral per session.",
]);

export const CAPABILITIES: readonly CapabilityDescriptor[] = Object.freeze(
  AXE_OPERATIONS.map((operation) =>
    Object.freeze({
      provider: AXE_PROVIDER_IDENTITY,
      operation,
      available: true,
      reason: null,
      cachePolicy: "snapshot" as const,
      effects: Object.freeze({
        mutatesArtifact: false,
        launchesProcess: true,
        mayShowUi: false,
        mayAccessNetwork: false,
        mayWriteFilesystem: true,
        changesPermissions: false,
        requiresRoot: false,
      }),
      limitations: Object.freeze([...HEALTH_LIMITATIONS]),
    }),
  ),
);
