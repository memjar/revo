# Chameleon / Ghidra analysis

This note records the current reference analysis used to start Chameleon.

## Reference inputs

- Ghidra source scratch tree: `/Users/studio/ghidra-scratch`
- Verified release: `ghidra_12.2_PUBLIC_20261016.zip`
- Release SHA-256: `2c2cd776db3c1f6a097ba418922378ac3649cadd5e844a6f5f088ae628a7be67`
- Revo retained evidence: `/Users/studio/ghidra-scratch/revo-evidence.json`

The release archive was opened and inventoried read-only. Ghidra build and dependency-fetch scripts were not executed.

## Architecture model

```text
artifact loader
  -> processor/language registry
  -> memory and listing model
  -> disassembler
  -> intermediate representation
  -> analysis passes
  -> decompiler
  -> project/database store
  -> UI, scripting, and API surfaces
```

The source is organized primarily into `Framework`, `Features`, `Processors`, `Configurations`, `GhidraBuild`, and `Test`. Chameleon begins with the same separation of concerns but uses a small Python core and explicit pass interfaces.

## Chameleon status

The independent prototype lives at `/Users/studio/Chameleon`. Current support is artifact hashing, byte-region loading, header format detection, and a pluggable analysis-pass API. ELF/PE/Mach-O decoding, IR, persistent projects, and decompilation remain future work.

## Reproduction

```bash
cd /Users/studio/Chameleon
python3 -m compileall -q chameleon
python3 -m chameleon.cli /bin/ls
```
