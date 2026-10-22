---
name: gguf-inspection
description: Parse and inspect GGUF v3 model files — header, metadata, tensor inventory, quantization type.
metadata:
  version: "1"
---

# GGUF Inspection

Inspect GGUF (GPT-Generated Unified Format) model files to extract architecture, quantization, tensor layout, and metadata without loading the full model into memory.

## When to use

Use this skill when you need to identify a GGUF model's architecture, quantization level, vocabulary size, context length, tensor count, or authorship metadata from the binary file alone.

## File structure

GGUF v3 layout (little-endian throughout):

| Offset  | Size | Field                                                     |
| ------- | ---- | --------------------------------------------------------- |
| 0x00    | 4    | Magic: `GGUF` (0x46475547)                                |
| 0x04    | 4    | Version (3)                                               |
| 0x08    | 8    | tensor_count (u64)                                        |
| 0x10    | 8    | metadata_kv_count (u64)                                   |
| 0x18    | var  | metadata KV pairs                                         |
| var     | var  | tensor info array                                         |
| aligned | var  | tensor data (aligned to `alignment` metadata, default 32) |

## Metadata extraction

Key metadata fields to extract:

- `general.architecture` — model family (llama, mamba, phi, gemma, qwen2, etc.)
- `general.name` — human-readable model name
- `general.quantization_version` — quantization format version
- `general.file_type` — GGML type enum (Q4_0=2, Q4_1=3, Q5_0=8, Q5_1=9, Q8_0=7, F16=1, F32=0, Q4_K_M=15, Q6_K=18, etc.)
- `tokenizer.ggml.model` — tokenizer type (llama, gpt2, etc.)
- `tokenizer.ggml.tokens` — vocabulary as string array
- `{arch}.context_length` — maximum context window
- `{arch}.embedding_length` — hidden dimension
- `{arch}.block_count` — number of transformer layers
- `{arch}.attention.head_count` — attention heads
- `{arch}.attention.head_count_kv` — KV heads (GQA indicator)

## Quick inspection commands

Hex header check:

```
xxd -l 32 model.gguf
```

Python with gguf-py:

```python
from gguf import GGUFReader
reader = GGUFReader("model.gguf")
for k, field in reader.fields.items():
    print(f"{k}: {field.parts[-1]}")
for tensor in reader.tensors:
    print(f"{tensor.name}: shape={tensor.shape}, type={tensor.tensor_type.name}")
```

Raw struct parse (no dependencies):

```python
import struct, mmap
with open("model.gguf", "rb") as f:
    magic, ver, tc, kvc = struct.unpack("<IIqq", f.read(24))
    assert magic == 0x46475547, "not GGUF"
```

## Tensor inventory

Each tensor info entry contains: name (string), n_dimensions (u32), dimensions (u64 * n_dims), type (u32 enum), offset from tensor data start (u64). Walk the tensor info array to build a full inventory of layer names, shapes, and quantization types per tensor.

Common tensor name patterns:

- `blk.{N}.attn_q.weight` — query projection, layer N
- `blk.{N}.attn_k.weight` / `attn_v.weight` — key/value
- `blk.{N}.ffn_gate.weight` / `ffn_up.weight` / `ffn_down.weight` — MLP
- `token_embd.weight` — embedding table
- `output_norm.weight` — final layer norm
- `output.weight` — LM head

## Architecture fingerprinting

Determine the model family from tensor names alone when metadata is missing:

- `blk.*.attn_q` + `ffn_gate` + `ffn_up` + `ffn_down` → LLaMA/Mistral
- `blk.*.attn_qkv` (fused) → Phi/StableLM
- `blk.*.ssm_*` → Mamba/SSM hybrid
- `blk.*.attn_q` + `ffn_gate_inp` → Mixtral (MoE gating)

## Quantization identification

Map `general.file_type` to quantization:

| Value | Type   | Bits/weight | Notes                       |
| ----- | ------ | ----------- | --------------------------- |
| 0     | F32    | 32          | Full precision              |
| 1     | F16    | 16          | Half precision              |
| 7     | Q8_0   | 8.5         | High quality                |
| 15    | Q4_K_M | 4.83        | Best quality/size for 4-bit |
| 18    | Q6_K   | 6.56        | Near-F16 quality            |
| 2     | Q4_0   | 4.5         | Legacy 4-bit                |
