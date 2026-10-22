---
name: model-weight-re
description: Reverse engineer SafeTensors and PyTorch model weight files — tensor inventory, architecture fingerprinting, dtype analysis.
metadata:
  version: "1"
---

# Model Weight RE

Extract architecture, tensor layout, parameter counts, and layer structure from SafeTensors and PyTorch weight files without running inference.

## When to use

Use when you have a .safetensors or .bin/.pt file and need to determine: model architecture, hidden dimensions, layer count, attention configuration, vocabulary size, total parameter count, or whether weights match a known architecture.

## SafeTensors format

Binary layout:

- Bytes 0-7: header size as u64 LE
- Bytes 8 to 8+header_size: UTF-8 JSON header
- Remaining: raw tensor data (contiguous, no padding)

Header JSON structure:

```json
{
  "tensor_name": {
    "dtype": "F16",
    "shape": [4096, 4096],
    "data_offsets": [0, 33554432]
  },
  "__metadata__": { "format": "pt" }
}
```

Quick header extraction:

```python
import struct, json
with open("model.safetensors", "rb") as f:
    size = struct.unpack("<Q", f.read(8))[0]
    header = json.loads(f.read(size))
    meta = header.pop("__metadata__", {})
    for name, info in sorted(header.items()):
        params = 1
        for d in info["shape"]: params *= d
        print(f"{name}: {info['dtype']} {info['shape']} ({params:,} params)")
```

## PyTorch format

PyTorch .bin/.pt files are ZIP archives containing pickled tensor metadata and raw data files.

Inspection:

```bash
zipinfo model.bin          # list archive contents
python -c "import torch; sd = torch.load('model.bin', map_location='cpu', weights_only=True); [print(f'{k}: {v.shape} {v.dtype}') for k,v in sd.items()]"
```

Structure inside the ZIP: `archive/data.pkl` (pickle with tensor metadata) + `archive/data/{0,1,2,...}` (raw tensor storage).

## Architecture fingerprinting

Determine model family from tensor name patterns:

| Pattern                                                  | Architecture               |
| -------------------------------------------------------- | -------------------------- |
| `model.layers.*.self_attn.q_proj`                        | LLaMA / Mistral            |
| `model.layers.*.mlp.gate_proj` + `up_proj` + `down_proj` | LLaMA-style gated MLP      |
| `transformer.h.*.attn.c_attn`                            | GPT-2 / GPT-NeoX           |
| `model.layers.*.self_attn.qkv_proj` (fused)              | Phi                        |
| `model.layers.*.block_sparse_moe`                        | Mixtral MoE                |
| `encoder.layers.*` + `decoder.layers.*`                  | Encoder-decoder (T5, BART) |
| `model.embed_tokens`                                     | HuggingFace convention     |
| `tok_embeddings`                                         | Meta/original LLaMA        |

## Parameter counting

```python
total = sum(1 for _ in [None] for name, info in header.items() if name != "__metadata__" for _ in [None] if (total := sum(eval("*".join(str(d) for d in info["shape"])) if info["shape"] else 0 for name, info in header.items() if name != "__metadata__")))
```

Simpler:

```python
import math
params = sum(math.prod(v["shape"]) for k, v in header.items() if k != "__metadata__")
print(f"{params/1e9:.2f}B parameters")
```

## Dtype analysis

| Dtype   | Bytes/param | Notes                             |
| ------- | ----------- | --------------------------------- |
| F32     | 4           | Full precision training           |
| F16     | 2           | Standard inference                |
| BF16    | 2           | Training-friendly, less precision |
| I8      | 1           | Post-training quantization        |
| F8_E4M3 | 1           | FP8 inference (Hopper+)           |

## Sharded models

Multi-file models use `model-00001-of-00003.safetensors` naming. The `model.safetensors.index.json` maps tensor names to filenames:

```json
{
  "weight_map": {
    "model.layers.0.self_attn.q_proj.weight": "model-00001-of-00003.safetensors"
  }
}
```

Parse the index first to locate specific layers without reading all shards.
