---
name: ollama-modelfile-re
description: Reverse engineer Ollama Modelfile format — directives, template syntax, parameter tuning, blob storage layout.
metadata:
  version: "1"
---

# Ollama Modelfile RE

Understand and reverse engineer Ollama's Modelfile format, model packaging, template syntax, and blob storage to extract, modify, or rebuild model configurations.

## When to use

Use when you need to: extract a running model's full configuration, understand template syntax for a custom chat format, tune inference parameters, repackage a model with different system prompts, or inspect Ollama's blob storage directly.

## Modelfile directives

| Directive   | Purpose                          | Example                                   |
| ----------- | -------------------------------- | ----------------------------------------- |
| `FROM`      | Base model (name, path, or GGUF) | `FROM llama3.2:3b` or `FROM ./model.gguf` |
| `TEMPLATE`  | Go template for chat formatting  | `TEMPLATE """{{ .System }}..."`           |
| `SYSTEM`    | Default system message           | `SYSTEM "You are a helpful assistant."`   |
| `PARAMETER` | Inference parameter override     | `PARAMETER temperature 0.7`               |
| `ADAPTER`   | LoRA adapter path                | `ADAPTER ./lora.gguf`                     |
| `LICENSE`   | License text                     | `LICENSE "MIT"`                           |
| `MESSAGE`   | Seed conversation history        | `MESSAGE user "Hello"`                    |

## Extracting a running model's config

```bash
ollama show MODEL --modelfile
```

This outputs the reconstructed Modelfile. For deeper inspection:

```bash
ollama show MODEL --parameters
ollama show MODEL --template
ollama show MODEL --system
ollama show MODEL --license
```

## Template syntax

Ollama uses Go's `text/template` with these variables:

| Variable                | Content                                |
| ----------------------- | -------------------------------------- |
| `{{ .System }}`         | System message                         |
| `{{ .Prompt }}`         | User message (non-chat mode)           |
| `{{ .Response }}`       | Assistant response (generation target) |
| `{{ range .Messages }}` | Iterate chat messages                  |
| `{{ .Role }}`           | Message role (system/user/assistant)   |
| `{{ .Content }}`        | Message content                        |

Common chat template pattern:

```
{{- range .Messages }}
{{- if eq .Role "system" }}<|system|>
{{ .Content }}<|end|>
{{- else if eq .Role "user" }}<|user|>
{{ .Content }}<|end|>
{{- else if eq .Role "assistant" }}<|assistant|>
{{ .Content }}<|end|>
{{- end }}
{{- end }}<|assistant|>
```

## Parameter reference

| Parameter        | Default | Range    | Effect                                    |
| ---------------- | ------- | -------- | ----------------------------------------- |
| `temperature`    | 0.8     | 0.0-2.0  | Randomness                                |
| `top_k`          | 40      | 1-100    | Vocab filter                              |
| `top_p`          | 0.9     | 0.0-1.0  | Nucleus sampling                          |
| `repeat_penalty` | 1.1     | 0.0-2.0  | Repetition suppression                    |
| `repeat_last_n`  | 64      | 0-N      | Context window for repeat penalty         |
| `num_ctx`        | 2048    | 1-131072 | Context length                            |
| `num_predict`    | -1      | -2 to N  | Max tokens (-1=infinite, -2=fill context) |
| `stop`           | —       | string   | Stop sequence                             |
| `seed`           | 0       | int      | Deterministic sampling (0=random)         |
| `mirostat`       | 0       | 0/1/2    | Mirostat sampling mode                    |
| `mirostat_tau`   | 5.0     | float    | Target entropy                            |
| `mirostat_eta`   | 0.1     | float    | Learning rate                             |
| `num_gpu`        | -1      | -1 to N  | GPU layers (-1=auto)                      |
| `num_thread`     | —       | int      | CPU threads                               |
| `numa`           | false   | bool     | NUMA optimization                         |

## Blob storage layout

Ollama stores models as content-addressed blobs:

```
~/.ollama/models/
  manifests/
    registry.ollama.ai/
      library/
        llama3.2/
          3b          # JSON manifest
  blobs/
    sha256-abc123...  # actual model weights, templates, etc.
```

Manifest structure:

```json
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.ollama.image.manifest",
  "config": {"digest": "sha256:...", "size": N, "mediaType": "application/vnd.ollama.image.config"},
  "layers": [
    {"digest": "sha256:...", "size": N, "mediaType": "application/vnd.ollama.image.model"},
    {"digest": "sha256:...", "size": N, "mediaType": "application/vnd.ollama.image.template"},
    {"digest": "sha256:...", "size": N, "mediaType": "application/vnd.ollama.image.params"},
    {"digest": "sha256:...", "size": N, "mediaType": "application/vnd.ollama.image.system"}
  ]
}
```

Layer media types:

- `application/vnd.ollama.image.model` — GGUF weights (largest blob)
- `application/vnd.ollama.image.template` — chat template text
- `application/vnd.ollama.image.params` — JSON parameters
- `application/vnd.ollama.image.system` — system prompt text
- `application/vnd.ollama.image.adapter` — LoRA adapter weights
- `application/vnd.ollama.image.license` — license text

## Direct blob inspection

Read template from blob:

```bash
cat ~/.ollama/models/blobs/sha256-TEMPLATE_DIGEST
```

Read parameters:

```bash
cat ~/.ollama/models/blobs/sha256-PARAMS_DIGEST | python3 -m json.tool
```

Identify the GGUF weight blob (largest file) and use gguf-inspection skill for deeper analysis.

## Building custom models

```bash
ollama create mymodel -f Modelfile
ollama run mymodel "test prompt"
ollama push mymodel          # to registry (if authenticated)
ollama cp mymodel mymodel:v2 # local copy with new tag
```
