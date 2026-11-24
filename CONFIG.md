# Configuration Guide

NetzZwergenWacht supports flexible configuration via TOML files for model routing, patrol behavior, and execution policies.

## Model Configuration

### Overview

Die Zwergenbrigade supports per-dwarf model routing, allowing you to assign different LLM providers and models to each specialist agent. This enables optimal cost/quality trade-offs and leveraging domain-specific model strengths.

### Configuration Structure

Create a `config.toml` file with a `[models]` section:

```toml
[models]
# Default provider configuration (fallback for all agents)
[models.default]
kind = "openai"              # Provider: "openai", "anthropic", "ollama"
model = "gpt-4o-mini"        # Model identifier
temperature = 0.7            # Optional: sampling temperature (0.0-2.0)

# Role-based routing (overrides default for specific roles)
[models.kommandant]
kind = "anthropic"
model = "claude-3-5-sonnet-20241022"
temperature = 0.3

[models.specialist]
kind = "openai"
model = "gpt-4o-mini"

[models.dokumentation]
kind = "anthropic"
model = "claude-3-5-haiku-20241022"

# Per-dwarf routing (highest priority, overrides role defaults)
[models.dwarfs.Leistungs]
kind = "openai"
model = "gpt-4o"             # More capable model for performance analysis

[models.dwarfs.Sicherheits]
kind = "anthropic"
model = "claude-3-5-sonnet-20241022"  # Security-focused model

[models.dwarfs.Browser]
kind = "anthropic"
model = "claude-3-5-haiku-20241022"   # Fast model for console log analysis
```

### Provider Resolution Order

1. **Per-dwarf override** (`models.dwarfs.<DwarfId>`) — highest priority
2. **Role-based routing** (`models.kommandant`, `models.specialist`, `models.dokumentation`)
3. **Default provider** (`models.default`) — fallback

Example resolution:
- `LeistungsZwerg` → Check `models.dwarfs.Leistungs` → Check `models.specialist` → Fallback to `models.default`
- `KommandantZwerg` → Check `models.kommandant` → Fallback to `models.default`

### Supported Providers

#### OpenAI
```toml
[models.default]
kind = "openai"
model = "gpt-4o"             # or "gpt-4o-mini", "gpt-4-turbo", etc.
```

Requires `OPENAI_API_KEY` environment variable.

#### Anthropic
```toml
[models.default]
kind = "anthropic"
model = "claude-3-5-sonnet-20241022"  # or "claude-3-5-haiku-20241022", "claude-opus-4-5-20251101"
```

Requires `ANTHROPIC_API_KEY` environment variable.

#### Ollama (Local)
```toml
[models.default]
kind = "ollama"
model = "llama3.2:3b"
# endpoint = "http://localhost:11434"  # Optional: custom Ollama endpoint
```

Requires running Ollama server locally.

### Die Zwergenbrigade Agent Roles

**Specialist Agents** (default: `models.specialist`):
- `Netz` — Network/HTTP diagnostics
- `Sicherheits` — Security analysis
- `Leistungs` — Performance/Core Web Vitals
- `Struktur` — Semantic HTML structure
- `Zugaenglichkeits` — Accessibility/WCAG
- `Such` — SEO metadata
- `Inhalts` — Content quality
- `Gestaltungs` — Visual integrity
- `Browser` — JavaScript runtime/console

**Coordination Agent** (default: `models.kommandant`):
- `Kommandant` — Hypothesis planning and evidence synthesis

**Reporting Agent** (default: `models.dokumentation`):
- `Dokumentations` — Stakeholder report generation

### Usage

#### Patrol Mode
```bash
# Use config file for model routing
nzw patrol https://example.com --config config.toml

# Portfolio patrol with model routing
nzw patrol --portfolio portfolio.toml --config config.toml
```

#### Investigation Mode
```bash
# Agentic investigation with specialist model routing
nzw investigate https://example.com \
  --objective "Diagnose LCP regression" \
  --config config.toml
```

### Cost Optimization Strategies

**Strategy 1: Fast specialists, capable coordinator**
```toml
[models.specialist]
kind = "openai"
model = "gpt-4o-mini"      # Low-cost for routine diagnostics

[models.kommandant]
kind = "anthropic"
model = "claude-3-5-sonnet-20241022"  # Higher capability for synthesis
```

**Strategy 2: Per-domain specialization**
```toml
[models.dwarfs.Leistungs]
kind = "openai"
model = "gpt-4o"           # GPT-4o excels at numerical analysis

[models.dwarfs.Sicherheits]
kind = "anthropic"
model = "claude-3-5-sonnet-20241022"  # Claude strong on security

[models.dwarfs.Browser]
kind = "openai"
model = "gpt-4o-mini"      # Simple console log parsing
```

**Strategy 3: Local development**
```toml
[models.default]
kind = "ollama"
model = "llama3.2:3b"      # Free local inference

[models.kommandant]
kind = "anthropic"
model = "claude-3-5-haiku-20241022"  # Paid only for complex coordination
```

### Environment Variables

Required authentication:
- `OPENAI_API_KEY` — For OpenAI providers
- `ANTHROPIC_API_KEY` — For Anthropic providers

Optional Ollama configuration:
- `OLLAMA_ENDPOINT` — Custom Ollama server URL (default: `http://localhost:11434`)

### Limitations & Known Issues

**Current Limitations:**
- Specialist re-consultation during investigation currently uses Kommandant's model (P1: should resolve per-specialist)
- No support for Azure OpenAI or other OpenAI-compatible endpoints yet
- Temperature parameter applies globally, not per-turn

**Validation:**
- Invalid `kind` values fall back to default provider
- Missing models fail gracefully with error message
- Unrecognized dwarf IDs in `models.dwarfs.*` are ignored

### Examples

**Minimal configuration** (single provider):
```toml
[models.default]
kind = "openai"
model = "gpt-4o-mini"
```

**Production configuration** (hybrid providers):
```toml
[models.default]
kind = "openai"
model = "gpt-4o-mini"

[models.kommandant]
kind = "anthropic"
model = "claude-3-5-sonnet-20241022"

[models.dwarfs.Leistungs]
kind = "openai"
model = "gpt-4o"

[models.dwarfs.Sicherheits]
kind = "anthropic"
model = "claude-3-5-sonnet-20241022"
```

**Local development** (minimize costs):
```toml
[models.default]
kind = "ollama"
model = "llama3.2:3b"
```

## Patrol Configuration

See `examples/patrol-budget.toml` for patrol-specific configuration (sampling, budgets, freshness TTL).

## Policy Configuration

See `examples/policy-gates.toml` for failure thresholds and severity-based gates.
