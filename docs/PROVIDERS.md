# Remy Provider Reference

## OpenRouter

- **Base URL:** `https://openrouter.ai/api/v1`
- **API Key:** Required — get one at [openrouter.ai/keys](https://openrouter.ai/keys)
- **Auth Header:** `Authorization: Bearer <key>`
- **Schema:** OpenAI-compatible chat completions
- **Notes:** Routes to 200+ upstream models (GPT-4o, Claude, Llama, Gemini, etc.). Good choice if you want model flexibility without managing multiple keys. Model IDs use format `provider/model-name` (e.g. `openai/gpt-4o`, `anthropic/claude-sonnet-4-5`).

## Groq

- **Base URL:** `https://api.groq.com/openai/v1`
- **API Key:** Required — get one at [console.groq.com](https://console.groq.com)
- **Auth Header:** `Authorization: Bearer <key>`
- **Schema:** OpenAI-compatible
- **Notes:** Extremely low inference latency (50–100ms). Recommended for fast bulk scanning passes. Best models: `llama-3.3-70b-versatile`, `llama-3.1-8b-instant`.

## OpenAI

- **Base URL:** `https://api.openai.com/v1`
- **API Key:** Required — get one at [platform.openai.com/api-keys](https://platform.openai.com/api-keys)
- **Auth Header:** `Authorization: Bearer <key>`
- **Schema:** OpenAI Chat Completions
- **Notes:** `gpt-4o` is the recommended model for deep code analysis. Custom `base_url` supported for Azure OpenAI deployments.

## Anthropic

- **Base URL:** `https://api.anthropic.com`
- **API Key:** Required — get one at [console.anthropic.com](https://console.anthropic.com)
- **Auth Header:** `x-api-key: <key>` (different from OpenAI providers — handled automatically)
- **Schema:** Native Anthropic Messages API (`/v1/messages`) — separate system prompt field
- **Notes:** Claude models excel at nuanced code reasoning. Recommended: `claude-sonnet-4-5` for balance of speed and quality.

## xAI (Grok)

- **Base URL:** `https://api.x.ai/v1`
- **API Key:** Required — get one at [console.x.ai](https://console.x.ai)
- **Auth Header:** `Authorization: Bearer <key>`
- **Schema:** OpenAI-compatible
- **Notes:** Grok 3 models. Good general-purpose code analysis.

## NVIDIA NIM

- **Base URL:** `https://integrate.api.nvidia.com/v1` (cloud) or your self-hosted endpoint
- **API Key:** Required for cloud — get one at [build.nvidia.com](https://build.nvidia.com)
- **Auth Header:** `Authorization: Bearer <key>`
- **Schema:** OpenAI-compatible
- **Notes:** Supports custom `base_url` for enterprise self-hosted NIM deployments. Access NVIDIA-optimized Llama, Mistral, and Phi models.

## Ollama (Local)

- **Base URL:** `http://localhost:11434` (default)
- **API Key:** Not required
- **Schema:** Ollama native `/api/chat`
- **Notes:** Fully local inference. Run `ollama serve` before using Remy. Pull models with `ollama pull llama3.2`. Remy auto-detects a running Ollama instance during the config wizard. Custom base URL supported for remote Ollama instances.

---

*Built by [Medusa Security](https://github.com/Medusa-Security)*
