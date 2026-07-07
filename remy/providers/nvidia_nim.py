import httpx
from typing import Optional
from .base import Provider, ModelInfo, Message, ProviderError

NVIDIA_MODELS = [
    ModelInfo(id="nvidia/llama-3.1-nemotron-70b-instruct", name="Llama 3.1 Nemotron 70B", context_length=128000, notes="NVIDIA-optimized, high quality."),
    ModelInfo(id="meta/llama-3.1-70b-instruct",           name="Meta Llama 3.1 70B",     context_length=128000, notes="Strong general-purpose model."),
    ModelInfo(id="microsoft/phi-3-medium-128k-instruct",  name="Phi-3 Medium 128K",       context_length=128000, notes="Efficient model from Microsoft."),
]


class NVIDIANIMProvider(Provider):
    """LLM provider backed by NVIDIA NIM cloud or self-hosted inference."""

    DEFAULT_BASE_URL = "https://integrate.api.nvidia.com/v1"

    def __init__(
        self,
        api_key: str,
        model: str = "nvidia/llama-3.1-nemotron-70b-instruct",
        base_url: Optional[str] = None,
    ) -> None:
        self.api_key = api_key
        self.model = model
        self.base_url = (base_url or self.DEFAULT_BASE_URL).rstrip("/")

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    async def list_models(self) -> list[ModelInfo]:
        """Return the curated list of available NVIDIA NIM models."""
        return NVIDIA_MODELS

    async def complete(self, messages: list[Message], **kwargs) -> str:
        """Send messages to NVIDIA NIM and return the response."""
        payload = {
            "model": kwargs.get("model", self.model),
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "temperature": kwargs.get("temperature", 0.2),
            "max_tokens": kwargs.get("max_tokens", 4096),
        }
        async with httpx.AsyncClient(timeout=60.0) as client:
            try:
                resp = await client.post(
                    f"{self.base_url}/chat/completions",
                    headers=self._headers(),
                    json=payload,
                )
                resp.raise_for_status()
                data = resp.json()
                return data["choices"][0]["message"]["content"]
            except httpx.HTTPStatusError as e:
                raise ProviderError(f"NVIDIA NIM API error: {e.response.status_code} {e.response.text}") from e
            except (httpx.RequestError, KeyError) as e:
                raise ProviderError(f"NVIDIA NIM request failed: {e}") from e

    async def validate_credentials(self) -> bool:
        """Validate API key."""
        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                resp = await client.get(f"{self.base_url}/models", headers=self._headers())
                return resp.status_code == 200
            except httpx.RequestError:
                return False
