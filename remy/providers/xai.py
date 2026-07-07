import httpx
from .base import Provider, ModelInfo, Message, ProviderError

XAI_MODELS = [
    ModelInfo(id="grok-3",      name="Grok 3",      context_length=131072, notes="Most capable Grok model."),
    ModelInfo(id="grok-3-mini", name="Grok 3 Mini",  context_length=131072, notes="Fast, cost-efficient Grok."),
    ModelInfo(id="grok-beta",   name="Grok Beta",    context_length=131072, notes="Latest beta release."),
]


class XAIProvider(Provider):
    """LLM provider backed by xAI's Grok model family."""

    BASE_URL = "https://api.x.ai/v1"

    def __init__(self, api_key: str, model: str = "grok-3-mini") -> None:
        self.api_key = api_key
        self.model = model

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    async def list_models(self) -> list[ModelInfo]:
        """Return the curated list of xAI Grok models."""
        return XAI_MODELS

    async def complete(self, messages: list[Message], **kwargs) -> str:
        """Send messages to xAI and return the response."""
        payload = {
            "model": kwargs.get("model", self.model),
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "temperature": kwargs.get("temperature", 0.2),
            "max_tokens": kwargs.get("max_tokens", 4096),
        }
        async with httpx.AsyncClient(timeout=60.0) as client:
            try:
                resp = await client.post(
                    f"{self.BASE_URL}/chat/completions",
                    headers=self._headers(),
                    json=payload,
                )
                resp.raise_for_status()
                data = resp.json()
                return data["choices"][0]["message"]["content"]
            except httpx.HTTPStatusError as e:
                raise ProviderError(f"xAI API error: {e.response.status_code} {e.response.text}") from e
            except (httpx.RequestError, KeyError) as e:
                raise ProviderError(f"xAI request failed: {e}") from e

    async def validate_credentials(self) -> bool:
        """Validate API key by listing models."""
        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                resp = await client.get(f"{self.BASE_URL}/models", headers=self._headers())
                return resp.status_code == 200
            except httpx.RequestError:
                return False
