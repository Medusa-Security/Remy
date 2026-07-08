import httpx
from typing import Optional
from .base import Provider, ModelInfo, Message, ProviderError


class OpenAIProvider(Provider):
    """LLM provider backed by OpenAI's Chat Completions API."""

    BASE_URL = "https://api.openai.com/v1"

    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4o",
        base_url: Optional[str] = None,
    ) -> None:
        self.api_key = api_key
        self.model = model
        self.base_url = (base_url or self.BASE_URL).rstrip("/")

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    async def list_models(self) -> list[ModelInfo]:
        """Fetch and filter GPT models from the OpenAI /models endpoint."""
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                resp = await client.get(
                    f"{self.base_url}/models", headers=self._headers()
                )
                resp.raise_for_status()
                data = resp.json()
                models = []
                for m in data.get("data", []):
                    mid = m.get("id", "")
                    if any(mid.startswith(p) for p in ("gpt-", "o1", "o3")):
                        models.append(ModelInfo(id=mid, name=mid))
                models.sort(key=lambda x: x.id)
                return models
            except httpx.HTTPStatusError as e:
                raise ProviderError(
                    f"OpenAI API error: {e.response.status_code}"
                ) from e
            except httpx.RequestError as e:
                raise ProviderError(f"OpenAI connection error: {e}") from e

    async def complete(self, messages: list[Message], **kwargs) -> str:
        """Send messages to OpenAI and return the response."""
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
                raise ProviderError(
                    f"OpenAI completion error: {e.response.status_code} {e.response.text}"
                ) from e
            except (httpx.RequestError, KeyError) as e:
                raise ProviderError(f"OpenAI request failed: {e}") from e

    async def validate_credentials(self) -> bool:
        """Validate credentials by fetching the models list."""
        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                resp = await client.get(
                    f"{self.base_url}/models", headers=self._headers()
                )
                return resp.status_code == 200
            except httpx.RequestError:
                return False
