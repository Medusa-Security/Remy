import httpx
from typing import Optional
from .base import Provider, ModelInfo, Message, ProviderError


class OpenRouterProvider(Provider):
    """LLM provider backed by OpenRouter (https://openrouter.ai).

    OpenRouter routes requests to many upstream models using an
    OpenAI-compatible API schema.
    """

    BASE_URL = "https://openrouter.ai/api/v1"

    def __init__(
        self,
        api_key: str,
        model: str = "openai/gpt-4o",
        base_url: Optional[str] = None,
    ) -> None:
        self.api_key = api_key
        self.model = model
        self.base_url = (base_url or self.BASE_URL).rstrip("/")

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "HTTP-Referer": "https://github.com/Medusa-Security",
            "X-Title": "Remy Agent",
            "Content-Type": "application/json",
        }

    async def list_models(self) -> list[ModelInfo]:
        """Fetch live model list from OpenRouter /models endpoint."""
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                resp = await client.get(
                    f"{self.base_url}/models",
                    headers=self._headers(),
                )
                resp.raise_for_status()
                data = resp.json()
                models = []
                for m in data.get("data", []):
                    models.append(
                        ModelInfo(
                            id=m.get("id", ""),
                            name=m.get("name", m.get("id", "")),
                            context_length=m.get("context_length"),
                            notes=m.get("description", ""),
                        )
                    )
                return models
            except httpx.HTTPStatusError as e:
                raise ProviderError(
                    f"OpenRouter API error: {e.response.status_code} {e.response.text}"
                ) from e
            except httpx.RequestError as e:
                raise ProviderError(f"OpenRouter connection error: {e}") from e

    async def complete(self, messages: list[Message], **kwargs) -> str:
        """Send chat messages and return the assistant's response."""
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
                    f"OpenRouter completion error: {e.response.status_code} {e.response.text}"
                ) from e
            except (httpx.RequestError, KeyError) as e:
                raise ProviderError(f"OpenRouter request failed: {e}") from e

    async def validate_credentials(self) -> bool:
        """Validate API key by fetching the models list."""
        try:
            await self.list_models()
            return True
        except ProviderError:
            return False
