import httpx
from typing import Optional
from .base import Provider, ModelInfo, Message, ProviderError


class OllamaProvider(Provider):
    """LLM provider backed by a local Ollama instance.

    Requires Ollama to be running locally (`ollama serve`).
    No API key is needed.
    """

    DEFAULT_BASE_URL = "http://localhost:11434"

    def __init__(
        self,
        model: str = "llama3.2",
        base_url: Optional[str] = None,
    ) -> None:
        self.model = model
        self.base_url = (base_url or self.DEFAULT_BASE_URL).rstrip("/")

    async def list_models(self) -> list[ModelInfo]:
        """Fetch running models from the Ollama /api/tags endpoint."""
        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                resp = await client.get(f"{self.base_url}/api/tags")
                resp.raise_for_status()
                data = resp.json()
                models = []
                for m in data.get("models", []):
                    name = m.get("name", "")
                    size = m.get("size", 0)
                    size_gb = f"{size / 1e9:.1f}GB" if size else ""
                    models.append(
                        ModelInfo(
                            id=name,
                            name=name,
                            notes=(
                                f"Local model, size: {size_gb}"
                                if size_gb
                                else "Local model"
                            ),
                        )
                    )
                return models
            except httpx.HTTPStatusError as e:
                raise ProviderError(
                    f"Ollama API error: {e.response.status_code}"
                ) from e
            except httpx.RequestError as e:
                raise ProviderError(
                    f"Cannot connect to Ollama at {self.base_url}. "
                    "Is Ollama running? Run `ollama serve` first."
                ) from e

    async def complete(self, messages: list[Message], **kwargs) -> str:
        """Send messages to Ollama's /api/chat endpoint and return the response."""
        payload = {
            "model": kwargs.get("model", self.model),
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "stream": False,
        }
        async with httpx.AsyncClient(timeout=120.0) as client:
            try:
                resp = await client.post(
                    f"{self.base_url}/api/chat",
                    json=payload,
                )
                resp.raise_for_status()
                data = resp.json()
                return data["message"]["content"]
            except httpx.HTTPStatusError as e:
                raise ProviderError(
                    f"Ollama completion error: {e.response.status_code} {e.response.text}"
                ) from e
            except (httpx.RequestError, KeyError) as e:
                raise ProviderError(f"Ollama request failed: {e}") from e

    async def validate_credentials(self) -> bool:
        """Check if Ollama is running and accessible (no key needed)."""
        return await self.detect_running(self.base_url)

    @classmethod
    async def detect_running(cls, base_url: str = DEFAULT_BASE_URL) -> bool:
        """Check if an Ollama instance is running at the given URL.

        Args:
            base_url: The Ollama server URL to probe.

        Returns:
            True if Ollama is reachable, False otherwise.
        """
        async with httpx.AsyncClient(timeout=5.0) as client:
            try:
                resp = await client.get(f"{base_url.rstrip('/')}/api/tags")
                return resp.status_code == 200
            except (httpx.RequestError, httpx.HTTPStatusError):
                return False
