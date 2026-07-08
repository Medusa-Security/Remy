import httpx
from .base import Provider, ModelInfo, Message, ProviderError

GROQ_MODELS = [
    ModelInfo(
        id="llama-3.3-70b-versatile",
        name="Llama 3.3 70B Versatile",
        context_length=128000,
        notes="Best overall quality on Groq.",
    ),
    ModelInfo(
        id="llama-3.1-8b-instant",
        name="Llama 3.1 8B Instant",
        context_length=128000,
        notes="Fastest option for bulk scanning.",
    ),
    ModelInfo(
        id="mixtral-8x7b-32768",
        name="Mixtral 8x7B",
        context_length=32768,
        notes="Good balance of speed and quality.",
    ),
    ModelInfo(
        id="gemma2-9b-it",
        name="Gemma 2 9B",
        context_length=8192,
        notes="Google Gemma 2, instruction tuned.",
    ),
]


class GroqProvider(Provider):
    """LLM provider backed by Groq for ultra-low-latency inference."""

    BASE_URL = "https://api.groq.com/openai/v1"

    def __init__(self, api_key: str, model: str = "llama-3.3-70b-versatile") -> None:
        self.api_key = api_key
        self.model = model

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    async def list_models(self) -> list[ModelInfo]:
        """Return a curated list of Groq-supported models."""
        return GROQ_MODELS

    async def complete(self, messages: list[Message], **kwargs) -> str:
        """Send messages to Groq and return the response."""
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
                raise ProviderError(
                    f"Groq API error: {e.response.status_code} {e.response.text}"
                ) from e
            except (httpx.RequestError, KeyError) as e:
                raise ProviderError(f"Groq request failed: {e}") from e

    async def validate_credentials(self) -> bool:
        """Validate API key by making a lightweight models request."""
        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                resp = await client.get(
                    f"{self.BASE_URL}/models", headers=self._headers()
                )
                return resp.status_code == 200
            except httpx.RequestError:
                return False
