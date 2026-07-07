import httpx
from .base import Provider, ModelInfo, Message, ProviderError

ANTHROPIC_MODELS = [
    ModelInfo(id="claude-opus-4-5",          name="Claude Opus 4.5",          context_length=200000, notes="Most capable. Best for deep logic analysis."),
    ModelInfo(id="claude-sonnet-4-5",        name="Claude Sonnet 4.5",        context_length=200000, notes="Balanced speed/quality. Recommended default."),
    ModelInfo(id="claude-haiku-4-5",         name="Claude Haiku 4.5",         context_length=200000, notes="Fastest Claude model."),
    ModelInfo(id="claude-3-5-haiku-20241022",name="Claude 3.5 Haiku",         context_length=200000, notes="Cost-efficient previous generation."),
]


class AnthropicProvider(Provider):
    """LLM provider backed by Anthropic's native Messages API."""

    BASE_URL = "https://api.anthropic.com"
    API_VERSION = "2023-06-01"

    def __init__(self, api_key: str, model: str = "claude-sonnet-4-5") -> None:
        self.api_key = api_key
        self.model = model

    def _headers(self) -> dict[str, str]:
        return {
            "x-api-key": self.api_key,
            "anthropic-version": self.API_VERSION,
            "content-type": "application/json",
        }

    async def list_models(self) -> list[ModelInfo]:
        """Return the curated list of Anthropic models."""
        return ANTHROPIC_MODELS

    async def complete(self, messages: list[Message], **kwargs) -> str:
        """Send messages to Anthropic Messages API and return the response.

        Separates the system message from user/assistant messages as required
        by the Anthropic API schema.
        """
        system_prompt = ""
        conversation: list[dict] = []

        for msg in messages:
            if msg.role == "system":
                system_prompt = msg.content
            else:
                conversation.append({"role": msg.role, "content": msg.content})

        if not conversation:
            conversation.append({"role": "user", "content": "Hello"})

        payload: dict = {
            "model": kwargs.get("model", self.model),
            "max_tokens": kwargs.get("max_tokens", 4096),
            "messages": conversation,
        }
        if system_prompt:
            payload["system"] = system_prompt

        async with httpx.AsyncClient(timeout=60.0) as client:
            try:
                resp = await client.post(
                    f"{self.BASE_URL}/v1/messages",
                    headers=self._headers(),
                    json=payload,
                )
                resp.raise_for_status()
                data = resp.json()
                # Anthropic response: content is a list of content blocks
                content_blocks = data.get("content", [])
                text_parts = [b["text"] for b in content_blocks if b.get("type") == "text"]
                return "\n".join(text_parts)
            except httpx.HTTPStatusError as e:
                raise ProviderError(
                    f"Anthropic API error: {e.response.status_code} {e.response.text}"
                ) from e
            except (httpx.RequestError, KeyError) as e:
                raise ProviderError(f"Anthropic request failed: {e}") from e

    async def validate_credentials(self) -> bool:
        """Validate API key by sending a minimal messages request."""
        try:
            payload = {
                "model": self.model,
                "max_tokens": 1,
                "messages": [{"role": "user", "content": "Hi"}],
            }
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    f"{self.BASE_URL}/v1/messages",
                    headers=self._headers(),
                    json=payload,
                )
                return resp.status_code not in (401, 403)
        except httpx.RequestError:
            return False
