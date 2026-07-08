from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional


class ProviderError(Exception):
    """Raised when a provider encounters an error (auth, network, API)."""

    pass


@dataclass
class ModelInfo:
    """Metadata about an available model from a provider."""

    id: str
    name: str
    context_length: Optional[int] = None
    notes: Optional[str] = None


@dataclass
class Message:
    """A single chat message."""

    role: str  # 'system', 'user', or 'assistant'
    content: str


class Provider(ABC):
    """Abstract base class for all LLM providers."""

    @abstractmethod
    async def list_models(self) -> list[ModelInfo]:
        """Return a list of available models for this provider."""
        ...

    @abstractmethod
    async def complete(self, messages: list[Message], **kwargs) -> str:
        """Send messages to the LLM and return the response text."""
        ...

    @abstractmethod
    async def validate_credentials(self) -> bool:
        """Validate that the credentials are correct. Returns True if valid."""
        ...
