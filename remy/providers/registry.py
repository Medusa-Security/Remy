from remy.config.schema import Config
from remy.config.store import get_api_key
from .base import Provider, ProviderError
from .openrouter import OpenRouterProvider
from .groq import GroqProvider
from .openai_provider import OpenAIProvider
from .anthropic import AnthropicProvider
from .xai import XAIProvider
from .nvidia_nim import NVIDIANIMProvider
from .ollama import OllamaProvider


def get_provider(config: Config) -> Provider:
    """Instantiate and return the correct provider based on the active config.

    Reads the API key from the system keyring (or encrypted fallback).
    Raises ProviderError if credentials are missing for non-Ollama providers.

    Args:
        config: The loaded Config pydantic model.

    Returns:
        An instantiated Provider ready to use.

    Raises:
        ProviderError: If the provider is unknown or credentials are missing.
    """
    provider_name = config.provider
    api_key = get_api_key(provider_name)
    base_url = config.base_url

    if provider_name == "openrouter":
        if not api_key:
            raise ProviderError(
                "OpenRouter API key not found. Run `remy config` to set it up."
            )
        return OpenRouterProvider(api_key=api_key, model=config.model, base_url=base_url)

    elif provider_name == "groq":
        if not api_key:
            raise ProviderError(
                "Groq API key not found. Run `remy config` to set it up."
            )
        return GroqProvider(api_key=api_key, model=config.model)

    elif provider_name == "openai":
        if not api_key:
            raise ProviderError(
                "OpenAI API key not found. Run `remy config` to set it up."
            )
        return OpenAIProvider(api_key=api_key, model=config.model, base_url=base_url)

    elif provider_name == "anthropic":
        if not api_key:
            raise ProviderError(
                "Anthropic API key not found. Run `remy config` to set it up."
            )
        return AnthropicProvider(api_key=api_key, model=config.model)

    elif provider_name == "xai":
        if not api_key:
            raise ProviderError(
                "xAI API key not found. Run `remy config` to set it up."
            )
        return XAIProvider(api_key=api_key, model=config.model)

    elif provider_name == "nvidia_nim":
        if not api_key:
            raise ProviderError(
                "NVIDIA NIM API key not found. Run `remy config` to set it up."
            )
        return NVIDIANIMProvider(api_key=api_key, model=config.model, base_url=base_url)

    elif provider_name == "ollama":
        # Ollama does not require an API key
        return OllamaProvider(
            model=config.model,
            base_url=base_url or OllamaProvider.DEFAULT_BASE_URL,
        )

    else:
        raise ProviderError(
            f"Unknown provider: '{provider_name}'. "
            "Run `remy providers list` to see supported providers."
        )
