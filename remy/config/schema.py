from typing import Literal, Optional
from pydantic import BaseModel, Field


class ScanDefaults(BaseModel):
    deep: bool = False
    max_file_size_kb: int = 1000
    respect_gitignore: bool = True


class Config(BaseModel):
    provider: Literal[
        "openrouter", "groq", "openai", "anthropic", "xai", "nvidia_nim", "ollama"
    ]
    model: str
    base_url: Optional[str] = None
    scan_defaults: ScanDefaults = Field(default_factory=ScanDefaults)
