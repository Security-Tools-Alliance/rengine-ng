from typing import Optional, List
from pydantic import BaseModel, Field, validator
from enum import Enum

class LLMProvider(str, Enum):
    OPENAI = "openai"
    OLLAMA = "ollama"

class ModelCapabilities(BaseModel):
    min_tokens: int
    max_tokens: int
    supports_functions: bool
    best_for: List[str]
    provider: str

class LLMInputData(BaseModel):
    description: str
    llm_model: Optional[str] = Field(default=None)
    provider: Optional[LLMProvider] = Field(default=None)
    capabilities: Optional[ModelCapabilities] = Field(default=None)
    
    @validator('description')
    def validate_description(cls, v):
        if not v or len(v.strip()) < 10:
            raise ValueError("Description must be at least 10 characters long")
        return v.strip()

    class Config:
        json_schema_extra = {
            "example": {
                "description": "SQL Injection vulnerability found in login form",
                "llm_model": "gpt-3.5-turbo",
                "provider": "openai",
                "capabilities": {
                    "min_tokens": 64,
                    "max_tokens": 2048,
                    "supports_functions": True,
                    "best_for": ["quick_analysis"],
                    "provider": "openai"
                }
            }
        }

class LLMResponse:
    def __init__(self, status: bool, description: str = None, impact: str = None, 
                 remediation: str = None, references: list = None, error: str = None):
        self.status = status
        self.description = description
        self.impact = impact
        self.remediation = remediation
        self.references = references or []
        self.error = error

    def get(self, key, default=None):
        """Add dictionary-like get method"""
        return getattr(self, key, default)

    def to_dict(self):
        """Convert to dictionary"""
        return {
            'status': self.status,
            'description': self.description,
            'impact': self.impact,
            'remediation': self.remediation,
            'references': self.references,
            'error': self.error
        }