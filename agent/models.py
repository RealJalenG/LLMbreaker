from typing import Any, List, Optional, Type, Dict
from pydantic import BaseModel, Field
from datetime import datetime

class IntentIO(BaseModel):
    """Base class for Input/Output models"""
    pass

class TokenUsage(BaseModel):
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0

class IntentResult(BaseModel):
    output: Any
    usage: TokenUsage
    timestamp: datetime = Field(default_factory=datetime.now)

class PythonExecResult(BaseModel):
    prints: List[str]
    error: str

class CodeEngine:
    def configure(self, intent_ir: str, runtime_context: str):
        raise NotImplementedError

    def request(self, prompt: str) -> str:
        raise NotImplementedError
    
    @property
    def input_tokens(self) -> int:
        return 0
    
    @property
    def output_tokens(self) -> int:
        return 0
    
    @property
    def total_tokens(self) -> int:
        return 0

class Executor:
    def run(self) -> IntentResult:
        raise NotImplementedError

class EngineFactory:
    def create(self) -> CodeEngine:
        raise NotImplementedError
