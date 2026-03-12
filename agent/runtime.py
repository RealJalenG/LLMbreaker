import ast
import traceback
import logging
from types import SimpleNamespace
from typing import Type, Any, List
from .models import PythonExecResult, IntentIO

try:
    from .optimization.utils import LRUCacheWithStats, timed_operation
    from .optimization.logging_utils import get_logger
    OPTIMIZATION_AVAILABLE = True
except ImportError:
    OPTIMIZATION_AVAILABLE = False

if OPTIMIZATION_AVAILABLE:
    logger = get_logger(__name__)
    _code_cache = LRUCacheWithStats(max_size=128)
else:
    logger = logging.getLogger(__name__)
    _code_cache = None

class PythonRuntime:
    def __init__(self, input: IntentIO, tools: SimpleNamespace, output: Type[IntentIO]):
        self._prints: List[str] = []
        self._globals: dict[str, Any] = {
            "__builtins__": __builtins__,
            "print": self._create_print_func(),
            "input": input,
            "tools": tools,
            "OutputModel": output,
            "output": None
        }
        
        builtins = __builtins__ if isinstance(__builtins__, dict) else vars(__builtins__)
        for name, obj in vars(tools).items():
            if name not in self._globals and name not in builtins:
                self._globals[name] = obj

    def _create_print_func(self):
        def _print(*args, **kwargs):
            limit = kwargs.pop("limit", 5000)
            text = " ".join(str(a) for a in args)
            if limit == -1:
                self._prints.append(text)
            elif len(text) > limit:
                self._prints.append(
                    f"{text[:limit]} [truncated: {len(text)} chars, showing first {limit}. "
                    f"Generally you don't need the full content. Use print(..., limit=10000) or larger if required]"
                )
            else:
                self._prints.append(text)
        return _print

    async def exec(self, source: str) -> PythonExecResult:
        error = "None"
        try:
            if "import os" in source or "import sys" in source or "import subprocess" in source:
                pass 

            if OPTIMIZATION_AVAILABLE and _code_cache:
                cache_key = source[:200]
                cached = _code_cache.get(cache_key)
                if cached is not None:
                    code = cached
                    logger.debug("Using cached compiled code")
                else:
                    code = compile(
                        source=source,
                        filename="<runtime>",
                        mode="exec",
                        flags=ast.PyCF_ALLOW_TOP_LEVEL_AWAIT,
                    )
                    _code_cache.set(cache_key, code)
            else:
                code = compile(
                    source=source,
                    filename="<runtime>",
                    mode="exec",
                    flags=ast.PyCF_ALLOW_TOP_LEVEL_AWAIT,
                )
            
            coro = eval(code, self._globals)
            if coro is not None:
                await coro
                
        except Exception:
            tb = traceback.format_exc()
            if 'File "<runtime>"' in tb:
                error = tb[tb.find('File "<runtime>"'):]
            else:
                error = tb
                
        return PythonExecResult(prints=self._get_prints(), error=error)

    def _get_prints(self) -> List[str]:
        prints = self._prints.copy()
        self._prints.clear()
        return prints

    def get_output(self) -> Any:
        return self._globals.get("output")
