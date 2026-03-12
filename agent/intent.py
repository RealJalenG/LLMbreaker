"""
Intent模块 - 定义和执行Intent的核心模块

该模块负责构建Intent对象，定义任务目标、上下文、工具和输出格式，并执行Intent任务。
"""

from typing import Type, Callable, Tuple, Any, List
from .models import IntentIO, Executor, IntentResult, EngineFactory
from .engines.llm_engine import LLMEngineFactory
from .executor import IntentExecutor
from .handlers import IntentExecHandler

class Intent:
    _engine_factory: EngineFactory | None = None

    def __init__(self):
        self._goal: str = None
        self._ctxs: List[str] = []
        self._tools: List[Callable | Tuple[object, str, str]] = []
        self._input: IntentIO | None = None
        self._how: str = "No specified"
        self._rules: List[str] = []
        self._output: Type[IntentIO] | None = None

    @classmethod
    def set_engine_factory(cls, factory: EngineFactory):
        cls._engine_factory = factory

    def goal(self, goal: str) -> "Intent":
        self._goal = goal
        return self

    def ctxs(self, ctxs: List[str]) -> "Intent":
        self._ctxs = ctxs
        return self

    def tools(self, tools: List[Callable | Tuple[object, str, str]]) -> "Intent":
        self._tools = tools
        return self

    def input(self, input_obj: IntentIO | None = None, **field_definitions) -> "Intent":
        if input_obj is not None:
            self._input = input_obj
        else:
            # Dynamically create Pydantic model
            from pydantic import create_model
            DynamicInput = create_model("DynamicInput", **{k: (Any, ...) for k, v in field_definitions.items()})
            self._input = DynamicInput(**field_definitions)
        return self

    def how(self, how: str) -> "Intent":
        self._how = how
        return self

    def rules(self, rules: List[str]) -> "Intent":
        # Add default session management rule if not already present
        session_rule = "Session Management: For multi-step attacks, use create_session() first and pass session_id to all subsequent tool calls."
        if session_rule not in rules:
            rules.append(session_rule)
        self._rules = rules
        return self

    def output(self, output: Type[IntentIO] | None = None) -> "Intent":
        self._output = output
        return self
    
    def _validate(self):
        if not self._goal:
            raise ValueError("Goal is required for Intent")
        if not self._output:
            raise ValueError("Output model is required for Intent")

    def _build_ir(self) -> dict:
        return {
            "goal": self._goal,
            "ctxs": self._ctxs,
            "how": self._how,
            "rules": self._rules
        }

    def compile(
        self,
        engine_factory: EngineFactory | None = None,
        max_iterations: int = 30,
        verbose: bool = True
    ) -> Executor:
        self._validate()

        if engine_factory is not None:
            engine = engine_factory.create()
        elif self._engine_factory is not None:
            engine = self._engine_factory.create()
        else:
            # Default to our LLM engine
            engine = LLMEngineFactory().create()

        return IntentExecutor(
            self,
            engine=engine,
            handler=IntentExecHandler(verbose=verbose),
            max_iterations=max_iterations
        )

    async def run(self) -> IntentResult:
        return await self.compile().run()

    def run_sync(self) -> IntentResult:
        return self.compile().run_sync()
