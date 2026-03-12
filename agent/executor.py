import asyncio
import re
import logging
from types import SimpleNamespace
from pathlib import Path
from jinja2 import Template
from .models import IntentResult, IntentIO, PythonExecResult, CodeEngine, Executor, TokenUsage
from .runtime import PythonRuntime
from .handlers import IntentExecHandler

try:
    from .optimization.utils import timed_operation
    from .optimization.logging_utils import get_logger
    OPTIMIZATION_AVAILABLE = True
except ImportError:
    OPTIMIZATION_AVAILABLE = False

if OPTIMIZATION_AVAILABLE:
    logger = get_logger(__name__)
else:
    logger = logging.getLogger(__name__)

def extract_valid_python(response: str) -> str:
    """Extract python code from markdown blocks if present"""
    pattern = r"```python\s*([\s\S]*?)\s*```"
    matches = re.findall(pattern, response)
    if matches:
        return matches[-1]
    
    pattern_generic = r"```\s*([\s\S]*?)\s*```"
    matches_generic = re.findall(pattern_generic, response)
    if matches_generic:
        return matches_generic[-1]
    
    thought_pattern = r"<thought>([\s\S]*?)</thought>"
    thought_matches = re.findall(thought_pattern, response)
    if thought_matches:
        return ""
        
    return response

def extract_thought(response: str) -> str:
    """Extract thought section from response"""
    pattern = r"<thought>([\s\S]*?)</thought>"
    matches = re.findall(pattern, response)
    if matches:
        return matches[-1].strip()
    return "No thought provided"

class IntentExecutor(Executor):
    def __init__(
        self,
        intent,
        engine: CodeEngine,
        handler: IntentExecHandler,
        max_iterations: int = 30
    ):
        self._intent = intent
        self._engine = engine
        self._handler = handler
        self._max_iterations = max_iterations

    def _build_feedback(self, exec_result: PythonExecResult) -> str:
        feedback_template_path = Path(__file__).parent / "prompts" / "feedback.xml"
        
        output_status = "No output produced yet."
        
        if exec_result.error and exec_result.error != "None":
            error_msg = exec_result.error.strip()
            if "NameError: name 'output' is not defined" in error_msg:
                error_msg += "\n\n[System Hint]: You forgot to assign the result to the global variable `output`. Please ensure that your final result is assigned to `output = ...`"
            elif "AttributeError" in error_msg:
                error_msg += "\n\n[System Hint]: Check the tool return structure. Use `print(result)` to debug the exact structure of the returned data."
            elif "TypeError" in error_msg:
                error_msg += "\n\n[System Hint]: Check the data types of your inputs. Ensure you're passing the correct parameters to tools."
            elif "KeyError" in error_msg:
                error_msg += "\n\n[System Hint]: The expected key is missing from a dictionary. Check the tool documentation for the correct return structure."
            elif "TimeoutError" in error_msg:
                error_msg += "\n\n[System Hint]: The operation timed out. Try reducing the count parameter or increasing the interval between requests."
            elif "NameError: name 'tools' is not defined" in error_msg:
                error_msg += "\n\n[System Hint]: Use the pre-defined `tools` object to call all tools, e.g., `tools.attack()` instead of `attack()`"
            elif "NameError: name 'session' is not defined" in error_msg:
                error_msg += "\n\n[System Hint]: For multi-step attacks, you need to create a session first using `session = tools.create_session()`"
        else:
            error_msg = "None"
            
        if feedback_template_path.exists():
            feedback_template = Template(feedback_template_path.read_text())
            feedback = feedback_template.render(
                prints="\n".join(exec_result.prints),
                error=error_msg
            )
        else:
            feedback = f"Output:\n{str(exec_result.prints)}\nError:\n{error_msg}"
            
        feedback += "\n\n[Instruction]: If the previous step failed or returned 'success: False', adjust your strategy in the next step. Do not repeat the same action."
        
        return feedback

    def _build_runtime_context(self, tools, input_obj, output_cls) -> str:
        template_path = Path(__file__).parent / "prompts" / "runtime_context.xml"
        if not template_path.exists():
            return "Runtime Context: tools, input, output available."
            
        tool_list = []
        for name, tool in vars(tools).items():
            doc = getattr(tool, "__doc__", "No description")
            tool_list.append({"name": name, "desc": doc})
            
        input_schema = input_obj.model_json_schema() if input_obj else {}
        
        template = Template(template_path.read_text())
        return template.render(
            input_model_name=type(input_obj).__name__,
            output_model_name=output_cls.__name__,
            input_schema=input_schema,
            output_schema=output_cls.model_json_schema(),
            tools=tool_list
        )

    async def run(self) -> IntentResult:
        self._handler.on_start(self._intent)

        tools_dict = {}
        for tool in self._intent._tools:
            if isinstance(tool, tuple):
                obj, name, desc = tool
                if name in tools_dict:
                    raise ValueError(f"Tool name conflict: {name}")
                tools_dict[name] = obj
            else:
                tools_dict[tool.__name__] = tool
        tools = SimpleNamespace(**tools_dict)

        if 'create_session' not in tools_dict:
            from .tools import create_session
            tools_dict['create_session'] = create_session
            tools = SimpleNamespace(**tools_dict)

        input_obj = self._intent._input
        output_cls = self._intent._output
        
        runtime = PythonRuntime(input_obj, tools, output_cls)

        feedback = "start"
        
        runtime_ctx = self._build_runtime_context(tools, input_obj, output_cls)
        self._engine.configure(self._intent._build_ir(), runtime_ctx)
        
        output = None
        previous_tool_results = []
        strategy_history = []
        
        for step in range(self._max_iterations):
            if OPTIMIZATION_AVAILABLE:
                with timed_operation(f"agent_step_{step}"):
                    return await self._execute_step(
                        step, runtime, tools, feedback, 
                        previous_tool_results, strategy_history
                    )
            else:
                return await self._execute_step(
                    step, runtime, tools, feedback,
                    previous_tool_results, strategy_history
                )
        
        e = RuntimeError(f"Intent execution failed: no result produced after {self._max_iterations} iterations")
        self._handler.on_failed(e)
        raise e

    async def _execute_step(
        self, step: int, runtime: PythonRuntime, tools: SimpleNamespace,
        feedback: str, previous_tool_results: list, strategy_history: list
    ) -> IntentResult:
        """Execute a single step (extracted for optimization)"""
        logger.info(f"Agent Step {step+1}/{self._max_iterations}")
        
        code_response = self._engine.request(feedback)
        self._handler.on_code_response(step, code_response)
        
        thought = extract_thought(code_response)
        logger.info(f"Agent Thought: {thought}")
        
        valid_code = extract_valid_python(code_response)
        
        if not valid_code.strip():
            logger.warning("No valid Python code generated, requesting again with feedback")
            feedback = "No valid Python code was generated. Please provide a complete Python code solution."
            return await self._execute_step(
                step + 1, runtime, tools, feedback,
                previous_tool_results, strategy_history
            )
        
        exec_result = await runtime.exec(valid_code)
        
        if hasattr(exec_result, 'tool_results'):
            previous_tool_results.extend(exec_result.tool_results)
            for result in exec_result.tool_results:
                if isinstance(result, dict) and result.get('tool_name') == 'attack':
                    strategy = result.get('strategy', 'unknown')
                    strategy_history.append((strategy, result.get('success', False)))
        
        feedback = self._build_feedback(exec_result)
        
        if previous_tool_results:
            failed_calls = [r for r in previous_tool_results if isinstance(r, dict) and r.get('success') is False]
            successful_calls = [r for r in previous_tool_results if isinstance(r, dict) and r.get('success') is True]
            
            total_calls = len(previous_tool_results)
            success_rate = len(successful_calls) / total_calls if total_calls > 0 else 0
            
            if failed_calls:
                feedback += f"\n\n[Dynamic Strategy Hint]: {len(failed_calls)} tools failed in previous steps. Success rate so far: {success_rate:.2%}. Consider trying a different approach."
                
                for failed_call in failed_calls:
                    tool_name = failed_call.get('tool_name', 'unknown')
                    if tool_name == 'attack':
                        attack_strategies = [s[0] for s in strategy_history if s[0] != 'unknown']
                        if attack_strategies:
                            tried_strategies = list(set(attack_strategies))
                            feedback += f"\n[Attack Strategy Hint]: You've tried strategies: {', '.join(tried_strategies)}. "
                            
                            available_strategies = ['single', 'multi-round', 'batch', 'stratasword', 'ascii_smuggling', 'context_manipulation']
                            untried_strategies = [s for s in available_strategies if s not in tried_strategies]
                            if untried_strategies:
                                feedback += f"Try: {', '.join(untried_strategies)}."
                            else:
                                feedback += "Try adjusting parameters like count, interval, or combining strategies."
                        else:
                            feedback += "\n[Attack Strategy Hint]: Try a different attack strategy (e.g., 'multi-round', 'stratasword', 'ascii_smuggling', or 'context_manipulation')."
                    elif tool_name == 'regression_test':
                        feedback += "\n[Regression Test Hint]: Check if the regression test case exists and is valid. Use `tools.list_regression_cases()` to see available cases."
                    elif tool_name == 'get_system_status':
                        feedback += "\n[System Status Hint]: If system status shows issues, try reducing the workload or checking connectivity."
            
            if successful_calls:
                feedback += f"\n\n[Success Analysis]: {len(successful_calls)} tools succeeded. Consider building upon these successful approaches."
                
                successful_strategies = [r.get('strategy', 'unknown') for r in successful_calls if isinstance(r, dict) and r.get('success') is True]
                if successful_strategies and 'unknown' not in successful_strategies:
                    feedback += f"\n[Success Strategy Hint]: Successful strategies: {', '.join(successful_strategies)}. Consider repeating or enhancing these approaches."
        
        self._handler.on_exec_result(step, exec_result, feedback)

        output = runtime.get_output()
        if output:
            self._handler.on_output(step, output)
            
            if not isinstance(output, output_cls) and not isinstance(output, IntentIO):
                if isinstance(output, dict):
                    try:
                        output = output_cls(**output)
                    except Exception as e:
                        logger.error(f"Failed to cast output to {output_cls.__name__}: {e}")
                        raise RuntimeError(f"Output validation failed: expected {output_cls.__name__}, got {type(output).__name__}") from e
            
            result = IntentResult(
                output=output,
                usage=TokenUsage(
                    input_tokens=self._engine.input_tokens,
                    output_tokens=self._engine.output_tokens,
                    total_tokens=self._engine.total_tokens
                )
            )
            self._handler.on_completed(result)
            return result
        
        return await self._execute_step(
            step + 1, runtime, tools, feedback,
            previous_tool_results, strategy_history
        )

    def run_sync(self) -> IntentResult:
        return asyncio.run(self.run())
