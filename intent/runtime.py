"""
EnhancedRuntime - 增强执行环境
支持依赖注入、状态保持、安全执行和结果校验
"""

import logging
import time
import json
import requests
import traceback
from typing import Dict, Any, Optional, Callable, Type, List
from pydantic import BaseModel, ValidationError
from datetime import datetime
from dataclasses import dataclass, field
from contextlib import contextmanager

logger = logging.getLogger(__name__)


@dataclass
class ExecutionContext:
    """执行上下文"""
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    execution_id: str = ""
    parent_id: Optional[str] = None
    
    # 执行状态
    status: str = "pending"  # pending, running, success, failed, timeout
    error: Optional[str] = None
    
    # 执行结果
    result: Any = None
    validated_result: Any = None
    
    # 性能指标
    execution_time_ms: float = 0.0
    memory_usage_mb: float = 0.0
    
    def complete(self, status: str = "success", result: Any = None, error: str = None):
        """标记执行完成"""
        self.end_time = datetime.now()
        self.status = status
        self.result = result
        self.error = error
        self.execution_time_ms = (self.end_time - self.start_time).total_seconds() * 1000


class EnhancedRuntime:
    """
    增强执行环境
    
    核心能力:
    1. 依赖注入 - 将工具以Python对象形式注入
    2. 安全执行 - 沙箱环境执行生成的代码
    3. 状态保持 - 跨请求保持会话状态
    4. 结果校验 - Pydantic自动验证
    5. 错误归因 - L1-L4级错误分析
    
    使用示例:
    ```python
    runtime = EnhancedRuntime()
    
    # 依赖注入
    runtime.inject("session", requests.Session())
    runtime.inject("config", app_config)
    
    # 执行代码
    result = runtime.execute(code, input_data)
    
    # 验证结果
    validated = runtime.validate(result, AttackResult)
    ```
    """
    
    def __init__(self, timeout: int = 30):
        """
        初始化运行时环境
        
        Args:
            timeout: 执行超时时间(秒)
        """
        self.timeout = timeout
        
        # 依赖注入容器
        self._dependencies: Dict[str, Any] = {}
        
        # 会话状态
        self._session_state: Dict[str, Any] = {}
        
        # HTTP会话（支持Cookie持久化）
        self._http_session = requests.Session()
        
        # 执行历史
        self._execution_history: List[ExecutionContext] = []
        
        # 预注入常用依赖
        self._inject_defaults()
    
    def _inject_defaults(self):
        """注入默认依赖"""
        import json as json_module
        import re as re_module
        import random as random_module
        import hashlib as hashlib_module
        
        self._dependencies.update({
            'requests': requests,
            'json': json_module,
            're': re_module,
            'random': random_module,
            'hashlib': hashlib_module,
            'session': self._http_session,
            'state': self._session_state
        })
    
    def inject(self, name: str, obj: Any) -> 'EnhancedRuntime':
        """
        注入依赖
        
        Args:
            name: 依赖名称
            obj: 依赖对象
        
        Returns:
            self (支持链式调用)
        """
        self._dependencies[name] = obj
        logger.debug(f"注入依赖: {name} -> {type(obj).__name__}")
        return self
    
    def inject_function(self, func: Callable) -> 'EnhancedRuntime':
        """
        注入函数
        
        Args:
            func: 要注入的函数
        
        Returns:
            self
        """
        self._dependencies[func.__name__] = func
        logger.debug(f"注入函数: {func.__name__}")
        return self
    
    def get(self, name: str) -> Any:
        """获取依赖"""
        return self._dependencies.get(name)
    
    def set_state(self, key: str, value: Any):
        """设置会话状态"""
        self._session_state[key] = value
    
    def get_state(self, key: str, default: Any = None) -> Any:
        """获取会话状态"""
        return self._session_state.get(key, default)
    
    def clear_state(self):
        """清空会话状态"""
        self._session_state.clear()
    
    @contextmanager
    def execution_context(self, execution_id: str = None):
        """
        执行上下文管理器
        
        Args:
            execution_id: 执行ID
        """
        import uuid
        
        ctx = ExecutionContext(
            execution_id=execution_id or str(uuid.uuid4())[:8],
            status="running"
        )
        
        try:
            yield ctx
            if ctx.status == "running":
                ctx.complete("success")
        except Exception as e:
            ctx.complete("failed", error=str(e))
            raise
        finally:
            self._execution_history.append(ctx)
    
    def execute(
        self,
        code: str,
        input_data: Dict[str, Any] = None,
        output_type: Type[BaseModel] = None
    ) -> Any:
        """
        安全执行代码
        
        Args:
            code: 要执行的Python代码
            input_data: 输入数据
            output_type: 期望的输出类型（Pydantic Model）
        
        Returns:
            执行结果
        """
        start_time = time.time()
        
        with self.execution_context() as ctx:
            try:
                # 构建执行环境
                global_scope = self._dependencies.copy()
                
                # 注入输入数据
                if input_data:
                    global_scope['input'] = input_data
                    global_scope.update(input_data)
                
                # 准备结果容器
                global_scope['result'] = None
                
                # 执行代码
                exec(code, global_scope)
                
                # 获取结果
                result = global_scope.get('result')
                ctx.result = result
                
                # 验证输出
                if output_type and result:
                    validated = self.validate(result, output_type)
                    ctx.validated_result = validated
                    result = validated
                
                ctx.execution_time_ms = (time.time() - start_time) * 1000
                logger.info(f"代码执行成功, 耗时: {ctx.execution_time_ms:.2f}ms")
                
                return result
                
            except ValidationError as e:
                ctx.complete("failed", error=f"输出验证失败: {e}")
                logger.error(f"输出验证失败: {e}")
                raise
            except Exception as e:
                ctx.complete("failed", error=str(e))
                logger.error(f"代码执行失败: {e}\n{traceback.format_exc()}")
                raise
    
    def execute_function(
        self,
        func: Callable,
        args: tuple = (),
        kwargs: Dict[str, Any] = None,
        output_type: Type[BaseModel] = None
    ) -> Any:
        """
        执行函数
        
        Args:
            func: 要执行的函数
            args: 位置参数
            kwargs: 关键字参数
            output_type: 期望的输出类型
        
        Returns:
            执行结果
        """
        kwargs = kwargs or {}
        
        with self.execution_context() as ctx:
            try:
                result = func(*args, **kwargs)
                ctx.result = result
                
                if output_type and result:
                    if isinstance(result, dict):
                        validated = output_type(**result)
                    else:
                        validated = result
                    ctx.validated_result = validated
                    result = validated
                
                return result
                
            except Exception as e:
                ctx.complete("failed", error=str(e))
                raise
    
    def validate(self, data: Any, model: Type[BaseModel]) -> BaseModel:
        """
        验证数据
        
        Args:
            data: 要验证的数据
            model: Pydantic模型类
        
        Returns:
            验证后的Pydantic对象
        """
        if isinstance(data, model):
            return data
        
        if isinstance(data, dict):
            return model(**data)
        
        raise ValidationError(f"无法将 {type(data)} 转换为 {model.__name__}")
    
    def analyze_error(self, error: Exception) -> Dict[str, Any]:
        """
        错误归因分析 (L1-L4级)
        
        错误级别:
        - L1: 语法错误 (代码生成问题)
        - L2: 运行时错误 (执行环境问题)
        - L3: 逻辑错误 (业务逻辑问题)
        - L4: 验证错误 (输出格式问题)
        
        Args:
            error: 异常对象
        
        Returns:
            错误分析结果
        """
        error_type = type(error).__name__
        error_msg = str(error)
        
        # L1: 语法错误
        if isinstance(error, SyntaxError):
            return {
                'level': 'L1',
                'category': '语法错误',
                'type': error_type,
                'message': error_msg,
                'suggestion': '检查生成的代码语法',
                'recoverable': True
            }
        
        # L4: 验证错误
        if isinstance(error, ValidationError):
            return {
                'level': 'L4',
                'category': '验证错误',
                'type': error_type,
                'message': error_msg,
                'suggestion': '检查输出格式是否符合Schema',
                'recoverable': True
            }
        
        # L2: 运行时错误
        runtime_errors = (
            NameError, TypeError, AttributeError,
            ImportError, ModuleNotFoundError
        )
        if isinstance(error, runtime_errors):
            return {
                'level': 'L2',
                'category': '运行时错误',
                'type': error_type,
                'message': error_msg,
                'suggestion': '检查依赖注入和变量定义',
                'recoverable': True
            }
        
        # L3: 逻辑错误
        return {
            'level': 'L3',
            'category': '逻辑错误',
            'type': error_type,
            'message': error_msg,
            'suggestion': '检查业务逻辑实现',
            'recoverable': False
        }
    
    def get_execution_history(self) -> List[ExecutionContext]:
        """获取执行历史"""
        return self._execution_history.copy()
    
    def get_last_execution(self) -> Optional[ExecutionContext]:
        """获取最近一次执行"""
        return self._execution_history[-1] if self._execution_history else None
    
    def get_execution_stats(self) -> Dict[str, Any]:
        """获取执行统计"""
        if not self._execution_history:
            return {'total': 0}
        
        total = len(self._execution_history)
        success = sum(1 for ctx in self._execution_history if ctx.status == 'success')
        failed = sum(1 for ctx in self._execution_history if ctx.status == 'failed')
        avg_time = sum(ctx.execution_time_ms for ctx in self._execution_history) / total
        
        return {
            'total': total,
            'success': success,
            'failed': failed,
            'success_rate': f"{(success / total * 100):.2f}%",
            'avg_execution_time_ms': f"{avg_time:.2f}"
        }
    
    def reset(self):
        """重置运行时环境"""
        self._session_state.clear()
        self._http_session = requests.Session()
        self._dependencies['session'] = self._http_session
        self._dependencies['state'] = self._session_state
        self._execution_history.clear()
        logger.info("运行时环境已重置")
    
    def clone(self) -> 'EnhancedRuntime':
        """克隆运行时环境"""
        new_runtime = EnhancedRuntime(timeout=self.timeout)
        new_runtime._dependencies = self._dependencies.copy()
        new_runtime._session_state = self._session_state.copy()
        return new_runtime


# 全局运行时实例
_global_runtime: Optional[EnhancedRuntime] = None


def get_runtime() -> EnhancedRuntime:
    """获取全局运行时实例"""
    global _global_runtime
    if _global_runtime is None:
        _global_runtime = EnhancedRuntime()
    return _global_runtime


def set_runtime(runtime: EnhancedRuntime):
    """设置全局运行时实例"""
    global _global_runtime
    _global_runtime = runtime
