"""
错误处理与异常恢复模块

提供：
- 高级异常处理
- 重试机制
- 断路器模式
- 错误分类与报告
- 恢复策略
"""

import asyncio
import functools
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple, Type, Union
from datetime import datetime, timedelta
import traceback
import threading

logger = logging.getLogger(__name__)


class ErrorSeverity(Enum):
    """错误严重等级"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ErrorCategory(Enum):
    """错误类别"""
    VALIDATION = "validation"
    EXECUTION = "execution"
    TIMEOUT = "timeout"
    NETWORK = "network"
    RESOURCE = "resource"
    SECURITY = "security"
    UNKNOWN = "unknown"


@dataclass
class ErrorInfo:
    """错误信息"""
    message: str
    category: ErrorCategory
    severity: ErrorSeverity
    timestamp: datetime = field(default_factory=datetime.now)
    details: Dict[str, Any] = field(default_factory=dict)
    stack_trace: Optional[str] = None
    context: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "message": self.message,
            "category": self.category.value,
            "severity": self.severity.value,
            "timestamp": self.timestamp.isoformat(),
            "details": self.details,
            "stack_trace": self.stack_trace,
            "context": self.context
        }


class ErrorClassifier:
    """错误分类器"""
    
    _patterns: Dict[ErrorCategory, List[str]] = {
        ErrorCategory.VALIDATION: ["value error", "validation", "invalid", "type error"],
        ErrorCategory.EXECUTION: ["execution", "runtime", "attribute error", "key error"],
        ErrorCategory.TIMEOUT: ["timeout", "timed out"],
        ErrorCategory.NETWORK: ["connection", "network", "http", "ssl"],
        ErrorCategory.RESOURCE: ["memory", "cpu", "resource", "disk", "out of"],
        ErrorCategory.SECURITY: ["permission", "denied", "unauthorized", "forbidden"]
    }
    
    @classmethod
    def classify(cls, error: Exception) -> ErrorCategory:
        error_msg = str(error).lower()
        error_type = type(error).__name__.lower()
        
        for category, patterns in cls._patterns.items():
            for pattern in patterns:
                if pattern in error_msg or pattern in error_type:
                    return category
        return ErrorCategory.UNKNOWN
    
    @classmethod
    def get_severity(cls, error: Exception) -> ErrorSeverity:
        """根据错误类型判断严重程度"""
        error_type = type(error).__name__
        
        critical_types = {
            "MemoryError", "KeyboardInterrupt", "SystemExit"
        }
        high_types = {
            "TimeoutError", "ConnectionError", "OSError"
        }
        
        if error_type in critical_types:
            return ErrorSeverity.CRITICAL
        elif error_type in high_types or "security" in str(error).lower():
            return ErrorSeverity.HIGH
        elif "validation" in str(error).lower() or "value" in str(error).lower():
            return ErrorSeverity.LOW
        return ErrorSeverity.MEDIUM


class CircuitBreaker:
    """断路器模式实现"""
    
    _default_config = {
        "failure_threshold": 5,
        "recovery_timeout": 60.0,
        "half_open_requests": 3
    }
    
    def __init__(self, name: str, **config):
        self.name = name
        self._config = {**self._default_config, **config}
        self._state = "closed"
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time = None
        self._lock = threading.Lock()
        self._half_open_counter = 0
    
    @property
    def state(self) -> str:
        return self._state
    
    def record_success(self):
        with self._lock:
            if self._state == "half-open":
                self._success_count += 1
                self._half_open_counter += 1
                if self._half_open_counter >= self._config["half_open_requests"]:
                    self._state = "closed"
                    self._failure_count = 0
                    self._success_count = 0
                    self._half_open_counter = 0
                    logger.info(f"Circuit breaker '{self.name}' closed (recovered)")
    
    def record_failure(self):
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = datetime.now()
            
            if self._state == "half-open":
                self._state = "open"
                self._half_open_counter = 0
                logger.warning(f"Circuit breaker '{self.name}' opened after half-open failure")
            elif self._failure_count >= self._config["failure_threshold"]:
                self._state = "open"
                logger.warning(f"Circuit breaker '{self.name}' opened after {self._failure_count} failures")
    
    def allow_request(self) -> bool:
        with self._lock:
            if self._state == "closed":
                return True
            elif self._state == "open":
                if self._last_failure_time and \
                   datetime.now() - self._last_failure_time > timedelta(seconds=self._config["recovery_timeout"]):
                    self._state = "half-open"
                    self._half_open_counter = 0
                    logger.info(f"Circuit breaker '{self.name}' half-open (attempting recovery)")
                    return True
                return False
            elif self._state == "half-open":
                return self._half_open_counter < self._config["half_open_requests"]
            return False
    
    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "name": self.name,
                "state": self._state,
                "failure_count": self._failure_count,
                "success_count": self._success_count,
                "half_open_counter": self._half_open_counter,
                "config": self._config
            }
    
    def reset(self):
        with self._lock:
            self._state = "closed"
            self._failure_count = 0
            self._success_count = 0
            self._half_open_counter = 0
            self._last_failure_time = None


class RetryManager:
    """重试管理器"""
    
    def __init__(self, max_retries: int = 3, base_delay: float = 0.1, max_delay: float = 10.0, backoff: float = 2.0):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.backoff = backoff
        self._attempts: Dict[str, List[datetime]] = defaultdict(list)
        self._lock = threading.Lock()
    
    def should_retry(self, operation_id: str, exception: Exception) -> bool:
        with self._lock:
            attempts = self._attempts[operation_id]
            if len(attempts) >= self.max_retries:
                return False
            return True
    
    def get_delay(self, operation_id: str) -> float:
        with self._lock:
            attempts = len(self._attempts[operation_id])
            delay = min(self.base_delay * (self.backoff ** attempts), self.max_delay)
            return delay
    
    def record_attempt(self, operation_id: str):
        with self._lock:
            self._attempts[operation_id].append(datetime.now())
    
    def record_success(self, operation_id: str):
        with self._lock:
            if operation_id in self._attempts:
                del self._attempts[operation_id]
    
    def reset(self, operation_id: str = None):
        with self._lock:
            if operation_id:
                self._attempts.pop(operation_id, None)
            else:
                self._attempts.clear()
    
    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "total_operations": len(self._attempts),
                "pending_retries": sum(len(v) for v in self._attempts.values())
            }


class ErrorHandler:
    """统一错误处理器"""
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._error_history: List[ErrorInfo] = []
        self._error_counts: Dict[str, int] = defaultdict(int)
        self._handlers: Dict[ErrorCategory, List[Callable]] = defaultdict(list)
        self._lock = threading.Lock()
        self._circuit_breakers: Dict[str, CircuitBreaker] = {}
        self._retry_manager = RetryManager()
    
    def register_handler(self, category: ErrorCategory, handler: Callable):
        """注册错误处理器"""
        with self._lock:
            self._handlers[category].append(handler)
    
    def get_circuit_breaker(self, name: str, **config) -> CircuitBreaker:
        """获取或创建断路器"""
        with self._lock:
            if name not in self._circuit_breakers:
                self._circuit_breakers[name] = CircuitBreaker(name, **config)
            return self._circuit_breakers[name]
    
    def handle(self, error: Exception, context: Dict[str, Any] = None) -> ErrorInfo:
        """处理错误"""
        category = ErrorClassifier.classify(error)
        severity = ErrorClassifier.get_severity(error)
        
        error_info = ErrorInfo(
            message=str(error),
            category=category,
            severity=severity,
            stack_trace=traceback.format_exc(),
            details={
                "error_type": type(error).__name__,
                "error_module": type(error).__module__
            },
            context=context or {}
        )
        
        with self._lock:
            self._error_history.append(error_info)
            self._error_counts[category.value] += 1
            
            while len(self._error_history) > 1000:
                self._error_history.pop(0)
        
        with self._lock:
            handlers = self._handlers.get(category, [])
        for handler in handlers:
            try:
                handler(error_info)
            except Exception as e:
                logger.error(f"Error in error handler: {e}")
        
        return error_info
    
    def execute_with_retry(
        self,
        operation: Callable,
        operation_id: str = None,
        context: Dict[str, Any] = None,
        retry_on: Tuple[Type[Exception], ...] = None
    ):
        """带重试的操作执行"""
        op_id = operation_id or f"op_{id(operation)}"
        retry_on = retry_on or (Exception,)
        
        self._retry_manager.record_attempt(op_id)
        
        last_error = None
        for attempt in range(self._retry_manager.max_retries + 1):
            try:
                result = operation()
                self._retry_manager.record_success(op_id)
                return result
            except retry_on as e:
                last_error = e
                if not self._retry_manager.should_retry(op_id, e):
                    logger.warning(f"Max retries exceeded for operation {op_id}")
                    break
                delay = self._retry_manager.get_delay(op_id)
                logger.debug(f"Retrying operation {op_id} in {delay:.2f}s (attempt {attempt + 1})")
                time.sleep(delay)
        
        self.handle(last_error, context)
        raise last_error
    
    async def execute_async_with_retry(
        self,
        operation: Callable,
        operation_id: str = None,
        context: Dict[str, Any] = None,
        retry_on: Tuple[Type[Exception], ...] = None
    ):
        """带重试的异步操作执行"""
        op_id = operation_id or f"op_{id(operation)}"
        retry_on = retry_on or (Exception,)
        
        self._retry_manager.record_attempt(op_id)
        
        last_error = None
        for attempt in range(self._retry_manager.max_retries + 1):
            try:
                result = await operation()
                self._retry_manager.record_success(op_id)
                return result
            except retry_on as e:
                last_error = e
                if not self._retry_manager.should_retry(op_id, e):
                    logger.warning(f"Max retries exceeded for operation {op_id}")
                    break
                delay = self._retry_manager.get_delay(op_id)
                await asyncio.sleep(delay)
        
        self.handle(last_error, context)
        raise last_error
    
    def execute_with_circuit_breaker(
        self,
        operation: Callable,
        circuit_breaker_name: str = "default",
        **circuit_config
    ) -> Any:
        """带断路器的操作执行"""
        cb = self.get_circuit_breaker(circuit_breaker_name, **circuit_config)
        
        if not cb.allow_request():
            raise CircuitOpenError(f"Circuit breaker '{circuit_breaker_name}' is open")
        
        try:
            result = operation()
            cb.record_success()
            return result
        except Exception as e:
            cb.record_failure()
            raise
    
    def get_error_stats(self) -> Dict[str, Any]:
        """获取错误统计"""
        with self._lock:
            return {
                "total_errors": len(self._error_history),
                "error_counts": dict(self._error_counts),
                "recent_errors": [e.to_dict() for e in list(self._error_history)[-10:]],
                "circuit_breakers": {
                    name: cb.get_stats() 
                    for name, cb in self._circuit_breakers.items()
                }
            }
    
    def clear_history(self):
        """清除错误历史"""
        with self._lock:
            self._error_history.clear()
            self._error_counts.clear()


class CircuitOpenError(Exception):
    """断路器打开异常"""
    pass


def with_error_handling(
    fallback: Callable = None,
    error_types: Tuple[Type[Exception], ...] = (Exception,),
    reraise: bool = True
):
    """错误处理装饰器"""
    def decorator(func: Callable):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            handler = ErrorHandler()
            try:
                return func(*args, **kwargs)
            except error_types as e:
                error_info = handler.handle(e, {"function": func.__name__})
                if fallback:
                    return fallback(error_info)
                if reraise:
                    raise
                return None
        return wrapper
    return decorator


@dataclass
class RecoveryStrategy:
    """恢复策略"""
    name: str
    condition: Callable[[ErrorInfo], bool]
    action: Callable[[], None]
    max_attempts: int = 3
    delay_between_attempts: float = 1.0


class RecoveryManager:
    """恢复管理器"""
    
    def __init__(self):
        self._strategies: List[RecoveryStrategy] = []
        self._lock = threading.Lock()
    
    def add_strategy(self, strategy: RecoveryStrategy):
        """添加恢复策略"""
        with self._lock:
            self._strategies.append(strategy)
    
    def execute_recovery(self, error_info: ErrorInfo) -> bool:
        """执行恢复"""
        with self._lock:
            strategies = list(self._strategies)
        
        for strategy in strategies:
            if strategy.condition(error_info):
                logger.info(f"Executing recovery strategy: {strategy.name}")
                for attempt in range(strategy.max_attempts):
                    try:
                        strategy.action()
                        logger.info(f"Recovery strategy '{strategy.name}' succeeded")
                        return True
                    except Exception as e:
                        logger.warning(f"Recovery attempt {attempt + 1} failed: {e}")
                        time.sleep(strategy.delay_between_attempts)
                logger.error(f"All recovery attempts failed for strategy: {strategy.name}")
        return False
