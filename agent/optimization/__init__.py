"""
优化模块 - 提供系统优化功能

包含：
- utils.py: 内存池、缓存、性能监控等工具
- error_handler.py: 错误处理与异常恢复
- logging_utils.py: 日志记录与调试功能
"""

from .utils import (
    MemoryPool,
    StringPool,
    LRUCacheWithStats,
    ResourceManager,
    PerformanceMonitor,
    AsyncPool,
    ThreadPool,
    cached_with_stats,
    retry_on_failure,
    timed_operation
)

from .error_handler import (
    ErrorSeverity,
    ErrorCategory,
    ErrorInfo,
    ErrorClassifier,
    CircuitBreaker,
    RetryManager,
    ErrorHandler,
    RecoveryManager,
    RecoveryStrategy,
    CircuitOpenError,
    with_error_handling
)

from .logging_utils import (
    StructuredLogger,
    DebugContext,
    PerformanceTracer,
    LogCollector,
    log_operation,
    setup_logging,
    get_logger,
    LogLevel
)

__all__ = [
    # Utils
    "MemoryPool",
    "StringPool",
    "LRUCacheWithStats",
    "ResourceManager",
    "PerformanceMonitor",
    "AsyncPool",
    "ThreadPool",
    "cached_with_stats",
    "retry_on_failure",
    "timed_operation",
    
    # Error Handler
    "ErrorSeverity",
    "ErrorCategory",
    "ErrorInfo",
    "ErrorClassifier",
    "CircuitBreaker",
    "RetryManager",
    "ErrorHandler",
    "RecoveryManager",
    "RecoveryStrategy",
    "CircuitOpenError",
    "with_error_handling",
    
    # Logging
    "StructuredLogger",
    "DebugContext",
    "PerformanceTracer",
    "LogCollector",
    "log_operation",
    "setup_logging",
    "get_logger",
    "LogLevel"
]
