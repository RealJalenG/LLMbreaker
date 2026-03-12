"""
日志记录与调试功能模块

提供：
- 结构化日志
- 日志级别控制
- 调试工具
- 性能追踪
- 日志聚合
"""

import functools
import json
import logging
import os
import sys
import time
from contextlib import contextmanager
from datetime import datetime
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Union
from pathlib import Path
import threading
import traceback

logger = logging.getLogger(__name__)


class LogLevel:
    """日志级别常量"""
    TRACE = 5
    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40
    CRITICAL = 50


class StructuredLogger:
    """结构化日志记录器"""
    
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
        self._loggers: Dict[str, logging.Logger] = {}
        self._handlers: List[logging.Handler] = []
        self._config = {
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            "date_format": "%Y-%m-%d %H:%M:%S",
            "json_format": False,
            "log_dir": "logs",
            "max_file_size": 10 * 1024 * 1024,  # 10MB
            "backup_count": 5
        }
        self._lock = threading.Lock()
        self._performance_records: List[Dict] = []
    
    def configure(
        self,
        log_dir: str = "logs",
        level: int = logging.INFO,
        json_format: bool = False,
        console_output: bool = True,
        file_output: bool = True
    ):
        """配置日志系统"""
        self._config.update({
            "log_dir": log_dir,
            "level": level,
            "json_format": json_format,
            "console_output": console_output,
            "file_output": file_output
        })
        
        # 创建日志目录
        if file_output:
            Path(log_dir).mkdir(parents=True, exist_ok=True)
    
    def get_logger(self, name: str, log_file: str = None) -> logging.Logger:
        """获取日志记录器"""
        with self._lock:
            if name in self._loggers:
                return self._loggers[name]
            
            logger_instance = logging.getLogger(name)
            logger_instance.setLevel(self._config.get("level", logging.INFO))
            logger_instance.propagate = False
            
            # 清除现有处理器
            logger_instance.handlers.clear()
            
            # 控制台处理器
            if self._config.get("console_output", True):
                console_handler = logging.StreamHandler()
                formatter = self._create_formatter()
                console_handler.setFormatter(formatter)
                logger_instance.addHandler(console_handler)
            
            # 文件处理器
            if self._config.get("file_output", True) or log_file:
                log_path = log_file or f"{self._config['log_dir']}/{name}.log"
                file_handler = logging.FileHandler(log_path, encoding="utf-8")
                formatter = self._create_formatter()
                file_handler.setFormatter(formatter)
                logger_instance.addHandler(file_handler)
            
            self._loggers[name] = logger_instance
            return logger_instance
    
    def _create_formatter(self) -> logging.Formatter:
        """创建格式化器"""
        if self._config.get("json_format", False):
            return JSONFormatter()
        return logging.Formatter(
            fmt=self._config.get("format", "%(asctime)s - %(name)s - %(levelname)s - %(message)s"),
            datefmt=self._config.get("date_format", "%Y-%m-%d %H:%M:%S")
        )
    
    def log_performance(self, operation: str, duration: float, metadata: Dict = None):
        """记录性能日志"""
        record = {
            "timestamp": datetime.now().isoformat(),
            "operation": operation,
            "duration_ms": duration * 1000,
            "metadata": metadata or {}
        }
        with self._lock:
            self._performance_records.append(record)
            # 保持记录数在合理范围内
            while len(self._performance_records) > 10000:
                self._performance_records.pop(0)
    
    def get_performance_stats(self, operation: str = None) -> Dict[str, Any]:
        """获取性能统计"""
        with self._lock:
            records = self._performance_records
        
        if operation:
            records = [r for r in records if r["operation"] == operation]
        
        if not records:
            return {"count": 0, "avg_ms": 0, "min_ms": 0, "max_ms": 0}
        
        durations = [r["duration_ms"] for r in records]
        return {
            "count": len(durations),
            "avg_ms": sum(durations) / len(durations),
            "min_ms": min(durations),
            "max_ms": max(durations),
            "total_ms": sum(durations)
        }
    
    def clear_performance_records(self):
        """清除性能记录"""
        with self._lock:
            self._performance_records.clear()


class JSONFormatter(logging.Formatter):
    """JSON 格式化器"""
    
    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "name": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        }
        
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        
        if hasattr(record, "extra_data"):
            log_entry.update(record.extra_data)
        
        return json.dumps(log_entry, ensure_ascii=False)


class DebugContext:
    """调试上下文管理器"""
    
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
        self._debug_sessions: Dict[str, Dict] = {}
        self._current_session = None
        self._lock = threading.Lock()
    
    def start_session(self, session_id: str = None) -> str:
        """启动调试会话"""
        sid = session_id or f"debug_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        with self._lock:
            self._debug_sessions[sid] = {
                "start_time": datetime.now(),
                "events": [],
                "metrics": {}
            }
            self._current_session = sid
        return sid
    
    def end_session(self) -> Optional[Dict]:
        """结束调试会话"""
        with self._lock:
            if self._current_session is None:
                return None
            session_id = self._current_session
            self._current_session = None
            return self._debug_sessions.pop(session_id, None)
    
    def log_event(self, event_type: str, data: Dict = None):
        """记录事件"""
        with self._lock:
            if self._current_session is None:
                return
            session = self._debug_sessions[self._current_session]
            session["events"].append({
                "timestamp": datetime.now().isoformat(),
                "type": event_type,
                "data": data or {}
            })
    
    def set_metric(self, key: str, value: Any):
        """设置指标"""
        with self._lock:
            if self._current_session is None:
                return
            session = self._debug_sessions[self._current_session]
            session["metrics"][key] = value
    
    def get_session_report(self) -> Optional[Dict]:
        """获取会话报告"""
        with self._lock:
            if self._current_session is None:
                return None
            return self._debug_sessions[self._current_session]
    
    def get_all_sessions(self) -> List[str]:
        """获取所有会话ID"""
        with self._lock:
            return list(self._debug_sessions.keys())


class PerformanceTracer:
    """性能追踪器"""
    
    def __init__(self):
        self._traces: List[Dict] = []
        self._lock = threading.Lock()
        self._enabled = True
    
    def trace(self, operation_name: str):
        """返回追踪上下文"""
        return self._TraceContext(operation_name, self)
    
    def start_span(self, name: str, parent: str = None) -> str:
        """开始追踪跨度"""
        span_id = f"span_{len(self._traces)}"
        with self._lock:
            self._traces.append({
                "span_id": span_id,
                "name": name,
                "parent": parent,
                "start_time": time.perf_counter(),
                "end_time": None,
                "events": []
            })
        return span_id
    
    def end_span(self, span_id: str):
        """结束追踪跨度"""
        with self._lock:
            for trace in self._traces:
                if trace["span_id"] == span_id:
                    trace["end_time"] = time.perf_counter()
                    break
    
    def add_event(self, span_id: str, event_name: str, data: Dict = None):
        """添加事件"""
        with self._lock:
            for trace in self._traces:
                if trace["span_id"] == span_id:
                    trace["events"].append({
                        "name": event_name,
                        "timestamp": time.perf_counter(),
                        "data": data or {}
                    })
                    break
    
    def get_trace_tree(self) -> List[Dict]:
        """获取追踪树"""
        with self._lock:
            return list(self._traces)
    
    def clear_traces(self):
        """清除追踪"""
        with self._lock:
            self._traces.clear()
    
    def get_stats(self) -> Dict[str, Any]:
        """获取统计"""
        with self._lock:
            completed = [t for t in self._traces if t["end_time"]]
            if not completed:
                return {"total_spans": 0}
            
            durations = [(t["end_time"] - t["start_time"]) * 1000 for t in completed]
            return {
                "total_spans": len(self._traces),
                "completed_spans": len(completed),
                "avg_duration_ms": sum(durations) / len(durations),
                "max_duration_ms": max(durations),
                "min_duration_ms": min(durations)
            }
    
    class _TraceContext:
        def __init__(self, name: str, tracer: 'PerformanceTracer'):
            self._name = name
            self._tracer = tracer
            self._span_id = None
        
        def __enter__(self):
            self._span_id = self._tracer.start_span(self._name)
            self._start = time.perf_counter()
            return self
        
        def __exit__(self, *args):
            duration = time.perf_counter() - self._start
            self._tracer.end_span(self._span_id)
            self._tracer.log_performance(self._name, duration)
            return False


def log_operation(
    log_args: bool = False,
    log_result: bool = False,
    log_duration: bool = True,
    level: int = logging.DEBUG
):
    """操作日志装饰器"""
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            logger_instance = StructuredLogger().get_logger(func.__module__)
            start_time = time.perf_counter()
            
            try:
                if log_args:
                    logger_instance.log(level, f"Calling {func.__name__} with args={args}, kwargs={kwargs}")
                else:
                    logger_instance.log(level, f"Calling {func.__name__}")
                
                result = func(*args, **kwargs)
                
                if log_duration:
                    duration = time.perf_counter() - start_time
                    logger_instance.log(level, f"{func.__name__} completed in {duration*1000:.2f}ms")
                
                if log_result:
                    logger_instance.log(level, f"{func.__name__} returned: {result}")
                
                return result
            except Exception as e:
                duration = time.perf_counter() - start_time
                logger_instance.log(
                    logging.ERROR,
                    f"{func.__name__} failed after {duration*1000:.2f}ms: {e}"
                )
                raise
        
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            logger_instance = StructuredLogger().get_logger(func.__module__)
            start_time = time.perf_counter()
            
            try:
                if log_args:
                    logger_instance.log(level, f"Calling {func.__name__} with args={args}, kwargs={kwargs}")
                else:
                    logger_instance.log(level, f"Calling {func.__name__}")
                
                result = await func(*args, **kwargs)
                
                if log_duration:
                    duration = time.perf_counter() - start_time
                    logger_instance.log(level, f"{func.__name__} completed in {duration*1000:.2f}ms")
                
                if log_result:
                    logger_instance.log(level, f"{func.__name__} returned: {result}")
                
                return result
            except Exception as e:
                duration = time.perf_counter() - start_time
                logger_instance.log(
                    logging.ERROR,
                    f"{func.__name__} failed after {duration*1000:.2f}ms: {e}"
                )
                raise
        
        return async_wrapper if asyncio.iscoroutinefunction(func) else wrapper
    return decorator


class LogCollector:
    """日志收集器，用于临时收集日志"""
    
    def __init__(self, level: int = logging.DEBUG):
        self._logs: List[Dict] = []
        self._level = level
        self._handler = None
        self._logger = None
    
    def __enter__(self):
        self._logs.clear()
        self._logger = logging.getLogger(f"collector_{id(self)}")
        self._handler = _LogHandler(self)
        self._handler.setLevel(self._level)
        self._logger.addHandler(self._handler)
        self._logger.setLevel(self._level)
        return self
    
    def __exit__(self, *args):
        if self._handler and self._logger:
            self._logger.removeHandler(self._handler)
        self._handler = None
        self._logger = None
    
    def get_logs(self) -> List[Dict]:
        return list(self._logs)
    
    def clear(self):
        self._logs.clear()


class _LogHandler(logging.Handler):
    def __init__(self, collector: LogCollector):
        super().__init__()
        self._collector = collector
    
    def emit(self, record: logging.LogRecord):
        self._collector._logs.append({
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
            "name": record.name,
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        })


# 便捷函数
def setup_logging(
    log_dir: str = "logs",
    level: int = logging.INFO,
    json_format: bool = False
):
    """快速设置日志系统"""
    logger_instance = StructuredLogger()
    logger_instance.configure(
        log_dir=log_dir,
        level=level,
        json_format=json_format
    )
    return logger_instance


def get_logger(name: str) -> logging.Logger:
    """获取日志记录器"""
    return StructuredLogger().get_logger(name)
