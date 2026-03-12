"""
优化工具模块 - 提供通用优化功能

包含：
- 内存池管理
- 对象池
- 缓存机制
- 性能监控
- 资源清理
"""

import asyncio
import gc
import logging
import time
import weakref
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from functools import lru_cache, wraps
from typing import Any, Callable, Dict, Generic, List, Optional, Type, TypeVar, Union
from dataclasses import dataclass
import threading
import psutil
import os

logger = logging.getLogger(__name__)

T = TypeVar('T')


class MemoryPool(Generic[T]):
    """通用对象内存池"""
    
    def __init__(self, max_size: int = 100, factory: Callable[[], T] = None):
        self._pool: List[T] = []
        self._max_size = max_size
        self._factory = factory
        self._lock = threading.Lock()
        self._hit_count = 0
        self._miss_count = 0
    
    def acquire(self) -> T:
        with self._lock:
            if self._pool:
                self._hit_count += 1
                return self._pool.pop()
            self._miss_count += 1
            if self._factory:
                return self._factory()
            raise ValueError("Pool is empty and no factory provided")
    
    def release(self, obj: T) -> None:
        with self._lock:
            if len(self._pool) < self._max_size:
                self._pool.append(obj)
    
    def resize(self, new_size: int) -> None:
        with self._lock:
            self._max_size = new_size
            while len(self._pool) > new_size:
                self._pool.pop()
    
    def clear(self) -> None:
        with self._lock:
            self._pool.clear()
    
    @property
    def stats(self) -> Dict[str, int]:
        with self._lock:
            return {
                "pool_size": len(self._pool),
                "hit_count": self._hit_count,
                "miss_count": self._miss_count,
                "hit_rate": self._hit_count / (self._hit_count + self._miss_count + 1e-10)
            }


class StringPool:
    """字符串 intern 池，减少重复字符串内存占用"""
    
    _interned: Dict[str, str] = {}
    _lock = threading.Lock()
    
    @classmethod
    def intern(cls, s: str) -> str:
        with cls._lock:
            if s not in cls._interned:
                cls._interned[s] = s
            return cls._interned[s]
    
    @classmethod
    def get_stats(cls) -> Dict[str, int]:
        with cls._lock:
            return {"interned_count": len(cls._interned)}


class LRUCacheWithStats(Generic[T]):
    """带统计信息的 LRU 缓存"""
    
    def __init__(self, max_size: int = 256):
        self._cache: Dict[str, T] = {}
        self._order: List[str] = []
        self._max_size = max_size
        self._lock = threading.Lock()
        self._hit_count = 0
        self._miss_count = 0
    
    def get(self, key: str) -> Optional[T]:
        with self._lock:
            if key in self._cache:
                self._hit_count += 1
                self._order.remove(key)
                self._order.append(key)
                return self._cache[key]
            self._miss_count += 1
            return None
    
    def set(self, key: str, value: T) -> None:
        with self._lock:
            if key in self._cache:
                self._order.remove(key)
            elif len(self._order) >= self._max_size:
                oldest = self._order.pop(0)
                del self._cache[oldest]
            self._order.append(key)
            self._cache[key] = value
    
    def clear(self) -> None:
        with self._lock:
            self._cache.clear()
            self._order.clear()
    
    @property
    def stats(self) -> Dict[str, Any]:
        with self._lock:
            total = self._hit_count + self._miss_count
            return {
                "size": len(self._cache),
                "hit_count": self._hit_count,
                "miss_count": self._miss_count,
                "hit_rate": self._hit_count / (total + 1e-10)
            }


class ResourceManager:
    """资源管理器，负责系统资源监控和清理"""
    
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
        self._process = psutil.Process(os.getpid())
        self._monitoring = False
        self._baseline_memory = 0
        self._cleanup_callbacks: List[Callable] = []
        self._lock = threading.Lock()
    
    def start_monitoring(self, interval: float = 5.0):
        """启动资源监控"""
        self._monitoring = True
        self._baseline_memory = self.get_memory_mb()
        logger.info(f"Resource monitoring started. Baseline memory: {self._baseline_memory:.2f} MB")
    
    def stop_monitoring(self):
        """停止资源监控"""
        self._monitoring = False
        logger.info("Resource monitoring stopped")
    
    def get_memory_mb(self) -> float:
        """获取当前内存使用（MB）"""
        try:
            return self._process.memory_info().rss / (1024 * 1024)
        except Exception:
            return 0.0
    
    def get_cpu_percent(self) -> float:
        """获取CPU使用率"""
        try:
            return self._process.cpu_percent()
        except Exception:
            return 0.0
    
    def get_memory_stats(self) -> Dict[str, float]:
        """获取内存统计信息"""
        current = self.get_memory_mb()
        return {
            "current_mb": current,
            "baseline_mb": self._baseline_memory,
            "delta_mb": current - self._baseline_memory,
            "percent_change": ((current - self._baseline_memory) / (self._baseline_memory + 1e-10)) * 100
        }
    
    def register_cleanup(self, callback: Callable):
        """注册清理回调"""
        with self._lock:
            self._cleanup_callbacks.append(callback)
    
    def cleanup(self):
        """执行所有清理回调"""
        with self._lock:
            for callback in self._cleanup_callbacks:
                try:
                    callback()
                except Exception as e:
                    logger.error(f"Cleanup callback failed: {e}")
            self._cleanup_callbacks.clear()
    
    def force_garbage_collection(self):
        """强制执行垃圾回收"""
        gc.collect()
        logger.debug("Forced garbage collection")


class PerformanceMonitor:
    """性能监控器"""
    
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
        self._timers: Dict[str, List[float]] = defaultdict(list)
        self._counters: Dict[str, int] = defaultdict(int)
        self._lock = threading.Lock()
    
    def time_operation(self, operation_name: str):
        """返回计时上下文管理器"""
        return self._TimerContext(operation_name, self)
    
    def increment_counter(self, counter_name: str, value: int = 1):
        """增加计数器"""
        with self._lock:
            self._counters[counter_name] += value
    
    def get_stats(self) -> Dict[str, Any]:
        """获取性能统计"""
        with self._lock:
            stats = {
                "timers": {},
                "counters": dict(self._counters)
            }
            for name, durations in self._timers.items():
                if durations:
                    stats["timers"][name] = {
                        "count": len(durations),
                        "avg_ms": sum(durations) / len(durations) * 1000,
                        "min_ms": min(durations) * 1000,
                        "max_ms": max(durations) * 1000,
                        "total_ms": sum(durations) * 1000
                    }
            return stats
    
    def reset_stats(self):
        """重置统计"""
        with self._lock:
            self._timers.clear()
            self._counters.clear()
    
    class _TimerContext:
        def __init__(self, name: str, monitor: 'PerformanceMonitor'):
            self._name = name
            self._monitor = monitor
        
        def __enter__(self):
            self._start = time.perf_counter()
            return self
        
        def __exit__(self, *args):
            duration = time.perf_counter() - self._start
            with self._monitor._lock:
                self._monitor._timers[self._name].append(duration)
            return False


class AsyncPool:
    """异步任务池"""
    
    def __init__(self, max_workers: int = 10):
        self._max_workers = max_workers
        self._semaphore = asyncio.Semaphore(max_workers)
        self._running = 0
        self._completed = 0
        self._failed = 0
    
    async def run(self, coro) -> Any:
        async with self._semaphore:
            self._running += 1
            try:
                result = await coro
                self._completed += 1
                return result
            except Exception as e:
                self._failed += 1
                raise
    
    def get_stats(self) -> Dict[str, int]:
        return {
            "running": self._running,
            "completed": self._completed,
            "failed": self._failed,
            "available": self._max_workers - self._running
        }


def cached_with_stats(maxsize: int = 256):
    """带统计的缓存装饰器"""
    cache = LRUCacheWithStats(maxsize)
    
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            key = str(args) + str(sorted(kwargs.items()))
            result = cache.get(key)
            if result is None:
                result = func(*args, **kwargs)
                cache.set(key, result)
            return result
        wrapper.cache = cache
        return wrapper
    return decorator


def retry_on_failure(max_retries: int = 3, delay: float = 0.1, backoff: float = 2.0):
    """失败重试装饰器"""
    def decorator(func: Callable):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            last_exception = None
            current_delay = delay
            for attempt in range(max_retries + 1):
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    if attempt < max_retries:
                        await asyncio.sleep(current_delay)
                        current_delay *= backoff
            raise last_exception
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            last_exception = None
            current_delay = delay
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    if attempt < max_retries:
                        time.sleep(current_delay)
                        current_delay *= backoff
            raise last_exception
        
        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper
    return decorator


class ThreadPool:
    """轻量级线程池"""
    
    def __init__(self, max_workers: int = 10):
        self._pool = ThreadPoolExecutor(max_workers=max_workers)
        self._tasks = []
        self._lock = threading.Lock()
    
    def submit(self, func: Callable, *args, **kwargs):
        """提交任务"""
        future = self._pool.submit(func, *args, **kwargs)
        with self._lock:
            self._tasks.append(future)
        return future
    
    def map(self, func: Callable, iterable):
        """映射执行"""
        return self._pool.map(func, iterable)
    
    def shutdown(self, wait: bool = True):
        """关闭线程池"""
        self._pool.shutdown(wait=wait)
    
    def get_pending_count(self) -> int:
        """获取待完成任务数"""
        with self._lock:
            return sum(1 for f in self._tasks if not f.done())
    
    def get_completed_count(self) -> int:
        """获取已完成任务数"""
        with self._lock:
            return sum(1 for f in self._tasks if f.done())


@contextmanager
def timed_operation(name: str):
    """简单计时上下文"""
    start = time.perf_counter()
    yield
    duration = time.perf_counter() - start
    logger.debug(f"Operation '{name}' completed in {duration*1000:.2f}ms")
