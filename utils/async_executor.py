#!/usr/bin/env python3
"""
统一异步执行管理器
解决asyncio.run()冲突，提供统一的异步执行接口
"""

import asyncio
import threading
from typing import Any, Callable, Coroutine, Optional, TypeVar, List
from concurrent.futures import Future
import functools
import logging

logger = logging.getLogger(__name__)

T = TypeVar('T')


class AsyncExecutor:
    """
    统一异步执行管理器
    
    特点：
    1. 单例模式，全局共享事件循环
    2. 自动检测是否在异步上下文中
    3. 支持同步和异步调用方式
    4. 线程安全
    """
    
    _instance: Optional['AsyncExecutor'] = None
    _lock = threading.Lock()
    
    def __new__(cls) -> 'AsyncExecutor':
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._initialized = True
        self._tasks: List[asyncio.Task] = []
    
    @classmethod
    def get_instance(cls) -> 'AsyncExecutor':
        """获取单例实例"""
        return cls()
    
    def _ensure_loop(self) -> asyncio.AbstractEventLoop:
        """确保事件循环存在"""
        try:
            loop = asyncio.get_running_loop()
            return loop
        except RuntimeError:
            pass
        
        if self._loop is None or self._loop.is_closed():
            self._loop = asyncio.new_event_loop()
        
        return self._loop
    
    def _start_background_loop(self):
        """启动后台事件循环线程"""
        if self._running:
            return
        
        def run_loop():
            asyncio.set_event_loop(self._loop)
            self._loop.run_forever()
        
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=run_loop, daemon=True)
        self._thread.start()
        self._running = True
    
    def run(self, coro: Coroutine[Any, Any, T]) -> T:
        """
        执行协程，自动选择最佳执行方式
        
        Args:
            coro: 要执行的协程
            
        Returns:
            协程的返回值
        """
        try:
            loop = asyncio.get_running_loop()
            future = asyncio.ensure_future(coro, loop=loop)
            return future
        except RuntimeError:
            pass
        
        loop = self._ensure_loop()
        
        if loop.is_running():
            future = asyncio.run_coroutine_threadsafe(coro, loop)
            return future.result()
        else:
            return loop.run_until_complete(coro)
    
    def run_sync(self, coro: Coroutine[Any, Any, T]) -> T:
        """
        同步执行协程（阻塞直到完成）
        
        Args:
            coro: 要执行的协程
            
        Returns:
            协程的返回值
        """
        try:
            loop = asyncio.get_running_loop()
            future = asyncio.run_coroutine_threadsafe(
                coro, 
                loop if loop.is_running() else self._ensure_loop()
            )
            return future.result()
        except RuntimeError:
            loop = self._ensure_loop()
            return loop.run_until_complete(coro)
    
    async def run_async(self, coro: Coroutine[Any, Any, T]) -> T:
        """
        异步执行协程
        
        Args:
            coro: 要执行的协程
            
        Returns:
            协程的返回值
        """
        return await coro
    
    def run_batch(self, coros: List[Coroutine[Any, Any, T]]) -> List[T]:
        """
        批量执行协程
        
        Args:
            coros: 协程列表
            
        Returns:
            结果列表
        """
        async def gather_all():
            return await asyncio.gather(*coros, return_exceptions=True)
        
        return self.run(gather_all())
    
    def create_task(self, coro: Coroutine[Any, Any, T]) -> asyncio.Task:
        """
        创建异步任务
        
        Args:
            coro: 要执行的协程
            
        Returns:
            Task对象
        """
        loop = self._ensure_loop()
        task = loop.create_task(coro)
        self._tasks.append(task)
        return task
    
    def cancel_all_tasks(self):
        """取消所有任务"""
        for task in self._tasks:
            if not task.done():
                task.cancel()
        self._tasks.clear()
    
    def shutdown(self):
        """关闭执行器"""
        self.cancel_all_tasks()
        
        if self._loop and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._loop.stop)
        
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        
        if self._loop and not self._loop.is_closed():
            self._loop.close()
        
        self._running = False
        self._loop = None
        self._thread = None


def async_to_sync(func: Callable[..., Coroutine[Any, Any, T]]) -> Callable[..., T]:
    """
    装饰器：将异步函数转换为同步函数
    
    用法:
        @async_to_sync
        async def my_async_func():
            await asyncio.sleep(1)
            return "done"
        
        result = my_async_func()
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs) -> T:
        executor = AsyncExecutor.get_instance()
        coro = func(*args, **kwargs)
        return executor.run_sync(coro)
    return wrapper


def sync_to_async(func: Callable[..., T]) -> Callable[..., Coroutine[Any, Any, T]]:
    """
    装饰器：将同步函数转换为异步函数
    
    用法:
        @sync_to_async
        def my_sync_func():
            time.sleep(1)
            return "done"
        
        result = await my_sync_func()
    """
    @functools.wraps(func)
    async def wrapper(*args, **kwargs) -> T:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, functools.partial(func, *args, **kwargs))
    return wrapper


def run_async(coro: Coroutine[Any, Any, T]) -> T:
    """
    快捷函数：执行协程
    
    Args:
        coro: 要执行的协程
        
    Returns:
        协程的返回值
    """
    executor = AsyncExecutor.get_instance()
    return executor.run(coro)


def run_batch_async(coros: List[Coroutine[Any, Any, T]]) -> List[T]:
    """
    快捷函数：批量执行协程
    
    Args:
        coros: 协程列表
        
    Returns:
        结果列表
    """
    executor = AsyncExecutor.get_instance()
    return executor.run_batch(coros)


_executor_instance: Optional[AsyncExecutor] = None


def get_executor() -> AsyncExecutor:
    """获取全局执行器实例"""
    global _executor_instance
    if _executor_instance is None:
        _executor_instance = AsyncExecutor.get_instance()
    return _executor_instance
