#!/usr/bin/env python3
"""
异步HTTP连接池
支持连接复用、并发控制、重试机制
"""

import asyncio
import aiohttp
import logging
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass
import threading
import time
from contextlib import asynccontextmanager

logger = logging.getLogger(__name__)


@dataclass
class HTTPPoolConfig:
    """HTTP连接池配置"""
    max_connections: int = 100
    max_connections_per_host: int = 20
    connect_timeout: int = 30
    read_timeout: int = 60
    total_timeout: int = 120
    enable_retry: bool = True
    max_retries: int = 3
    retry_delay: float = 1.0
    enable_stats: bool = True


class AsyncHTTPPool:
    """
    异步HTTP连接池
    
    特点：
    1. 连接复用，减少TCP握手开销
    2. 并发控制，防止资源耗尽
    3. 自动重试机制
    4. 请求统计
    5. 线程安全
    """
    
    _instance: Optional['AsyncHTTPPool'] = None
    _lock = threading.Lock()
    
    def __new__(cls) -> 'AsyncHTTPPool':
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self, config: Optional[HTTPPoolConfig] = None):
        if self._initialized:
            return
        
        self._config = config or HTTPPoolConfig()
        self._session: Optional[aiohttp.ClientSession] = None
        self._connector: Optional[aiohttp.TCPConnector] = None
        self._semaphore: Optional[asyncio.Semaphore] = None
        
        self._stats = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "retries": 0,
            "total_time_ms": 0
        }
        self._stats_lock = threading.Lock()
        self._initialized = True
    
    @classmethod
    def get_instance(cls, config: Optional[HTTPPoolConfig] = None) -> 'AsyncHTTPPool':
        """获取单例实例"""
        instance = cls()
        if config:
            instance._config = config
        return instance
    
    async def _ensure_session(self) -> aiohttp.ClientSession:
        """确保session存在"""
        if self._session is None or self._session.closed:
            self._connector = aiohttp.TCPConnector(
                limit=self._config.max_connections,
                limit_per_host=self._config.max_connections_per_host,
                enable_cleanup_closed=True,
                force_close=False,
                ttl=300
            )
            
            timeout = aiohttp.ClientTimeout(
                total=self._config.total_timeout,
                connect=self._config.connect_timeout,
                sock_read=self._config.read_timeout
            )
            
            self._session = aiohttp.ClientSession(
                connector=self._connector,
                timeout=timeout,
                connector_owner=True
            )
            
            self._semaphore = asyncio.Semaphore(self._config.max_connections)
        
        return self._session
    
    async def _update_stats(self, success: bool, time_ms: float, retry: bool = False):
        """更新统计信息"""
        if not self._config.enable_stats:
            return
        
        with self._stats_lock:
            self._stats["total_requests"] += 1
            self._stats["total_time_ms"] += time_ms
            if success:
                self._stats["successful_requests"] += 1
            else:
                self._stats["failed_requests"] += 1
            if retry:
                self._stats["retries"] += 1
    
    async def request(
        self,
        method: str,
        url: str,
        **kwargs
    ) -> Tuple[Optional[Dict[str, Any]], Optional[Exception]]:
        """
        发送HTTP请求
        
        Args:
            method: HTTP方法
            url: URL
            **kwargs: 其他参数
            
        Returns:
            (响应数据, 错误)
        """
        start_time = time.time()
        last_error = None
        
        for attempt in range(self._config.max_retries + 1):
            try:
                session = await self._ensure_session()
                
                async with self._semaphore:
                    async with session.request(method, url, **kwargs) as response:
                        elapsed_ms = (time.time() - start_time) * 1000
                        
                        if response.status >= 400:
                            text = await response.text()
                            error = Exception(f"HTTP {response.status}: {text[:200]}")
                            await self._update_stats(False, elapsed_ms, attempt > 0)
                            return None, error
                        
                        try:
                            data = await response.json()
                        except:
                            data = await response.text()
                        
                        await self._update_stats(True, elapsed_ms, attempt > 0)
                        return data, None
                        
            except asyncio.TimeoutError as e:
                last_error = e
                logger.warning(f"Request timeout (attempt {attempt + 1}): {url}")
            except aiohttp.ClientError as e:
                last_error = e
                logger.warning(f"Request error (attempt {attempt + 1}): {e}")
            except Exception as e:
                last_error = e
                logger.error(f"Unexpected error (attempt {attempt + 1}): {e}")
            
            if attempt < self._config.max_retries and self._config.enable_retry:
                await asyncio.sleep(self._config.retry_delay * (attempt + 1))
        
        elapsed_ms = (time.time() - start_time) * 1000
        await self._update_stats(False, elapsed_ms, True)
        return None, last_error
    
    async def get(
        self,
        url: str,
        **kwargs
    ) -> Tuple[Optional[Dict[str, Any]], Optional[Exception]]:
        """GET请求"""
        return await self.request("GET", url, **kwargs)
    
    async def post(
        self,
        url: str,
        **kwargs
    ) -> Tuple[Optional[Dict[str, Any]], Optional[Exception]]:
        """POST请求"""
        return await self.request("POST", url, **kwargs)
    
    async def post_json(
        self,
        url: str,
        data: Dict[str, Any],
        **kwargs
    ) -> Tuple[Optional[Dict[str, Any]], Optional[Exception]]:
        """POST JSON请求"""
        kwargs.setdefault("json", data)
        return await self.post(url, **kwargs)
    
    @asynccontextmanager
    async def request_context(
        self,
        method: str,
        url: str,
        **kwargs
    ):
        """请求上下文管理器"""
        session = await self._ensure_session()
        async with self._semaphore:
            async with session.request(method, url, **kwargs) as response:
                yield response
    
    async def batch_request(
        self,
        requests: List[Dict[str, Any]],
        concurrency: int = 10
    ) -> List[Tuple[Optional[Dict[str, Any]], Optional[Exception]]]:
        """
        批量请求
        
        Args:
            requests: 请求列表，每个元素包含 method, url, **kwargs
            concurrency: 并发数
            
        Returns:
            结果列表
        """
        semaphore = asyncio.Semaphore(concurrency)
        
        async def single_request(req: Dict[str, Any]):
            async with semaphore:
                return await self.request(
                    req.get("method", "GET"),
                    req["url"],
                    **{k: v for k, v in req.items() if k not in ["method", "url"]}
                )
        
        return await asyncio.gather(*[single_request(req) for req in requests])
    
    async def close(self):
        """关闭连接池"""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None
            self._connector = None
            logger.info("HTTP pool closed")
    
    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        with self._stats_lock:
            stats = self._stats.copy()
        
        if stats["total_requests"] > 0:
            stats["success_rate"] = stats["successful_requests"] / stats["total_requests"]
            stats["avg_time_ms"] = stats["total_time_ms"] / stats["total_requests"]
        else:
            stats["success_rate"] = 0
            stats["avg_time_ms"] = 0
        
        return stats
    
    def reset_stats(self):
        """重置统计"""
        with self._stats_lock:
            self._stats = {
                "total_requests": 0,
                "successful_requests": 0,
                "failed_requests": 0,
                "retries": 0,
                "total_time_ms": 0
            }


def get_http_pool(config: Optional[HTTPPoolConfig] = None) -> AsyncHTTPPool:
    """获取全局HTTP池实例"""
    return AsyncHTTPPool.get_instance(config)
