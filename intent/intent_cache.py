"""
IntentCache - 意图缓存管理器
实现逻辑与数据解耦，跨任务复用相同意图的生成结果
"""

import hashlib
import json
import os
import pickle
import logging
import threading
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class CacheEntry:
    """缓存条目"""
    cache_key: str
    intent_hash: str
    generated_content: Any
    created_at: datetime = field(default_factory=datetime.now)
    last_accessed: datetime = field(default_factory=datetime.now)
    access_count: int = 0
    is_validated: bool = False
    validation_result: Optional[str] = None
    ttl_seconds: int = 86400  # 默认24小时过期
    
    def is_expired(self) -> bool:
        """检查是否过期"""
        if self.ttl_seconds <= 0:
            return False
        return datetime.now() > self.created_at + timedelta(seconds=self.ttl_seconds)
    
    def touch(self):
        """更新访问时间和计数"""
        self.last_accessed = datetime.now()
        self.access_count += 1


class IntentCache:
    """
    意图缓存管理器
    
    核心功能:
    1. 基于intent hash的缓存键生成
    2. 内存+磁盘二级缓存
    3. LRU淘汰策略
    4. 缓存统计和监控
    
    使用示例:
    ```python
    cache = IntentCache()
    
    # 检查缓存
    cache_key = intent.get_cache_key()
    if cache_key in cache:
        result = cache.get(cache_key)
    else:
        result = llm.generate(intent.to_prompt())
        cache.set(cache_key, result)
    ```
    """
    
    def __init__(
        self,
        cache_dir: str = ".intent_cache",
        max_memory_entries: int = 1000,
        default_ttl: int = 86400,
        enable_disk_cache: bool = True
    ):
        """
        初始化缓存管理器
        
        Args:
            cache_dir: 磁盘缓存目录
            max_memory_entries: 最大内存缓存条目数
            default_ttl: 默认过期时间(秒)
            enable_disk_cache: 是否启用磁盘缓存
        """
        self.cache_dir = Path(cache_dir)
        self.max_memory_entries = max_memory_entries
        self.default_ttl = default_ttl
        self.enable_disk_cache = enable_disk_cache
        
        # 内存缓存
        self._memory_cache: Dict[str, CacheEntry] = {}
        self._lock = threading.RLock()
        
        # 统计信息
        self._stats = {
            'hits': 0,
            'misses': 0,
            'evictions': 0,
            'disk_reads': 0,
            'disk_writes': 0
        }
        
        # 初始化磁盘缓存目录
        if self.enable_disk_cache:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            self._load_cache_index()
    
    def _load_cache_index(self):
        """加载磁盘缓存索引"""
        index_file = self.cache_dir / "cache_index.json"
        if index_file.exists():
            try:
                with open(index_file, 'r', encoding='utf-8') as f:
                    index = json.load(f)
                logger.info(f"加载缓存索引: {len(index)} 个条目")
            except Exception as e:
                logger.warning(f"加载缓存索引失败: {e}")
    
    def _save_cache_index(self):
        """保存磁盘缓存索引"""
        if not self.enable_disk_cache:
            return
        
        index_file = self.cache_dir / "cache_index.json"
        index = {
            key: {
                'intent_hash': entry.intent_hash,
                'created_at': entry.created_at.isoformat(),
                'access_count': entry.access_count
            }
            for key, entry in self._memory_cache.items()
        }
        
        try:
            with open(index_file, 'w', encoding='utf-8') as f:
                json.dump(index, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.warning(f"保存缓存索引失败: {e}")
    
    def _get_disk_path(self, cache_key: str) -> Path:
        """获取磁盘缓存文件路径"""
        return self.cache_dir / f"{cache_key}.cache"
    
    def _evict_lru(self):
        """LRU淘汰策略"""
        if len(self._memory_cache) < self.max_memory_entries:
            return
        
        # 按最后访问时间排序，淘汰最老的
        sorted_entries = sorted(
            self._memory_cache.items(),
            key=lambda x: x[1].last_accessed
        )
        
        # 淘汰10%的条目
        evict_count = max(1, len(sorted_entries) // 10)
        for key, entry in sorted_entries[:evict_count]:
            # 如果启用磁盘缓存，先写入磁盘
            if self.enable_disk_cache and entry.access_count > 1:
                self._write_to_disk(key, entry)
            
            del self._memory_cache[key]
            self._stats['evictions'] += 1
        
        logger.debug(f"LRU淘汰: 移除 {evict_count} 个条目")
    
    def _write_to_disk(self, cache_key: str, entry: CacheEntry):
        """写入磁盘缓存"""
        if not self.enable_disk_cache:
            return
        
        disk_path = self._get_disk_path(cache_key)
        try:
            with open(disk_path, 'wb') as f:
                pickle.dump(entry, f)
            self._stats['disk_writes'] += 1
        except Exception as e:
            logger.warning(f"写入磁盘缓存失败: {e}")
    
    def _read_from_disk(self, cache_key: str) -> Optional[CacheEntry]:
        """从磁盘读取缓存"""
        if not self.enable_disk_cache:
            return None
        
        disk_path = self._get_disk_path(cache_key)
        if not disk_path.exists():
            return None
        
        try:
            with open(disk_path, 'rb') as f:
                entry = pickle.load(f)
            self._stats['disk_reads'] += 1
            return entry
        except Exception as e:
            logger.warning(f"读取磁盘缓存失败: {e}")
            return None
    
    def get(self, cache_key: str) -> Optional[Any]:
        """
        获取缓存内容
        
        Args:
            cache_key: 缓存键
        
        Returns:
            缓存的内容，未命中返回None
        """
        with self._lock:
            # 先查内存
            if cache_key in self._memory_cache:
                entry = self._memory_cache[cache_key]
                
                # 检查过期
                if entry.is_expired():
                    del self._memory_cache[cache_key]
                    self._stats['misses'] += 1
                    return None
                
                entry.touch()
                self._stats['hits'] += 1
                logger.debug(f"缓存命中(内存): {cache_key[:16]}...")
                return entry.generated_content
            
            # 再查磁盘
            entry = self._read_from_disk(cache_key)
            if entry and not entry.is_expired():
                entry.touch()
                self._memory_cache[cache_key] = entry
                self._stats['hits'] += 1
                logger.debug(f"缓存命中(磁盘): {cache_key[:16]}...")
                return entry.generated_content
            
            self._stats['misses'] += 1
            return None
    
    def set(
        self,
        cache_key: str,
        content: Any,
        intent_hash: str = "",
        ttl: int = None,
        validated: bool = False
    ):
        """
        设置缓存内容
        
        Args:
            cache_key: 缓存键
            content: 缓存内容
            intent_hash: 意图哈希
            ttl: 过期时间(秒)
            validated: 是否已验证
        """
        with self._lock:
            # LRU淘汰
            self._evict_lru()
            
            entry = CacheEntry(
                cache_key=cache_key,
                intent_hash=intent_hash or cache_key,
                generated_content=content,
                ttl_seconds=ttl if ttl is not None else self.default_ttl,
                is_validated=validated
            )
            
            self._memory_cache[cache_key] = entry
            logger.debug(f"缓存写入: {cache_key[:16]}...")
    
    def __contains__(self, cache_key: str) -> bool:
        """检查缓存是否存在"""
        with self._lock:
            if cache_key in self._memory_cache:
                if not self._memory_cache[cache_key].is_expired():
                    return True
            
            # 检查磁盘
            if self.enable_disk_cache:
                entry = self._read_from_disk(cache_key)
                if entry and not entry.is_expired():
                    return True
            
            return False
    
    def delete(self, cache_key: str):
        """删除缓存"""
        with self._lock:
            if cache_key in self._memory_cache:
                del self._memory_cache[cache_key]
            
            if self.enable_disk_cache:
                disk_path = self._get_disk_path(cache_key)
                if disk_path.exists():
                    disk_path.unlink()
    
    def clear(self):
        """清空所有缓存"""
        with self._lock:
            self._memory_cache.clear()
            
            if self.enable_disk_cache:
                for cache_file in self.cache_dir.glob("*.cache"):
                    cache_file.unlink()
            
            logger.info("缓存已清空")
    
    def get_stats(self) -> Dict[str, Any]:
        """获取缓存统计信息"""
        with self._lock:
            total_requests = self._stats['hits'] + self._stats['misses']
            hit_rate = (self._stats['hits'] / total_requests * 100) if total_requests > 0 else 0
            
            return {
                'memory_entries': len(self._memory_cache),
                'max_memory_entries': self.max_memory_entries,
                'hits': self._stats['hits'],
                'misses': self._stats['misses'],
                'hit_rate': f"{hit_rate:.2f}%",
                'evictions': self._stats['evictions'],
                'disk_reads': self._stats['disk_reads'],
                'disk_writes': self._stats['disk_writes']
            }
    
    def validate_entry(self, cache_key: str, result: str):
        """验证缓存条目"""
        with self._lock:
            if cache_key in self._memory_cache:
                entry = self._memory_cache[cache_key]
                entry.is_validated = True
                entry.validation_result = result
    
    def get_validated_entries(self) -> List[CacheEntry]:
        """获取所有已验证的缓存条目"""
        with self._lock:
            return [
                entry for entry in self._memory_cache.values()
                if entry.is_validated
            ]
    
    def save(self):
        """保存缓存到磁盘"""
        if not self.enable_disk_cache:
            return
        
        with self._lock:
            for key, entry in self._memory_cache.items():
                self._write_to_disk(key, entry)
            self._save_cache_index()
        
        logger.info(f"缓存已保存: {len(self._memory_cache)} 个条目")
    
    def __del__(self):
        """析构时保存缓存"""
        try:
            self.save()
        except Exception:
            pass


# 全局缓存实例
_global_cache: Optional[IntentCache] = None


def get_intent_cache() -> IntentCache:
    """获取全局缓存实例"""
    global _global_cache
    if _global_cache is None:
        _global_cache = IntentCache()
    return _global_cache


def set_intent_cache(cache: IntentCache):
    """设置全局缓存实例"""
    global _global_cache
    _global_cache = cache
