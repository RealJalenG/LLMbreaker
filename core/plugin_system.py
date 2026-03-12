#!/usr/bin/env python3
"""
插件系统
支持动态加载和管理攻击策略插件
"""

import os
import importlib
import inspect
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Type, Callable
from dataclasses import dataclass, field
from pathlib import Path
import threading

logger = logging.getLogger(__name__)


@dataclass
class PluginInfo:
    """插件信息"""
    name: str
    version: str
    description: str
    author: str = ""
    enabled: bool = True
    priority: int = 100
    dependencies: List[str] = field(default_factory=list)


class AttackPlugin(ABC):
    """
    攻击插件基类
    
    所有攻击策略插件都需要继承此类并实现相应方法
    """
    
    @property
    @abstractmethod
    def info(self) -> PluginInfo:
        """获取插件信息"""
        pass
    
    @abstractmethod
    def initialize(self, config: Dict[str, Any]) -> bool:
        """
        初始化插件
        
        Args:
            config: 插件配置
            
        Returns:
            是否初始化成功
        """
        pass
    
    @abstractmethod
    def generate_attacks(
        self, 
        topic: str, 
        count: int = 10,
        **kwargs
    ) -> List[Dict[str, Any]]:
        """
        生成攻击payload
        
        Args:
            topic: 攻击主题
            count: 生成数量
            **kwargs: 其他参数
            
        Returns:
            攻击payload列表
        """
        pass
    
    @abstractmethod
    def execute_attack(
        self, 
        payload: str, 
        target: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        执行攻击
        
        Args:
            payload: 攻击payload
            target: 目标信息
            **kwargs: 其他参数
            
        Returns:
            攻击结果
        """
        pass
    
    def cleanup(self):
        """清理资源"""
        pass
    
    def get_config_schema(self) -> Dict[str, Any]:
        """
        获取配置schema
        
        Returns:
            配置schema，用于验证和生成配置界面
        """
        return {}
    
    def validate_config(self, config: Dict[str, Any]) -> List[str]:
        """
        验证配置
        
        Args:
            config: 配置字典
            
        Returns:
            错误列表，空列表表示验证通过
        """
        return []


class PluginManager:
    """
    插件管理器
    
    特点：
    1. 动态加载插件
    2. 插件生命周期管理
    3. 插件依赖管理
    4. 线程安全
    """
    
    _instance: Optional['PluginManager'] = None
    _lock = threading.Lock()
    
    def __new__(cls) -> 'PluginManager':
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self._plugins: Dict[str, AttackPlugin] = {}
        self._plugin_classes: Dict[str, Type[AttackPlugin]] = {}
        self._configs: Dict[str, Dict[str, Any]] = {}
        self._plugin_dirs: List[str] = []
        self._initialized = True
    
    @classmethod
    def get_instance(cls) -> 'PluginManager':
        """获取单例实例"""
        return cls()
    
    def add_plugin_dir(self, path: str):
        """添加插件目录"""
        if os.path.isdir(path) and path not in self._plugin_dirs:
            self._plugin_dirs.append(path)
    
    def discover_plugins(self) -> List[str]:
        """
        发现所有可用插件
        
        Returns:
            发现的插件名称列表
        """
        discovered = []
        
        for plugin_dir in self._plugin_dirs:
            if not os.path.isdir(plugin_dir):
                continue
            
            for file in os.listdir(plugin_dir):
                if file.endswith('.py') and not file.startswith('_'):
                    module_path = os.path.join(plugin_dir, file)
                    module_name = file[:-3]
                    
                    try:
                        spec = importlib.util.spec_from_file_location(
                            f"plugins.{module_name}",
                            module_path
                        )
                        if spec and spec.loader:
                            module = importlib.util.module_from_spec(spec)
                            spec.loader.exec_module(module)
                            
                            for name, obj in inspect.getmembers(module):
                                if (inspect.isclass(obj) and 
                                    issubclass(obj, AttackPlugin) and 
                                    obj != AttackPlugin):
                                    plugin_name = obj.__name__
                                    self._plugin_classes[plugin_name] = obj
                                    discovered.append(plugin_name)
                                    logger.info(f"Discovered plugin: {plugin_name}")
                    
                    except Exception as e:
                        logger.error(f"Failed to load plugin from {module_path}: {e}")
        
        return discovered
    
    def register_plugin(self, plugin_class: Type[AttackPlugin]) -> bool:
        """
        注册插件类
        
        Args:
            plugin_class: 插件类
            
        Returns:
            是否注册成功
        """
        try:
            plugin_name = plugin_class.__name__
            self._plugin_classes[plugin_name] = plugin_class
            logger.info(f"Registered plugin class: {plugin_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to register plugin: {e}")
            return False
    
    def load_plugin(
        self, 
        plugin_name: str, 
        config: Optional[Dict[str, Any]] = None
    ) -> Optional[AttackPlugin]:
        """
        加载插件实例
        
        Args:
            plugin_name: 插件名称
            config: 插件配置
            
        Returns:
            插件实例，失败返回None
        """
        if plugin_name in self._plugins:
            return self._plugins[plugin_name]
        
        plugin_class = self._plugin_classes.get(plugin_name)
        if not plugin_class:
            logger.error(f"Plugin class not found: {plugin_name}")
            return None
        
        try:
            plugin = plugin_class()
            
            if config:
                errors = plugin.validate_config(config)
                if errors:
                    logger.error(f"Plugin config validation failed: {errors}")
                    return None
            
            if plugin.initialize(config or {}):
                self._plugins[plugin_name] = plugin
                self._configs[plugin_name] = config or {}
                logger.info(f"Loaded plugin: {plugin_name}")
                return plugin
            else:
                logger.error(f"Plugin initialization failed: {plugin_name}")
                return None
                
        except Exception as e:
            logger.error(f"Failed to load plugin {plugin_name}: {e}")
            return None
    
    def unload_plugin(self, plugin_name: str) -> bool:
        """
        卸载插件
        
        Args:
            plugin_name: 插件名称
            
        Returns:
            是否卸载成功
        """
        if plugin_name not in self._plugins:
            return False
        
        try:
            plugin = self._plugins[plugin_name]
            plugin.cleanup()
            del self._plugins[plugin_name]
            if plugin_name in self._configs:
                del self._configs[plugin_name]
            logger.info(f"Unloaded plugin: {plugin_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to unload plugin {plugin_name}: {e}")
            return False
    
    def reload_plugin(self, plugin_name: str) -> Optional[AttackPlugin]:
        """
        重新加载插件
        
        Args:
            plugin_name: 插件名称
            
        Returns:
            新的插件实例
        """
        config = self._configs.get(plugin_name, {})
        self.unload_plugin(plugin_name)
        return self.load_plugin(plugin_name, config)
    
    def get_plugin(self, plugin_name: str) -> Optional[AttackPlugin]:
        """获取已加载的插件"""
        return self._plugins.get(plugin_name)
    
    def list_plugins(self) -> List[str]:
        """列出所有已加载的插件"""
        return list(self._plugins.keys())
    
    def list_available_plugins(self) -> List[str]:
        """列出所有可用的插件类"""
        return list(self._plugin_classes.keys())
    
    def get_plugin_info(self, plugin_name: str) -> Optional[PluginInfo]:
        """获取插件信息"""
        plugin = self._plugins.get(plugin_name)
        if plugin:
            return plugin.info
        return None
    
    def execute_with_plugin(
        self,
        plugin_name: str,
        method: str,
        *args,
        **kwargs
    ) -> Any:
        """
        使用插件执行方法
        
        Args:
            plugin_name: 插件名称
            method: 方法名
            *args: 位置参数
            **kwargs: 关键字参数
            
        Returns:
            方法执行结果
        """
        plugin = self.get_plugin(plugin_name)
        if not plugin:
            raise ValueError(f"Plugin not loaded: {plugin_name}")
        
        method_func = getattr(plugin, method, None)
        if not method_func or not callable(method_func):
            raise ValueError(f"Method not found: {method}")
        
        return method_func(*args, **kwargs)
    
    def get_stats(self) -> Dict[str, Any]:
        """获取插件管理器统计信息"""
        return {
            "loaded_plugins": len(self._plugins),
            "available_plugins": len(self._plugin_classes),
            "plugin_dirs": self._plugin_dirs,
            "plugins": {
                name: {
                    "info": plugin.info.__dict__,
                    "config": self._configs.get(name, {})
                }
                for name, plugin in self._plugins.items()
            }
        }


def get_plugin_manager() -> PluginManager:
    """获取全局插件管理器实例"""
    manager = PluginManager.get_instance()
    
    default_plugin_dirs = [
        "plugins",
        "agent/plugins"
    ]
    
    for plugin_dir in default_plugin_dirs:
        full_path = os.path.join(os.getcwd(), plugin_dir)
        if os.path.exists(full_path):
            manager.add_plugin_dir(full_path)
    
    return manager


def plugin_decorator(
    name: str,
    version: str = "1.0.0",
    description: str = "",
    author: str = "",
    priority: int = 100
):
    """
    插件装饰器，简化插件定义
    
    用法:
        @plugin_decorator("MyPlugin", version="1.0.0", description="My attack plugin")
        class MyPlugin(AttackPlugin):
            ...
    """
    def decorator(cls: Type[AttackPlugin]) -> Type[AttackPlugin]:
        original_info = cls.info
        
        @property
        def info(self) -> PluginInfo:
            return PluginInfo(
                name=name,
                version=version,
                description=description,
                author=author,
                priority=priority
            )
        
        cls.info = info
        return cls
    
    return decorator
