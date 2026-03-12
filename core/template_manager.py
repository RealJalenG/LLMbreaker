#!/usr/bin/env python3
"""
模板管理器
支持从YAML文件动态加载攻击模板
"""

import os
import yaml
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from pathlib import Path
import threading
import time

logger = logging.getLogger(__name__)


@dataclass
class Template:
    """模板数据结构"""
    name: str
    category: str
    template: str
    variables: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def render(self, **kwargs) -> str:
        """渲染模板"""
        result = self.template
        for var in self.variables:
            if var in kwargs:
                result = result.replace(f"{{{var}}}", str(kwargs[var]))
        return result


class TemplateManager:
    """
    模板管理器
    
    特点：
    1. 支持从YAML文件加载模板
    2. 支持热重载
    3. 线程安全
    4. 支持模板分类和搜索
    """
    
    _instance: Optional['TemplateManager'] = None
    _lock = threading.Lock()
    
    def __new__(cls) -> 'TemplateManager':
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self._templates: Dict[str, Template] = {}
        self._categories: Dict[str, List[str]] = {}
        self._last_load_time: float = 0
        self._template_paths: List[str] = []
        self._auto_reload: bool = True
        self._reload_interval: int = 300
        self._initialized = True
    
    @classmethod
    def get_instance(cls) -> 'TemplateManager':
        """获取单例实例"""
        return cls()
    
    def add_template_path(self, path: str):
        """添加模板文件路径"""
        if os.path.exists(path) and path not in self._template_paths:
            self._template_paths.append(path)
            self._load_from_file(path)
    
    def _load_from_file(self, path: str):
        """从文件加载模板"""
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f) or {}
            
            if 'templates' in data:
                for item in data['templates']:
                    template = Template(
                        name=item.get('name', ''),
                        category=item.get('category', 'general'),
                        template=item.get('template', ''),
                        variables=item.get('variables', []),
                        metadata=item.get('metadata', {})
                    )
                    self._templates[template.name] = template
                    
                    if template.category not in self._categories:
                        self._categories[template.category] = []
                    self._categories[template.category].append(template.name)
            
            if 'payloads' in data:
                for category, payloads in data['payloads'].items():
                    for i, payload in enumerate(payloads):
                        template_name = f"{category}_{i}"
                        template = Template(
                            name=template_name,
                            category=category,
                            template=payload,
                            variables=['prompt', 'topic'],
                            metadata={'source': path}
                        )
                        self._templates[template_name] = template
                        
                        if category not in self._categories:
                            self._categories[category] = []
                        self._categories[category].append(template_name)
            
            self._last_load_time = time.time()
            logger.info(f"Loaded templates from {path}: {len(self._templates)} total templates")
            
        except Exception as e:
            logger.error(f"Failed to load templates from {path}: {e}")
    
    def reload(self):
        """重新加载所有模板"""
        self._templates.clear()
        self._categories.clear()
        
        for path in self._template_paths:
            self._load_from_file(path)
    
    def check_reload(self):
        """检查是否需要重新加载"""
        if not self._auto_reload:
            return
        
        if time.time() - self._last_load_time > self._reload_interval:
            for path in self._template_paths:
                if os.path.getmtime(path) > self._last_load_time:
                    self.reload()
                    break
    
    def get_template(self, name: str) -> Optional[Template]:
        """获取指定模板"""
        self.check_reload()
        return self._templates.get(name)
    
    def get_templates_by_category(self, category: str) -> List[Template]:
        """获取指定分类的所有模板"""
        self.check_reload()
        template_names = self._categories.get(category, [])
        return [self._templates[name] for name in template_names if name in self._templates]
    
    def get_all_categories(self) -> List[str]:
        """获取所有分类"""
        return list(self._categories.keys())
    
    def get_random_template(self, category: Optional[str] = None) -> Optional[Template]:
        """获取随机模板"""
        import random
        
        self.check_reload()
        
        if category:
            templates = self.get_templates_by_category(category)
        else:
            templates = list(self._templates.values())
        
        if templates:
            return random.choice(templates)
        return None
    
    def render_template(self, name: str, **kwargs) -> Optional[str]:
        """渲染指定模板"""
        template = self.get_template(name)
        if template:
            return template.render(**kwargs)
        return None
    
    def add_template(self, template: Template):
        """添加模板"""
        self._templates[template.name] = template
        
        if template.category not in self._categories:
            self._categories[template.category] = []
        self._categories[template.category].append(template.name)
    
    def get_stats(self) -> Dict[str, Any]:
        """获取模板统计信息"""
        return {
            "total_templates": len(self._templates),
            "categories": {cat: len(templates) for cat, templates in self._categories.items()},
            "template_paths": self._template_paths,
            "last_load_time": self._last_load_time
        }


def get_template_manager() -> TemplateManager:
    """获取全局模板管理器实例"""
    manager = TemplateManager.get_instance()
    
    default_paths = [
        "config/attack_templates.yaml",
        "config/attack_templates(content).yaml"
    ]
    
    for path in default_paths:
        full_path = os.path.join(os.getcwd(), path)
        if os.path.exists(full_path):
            manager.add_template_path(full_path)
    
    return manager
