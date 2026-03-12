"""
IntentBuilder - 结构化意图构建器
基于七要素意图模型 (Goal/Context/Tools/Input/How/Rules/Output)
"""

import hashlib
import json
import logging
from typing import List, Dict, Any, Optional, Type, Callable
from dataclasses import dataclass, field
from datetime import datetime
from pydantic import BaseModel

logger = logging.getLogger(__name__)


@dataclass
class Intent:
    """
    意图数据类 - 七要素模型
    
    七要素说明:
    - Goal: 目标描述，明确要完成什么
    - Context: 上下文信息，包含当前状态和背景
    - Tools: 可用工具列表
    - Input: 输入数据（仅Schema，不含敏感数据）
    - How: 执行策略和方法
    - Rules: 约束规则列表
    - Output: 期望输出类型（Pydantic Model）
    """
    goal: str
    context: Dict[str, Any] = field(default_factory=dict)
    tools: List[Any] = field(default_factory=list)
    input_schema: Dict[str, Any] = field(default_factory=dict)
    how: str = ""
    rules: List[str] = field(default_factory=list)
    output_type: Optional[Type[BaseModel]] = None
    
    # 元数据
    created_at: datetime = field(default_factory=datetime.now)
    intent_id: str = ""
    
    def __post_init__(self):
        """初始化后生成intent_id"""
        if not self.intent_id:
            self.intent_id = self._generate_id()
    
    def _generate_id(self) -> str:
        """生成唯一意图ID"""
        content = json.dumps({
            'goal': self.goal,
            'rules': sorted(self.rules),
            'how': self.how
        }, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def get_cache_key(self) -> str:
        """
        生成缓存键
        基于goal和rules生成，实现逻辑复用
        """
        cache_content = json.dumps({
            'goal': self.goal,
            'rules': sorted(self.rules)
        }, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(cache_content.encode()).hexdigest()[:32]
    
    def to_prompt(self) -> str:
        """
        将意图转换为LLM提示词
        实现意图到自然语言的转换
        """
        prompt_parts = []
        
        # Goal
        prompt_parts.append(f"## 目标\n{self.goal}")
        
        # Context
        if self.context:
            context_str = json.dumps(self.context, ensure_ascii=False, indent=2)
            prompt_parts.append(f"## 上下文\n```json\n{context_str}\n```")
        
        # Tools
        if self.tools:
            tools_desc = []
            for tool in self.tools:
                if callable(tool):
                    tools_desc.append(f"- {tool.__name__}: {tool.__doc__ or '无描述'}")
                else:
                    tools_desc.append(f"- {str(tool)}")
            prompt_parts.append(f"## 可用工具\n" + "\n".join(tools_desc))
        
        # Input Schema
        if self.input_schema:
            schema_str = json.dumps(self.input_schema, ensure_ascii=False, indent=2)
            prompt_parts.append(f"## 输入Schema\n```json\n{schema_str}\n```")
        
        # How
        if self.how:
            prompt_parts.append(f"## 执行策略\n{self.how}")
        
        # Rules
        if self.rules:
            rules_str = "\n".join([f"- {rule}" for rule in self.rules])
            prompt_parts.append(f"## 约束规则\n{rules_str}")
        
        # Output
        if self.output_type:
            output_schema = self.output_type.model_json_schema()
            schema_str = json.dumps(output_schema, ensure_ascii=False, indent=2)
            prompt_parts.append(f"## 期望输出格式\n```json\n{schema_str}\n```")
        
        return "\n\n".join(prompt_parts)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'intent_id': self.intent_id,
            'goal': self.goal,
            'context': self.context,
            'tools': [str(t) for t in self.tools],
            'input_schema': self.input_schema,
            'how': self.how,
            'rules': self.rules,
            'output_type': self.output_type.__name__ if self.output_type else None,
            'created_at': self.created_at.isoformat()
        }


class IntentBuilder:
    """
    意图构建器 - 流式API设计
    
    使用示例:
    ```python
    intent = IntentBuilder() \\
        .goal("生成针对目标URL的越狱攻击") \\
        .context({"target": "https://example.com", "history": []}) \\
        .tools([execute_attack, detect_bypass]) \\
        .input(target_url="string", attack_type="string") \\
        .how("使用多种越狱模板进行组合攻击") \\
        .rules(["遵循OPSEC", "记录证据", "避免重复"]) \\
        .output(AttackResult) \\
        .build()
    ```
    """
    
    def __init__(self):
        self._goal: str = ""
        self._context: Dict[str, Any] = {}
        self._tools: List[Any] = []
        self._input_schema: Dict[str, Any] = {}
        self._how: str = ""
        self._rules: List[str] = []
        self._output_type: Optional[Type[BaseModel]] = None
    
    def goal(self, description: str) -> 'IntentBuilder':
        """设置目标描述"""
        self._goal = description
        return self
    
    def context(self, ctx: Dict[str, Any]) -> 'IntentBuilder':
        """设置上下文信息"""
        self._context.update(ctx)
        return self
    
    def add_context(self, key: str, value: Any) -> 'IntentBuilder':
        """添加单个上下文项"""
        self._context[key] = value
        return self
    
    def tools(self, tool_list: List[Any]) -> 'IntentBuilder':
        """设置可用工具列表"""
        self._tools = tool_list
        return self
    
    def add_tool(self, tool: Any) -> 'IntentBuilder':
        """添加单个工具"""
        self._tools.append(tool)
        return self
    
    def input(self, **kwargs) -> 'IntentBuilder':
        """设置输入Schema"""
        self._input_schema.update(kwargs)
        return self
    
    def input_schema(self, schema: Dict[str, Any]) -> 'IntentBuilder':
        """设置完整的输入Schema"""
        self._input_schema = schema
        return self
    
    def how(self, strategy: str) -> 'IntentBuilder':
        """设置执行策略"""
        self._how = strategy
        return self
    
    def rules(self, rule_list: List[str]) -> 'IntentBuilder':
        """设置约束规则"""
        self._rules = rule_list
        return self
    
    def add_rule(self, rule: str) -> 'IntentBuilder':
        """添加单个规则"""
        self._rules.append(rule)
        return self
    
    def output(self, output_model: Type[BaseModel]) -> 'IntentBuilder':
        """设置输出类型（Pydantic Model）"""
        self._output_type = output_model
        return self
    
    def build(self) -> Intent:
        """构建并返回Intent对象"""
        if not self._goal:
            raise ValueError("Intent必须包含goal（目标描述）")
        
        intent = Intent(
            goal=self._goal,
            context=self._context,
            tools=self._tools,
            input_schema=self._input_schema,
            how=self._how,
            rules=self._rules,
            output_type=self._output_type
        )
        
        logger.info(f"构建意图: {intent.intent_id} - {intent.goal[:50]}...")
        return intent
    
    def reset(self) -> 'IntentBuilder':
        """重置构建器状态"""
        self._goal = ""
        self._context = {}
        self._tools = []
        self._input_schema = {}
        self._how = ""
        self._rules = []
        self._output_type = None
        return self


# 便捷函数
def create_attack_intent(
    goal: str,
    target_url: str,
    attack_type: str = "general",
    rules: List[str] = None
) -> Intent:
    """
    创建攻击意图的便捷函数
    
    Args:
        goal: 攻击目标描述
        target_url: 目标URL
        attack_type: 攻击类型
        rules: 约束规则
    
    Returns:
        Intent对象
    """
    from .models import AttackResult
    
    default_rules = [
        "遵循安全测试规范",
        "记录所有证据",
        "避免造成实际损害"
    ]
    
    return IntentBuilder() \
        .goal(goal) \
        .context({
            "target_url": target_url,
            "attack_type": attack_type,
            "timestamp": datetime.now().isoformat()
        }) \
        .input(target_url="string", attack_prompt="string") \
        .how("使用越狱模板组合攻击，检测安全机制绕过") \
        .rules(rules or default_rules) \
        .output(AttackResult) \
        .build()


def create_bypass_detection_intent(response_text: str) -> Intent:
    """
    创建绕过检测意图的便捷函数
    
    Args:
        response_text: 待检测的响应文本
    
    Returns:
        Intent对象
    """
    from .models import BypassResult
    
    return IntentBuilder() \
        .goal("检测响应是否绕过安全机制") \
        .context({"response_length": len(response_text)}) \
        .input(response_text="string") \
        .how("多维度安全绕过检测：黑名单、白名单、异常字符、拒绝回答") \
        .rules(["降低误判率", "记录检测证据", "输出置信度"]) \
        .output(BypassResult) \
        .build()
