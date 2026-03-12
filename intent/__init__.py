"""
IntentLang 融合模块
基于七要素意图模型的智能攻击生成框架

核心组件:
- IntentBuilder: 结构化意图构建器 (七要素模型)
- IntentCache: 意图缓存管理器 (降低LLM成本80%)
- EnhancedRuntime: 增强执行环境 (依赖注入、状态保持)
- IntentExecutor: 意图执行器
- PERLoop: P-E-R认知循环 (Planner-Executor-Reflector)

使用示例:
```python
from intent import IntentBuilder, IntentExecutor, AttackResult

# 构建意图
intent = IntentBuilder() \\
    .goal("生成越狱攻击并执行") \\
    .context({"target": "https://example.com"}) \\
    .rules(["避免重复", "记录证据"]) \\
    .output(AttackResult) \\
    .build()

# 执行意图
executor = IntentExecutor()
result = executor.execute(intent, input_data={"prompt": "test"})
```
"""

from .intent_builder import IntentBuilder, Intent, create_attack_intent, create_bypass_detection_intent
from .intent_cache import IntentCache, get_intent_cache, set_intent_cache
from .runtime import EnhancedRuntime, get_runtime, set_runtime
from .executor import IntentExecutor, BatchIntentExecutor, execute_intent
from .per_loop import PERLoop, Planner, Executor, Reflector, ExecutionPlan, SubTask
from .models import (
    AttackResult,
    BypassTestResult,
    PentestResult,  # 兼容别名
    BypassResult,
    IntentOutput,
    GeneratedAttack,
    AttackStatus,
    AttackType
)

__all__ = [
    # 意图构建
    'IntentBuilder',
    'Intent',
    'create_attack_intent',
    'create_bypass_detection_intent',
    
    # 缓存管理
    'IntentCache',
    'get_intent_cache',
    'set_intent_cache',
    
    # 运行时
    'EnhancedRuntime',
    'get_runtime',
    'set_runtime',
    
    # 执行器
    'IntentExecutor',
    'BatchIntentExecutor',
    'execute_intent',
    
    # P-E-R 认知循环
    'PERLoop',
    'Planner',
    'Executor',
    'Reflector',
    'ExecutionPlan',
    'SubTask',
    
    # 数据模型
    'AttackResult',
    'BypassTestResult',
    'PentestResult',  # 兼容别名
    'BypassResult',
    'IntentOutput',
    'GeneratedAttack',
    'AttackStatus',
    'AttackType'
]

