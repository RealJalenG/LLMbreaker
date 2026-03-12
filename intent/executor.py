"""
IntentExecutor - 意图执行器
集成IntentBuilder、IntentCache和EnhancedRuntime，实现完整的意图执行流程
"""

import logging
import time
import json
from typing import Dict, Any, Optional, Type, List, Callable
from pydantic import BaseModel
from datetime import datetime

from .intent_builder import Intent, IntentBuilder
from .intent_cache import IntentCache, get_intent_cache
from .runtime import EnhancedRuntime, get_runtime
from .models import AttackResult, BypassResult, IntentOutput

logger = logging.getLogger(__name__)


class IntentExecutor:
    """
    意图执行器
    
    实现P-E-R认知循环:
    - Planner: 解析意图，制定执行计划
    - Executor: 执行计划，调用工具
    - Reflector: 反思结果，学习优化
    
    使用示例:
    ```python
    executor = IntentExecutor()
    
    intent = IntentBuilder() \\
        .goal("生成越狱攻击并执行") \\
        .context({"target": "https://example.com"}) \\
        .rules(["避免重复", "记录证据"]) \\
        .output(AttackResult) \\
        .build()
    
    result = executor.execute(intent, input_data={"prompt": "test"})
    ```
    """
    
    def __init__(
        self,
        cache: IntentCache = None,
        runtime: EnhancedRuntime = None,
        llm_client: Any = None,
        enable_cache: bool = True,
        enable_reflection: bool = True
    ):
        """
        初始化执行器
        
        Args:
            cache: 意图缓存实例
            runtime: 运行时环境实例
            llm_client: LLM客户端（用于代码生成）
            enable_cache: 是否启用缓存
            enable_reflection: 是否启用反思
        """
        self.cache = cache or get_intent_cache()
        self.runtime = runtime or get_runtime()
        self.llm_client = llm_client
        self.enable_cache = enable_cache
        self.enable_reflection = enable_reflection
        
        # 执行统计
        self._stats = {
            'total_executions': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'successful_executions': 0,
            'failed_executions': 0,
            'total_time_ms': 0.0
        }
        
        # 反思历史
        self._reflections: List[Dict[str, Any]] = []
    
    def execute(
        self,
        intent: Intent,
        input_data: Dict[str, Any] = None,
        use_cache: bool = True
    ) -> Any:
        """
        执行意图
        
        Args:
            intent: 意图对象
            input_data: 输入数据
            use_cache: 是否使用缓存
        
        Returns:
            执行结果
        """
        start_time = time.time()
        self._stats['total_executions'] += 1
        
        try:
            # Phase 1: Plan - 解析意图，检查缓存
            cache_key = intent.get_cache_key()
            execution_code = None
            
            if self.enable_cache and use_cache:
                cached = self.cache.get(cache_key)
                if cached:
                    logger.info(f"缓存命中: {intent.intent_id}")
                    self._stats['cache_hits'] += 1
                    execution_code = cached
                else:
                    self._stats['cache_misses'] += 1
            
            # Phase 2: Execute - 执行计划
            if execution_code:
                # 使用缓存的代码执行
                result = self._execute_cached(intent, execution_code, input_data)
            else:
                # 直接执行（使用内置策略）
                result = self._execute_direct(intent, input_data)
                
                # 缓存成功的执行结果
                if self.enable_cache and result:
                    self.cache.set(
                        cache_key,
                        self._serialize_result(result),
                        intent_hash=intent.intent_id
                    )
            
            # Phase 3: Reflect - 反思结果
            if self.enable_reflection:
                self._reflect(intent, result, time.time() - start_time)
            
            self._stats['successful_executions'] += 1
            self._stats['total_time_ms'] += (time.time() - start_time) * 1000
            
            return result
            
        except Exception as e:
            self._stats['failed_executions'] += 1
            
            if self.enable_reflection:
                self._reflect_failure(intent, e)
            
            logger.error(f"意图执行失败: {e}")
            raise
    
    def _execute_cached(
        self,
        intent: Intent,
        cached_code: str,
        input_data: Dict[str, Any]
    ) -> Any:
        """执行缓存的代码"""
        # 注入意图相关的依赖
        self.runtime.inject('intent', intent)
        self.runtime.inject('context', intent.context)
        
        # 注入工具
        for tool in intent.tools:
            if callable(tool):
                self.runtime.inject_function(tool)
        
        # 执行代码
        return self.runtime.execute(
            cached_code,
            input_data=input_data,
            output_type=intent.output_type
        )
    
    def _execute_direct(
        self,
        intent: Intent,
        input_data: Dict[str, Any]
    ) -> Any:
        """直接执行（不使用LLM生成代码）"""
        # 根据目标类型选择执行策略
        goal = intent.goal.lower()
        
        if '攻击' in goal or 'attack' in goal:
            return self._execute_attack_intent(intent, input_data)
        elif '检测' in goal or 'detect' in goal or '绕过' in goal:
            return self._execute_bypass_detection_intent(intent, input_data)
        elif '生成' in goal or 'generate' in goal:
            return self._execute_generation_intent(intent, input_data)
        else:
            return self._execute_generic_intent(intent, input_data)
    
    def _execute_attack_intent(
        self,
        intent: Intent,
        input_data: Dict[str, Any]
    ) -> AttackResult:
        """执行攻击意图"""
        from core.attack_executor import execute_attack
        from core.bypass_detector import detect_bypass
        
        # 获取攻击参数
        attack_prompt = input_data.get('attack_prompt', '')
        config = intent.context.get('config', {})
        
        # 初始化状态
        state = self.runtime.get_state('attack_state', {
            'clientid_count': 0,
            'request_count': 0
        })
        
        start_time = time.time()
        
        # 执行攻击
        response, new_state = execute_attack(config, state, attack_prompt)
        
        # 保存状态
        self.runtime.set_state('attack_state', new_state)
        
        # 检测绕过
        is_bypassed = detect_bypass(response) if response else False
        
        execution_time = (time.time() - start_time) * 1000
        
        # 构建结果
        result = AttackResult(
            success=response is not None,
            message="攻击执行完成",
            attack_prompt=attack_prompt,
            attack_type=input_data.get('attack_type', 'General Attack'),
            response=response,
            status='success' if response else 'error',
            bypassed=is_bypassed,
            confidence=0.9 if is_bypassed else 0.1,
            execution_time_ms=execution_time,
            evidence=[f"Response length: {len(response) if response else 0}"]
        )
        
        return result
    
    def _execute_bypass_detection_intent(
        self,
        intent: Intent,
        input_data: Dict[str, Any]
    ) -> BypassResult:
        """执行绕过检测意图"""
        from core.bypass_detector import (
            detect_bypass, load_detector_config,
            check_blacklist, check_whitelist_absence,
            check_abnormal_chars
        )
        
        response_text = input_data.get('response_text', '')
        config = load_detector_config()
        
        start_time = time.time()
        
        # 多维度检测
        blacklist_triggered = check_blacklist(
            response_text, 
            config.get('blacklist_keywords', [])
        )
        whitelist_absent = check_whitelist_absence(
            response_text,
            config.get('whitelist_keywords', [])
        )
        abnormal_chars = check_abnormal_chars(
            response_text,
            config.get('consecutive_char_threshold', 10)
        )
        
        # 综合判断
        is_bypassed = detect_bypass(response_text, config)
        
        execution_time = (time.time() - start_time) * 1000
        
        # 计算风险评分
        risk_score = 0.0
        if blacklist_triggered:
            risk_score += 40
        if whitelist_absent:
            risk_score += 30
        if abnormal_chars:
            risk_score += 30
        
        result = BypassResult(
            success=True,
            message="检测完成",
            response_text=response_text[:500],  # 截断
            is_bypassed=is_bypassed,
            blacklist_triggered=blacklist_triggered,
            whitelist_absent=whitelist_absent,
            abnormal_chars=abnormal_chars,
            risk_score=risk_score,
            execution_time_ms=execution_time
        )
        
        return result
    
    def _execute_generation_intent(
        self,
        intent: Intent,
        input_data: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """执行生成意图"""
        from core.attack_generator import AttackGenerator
        
        topic = input_data.get('topic', 'general')
        count = input_data.get('count', 5)
        category = input_data.get('category', 'general')
        
        generator = AttackGenerator()
        attacks = generator.generate_attack_info(topic, count, category)
        
        return attacks
    
    def _execute_generic_intent(
        self,
        intent: Intent,
        input_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """执行通用意图"""
        return {
            'success': True,
            'intent_id': intent.intent_id,
            'goal': intent.goal,
            'input': input_data,
            'message': '通用意图执行完成'
        }
    
    def _serialize_result(self, result: Any) -> str:
        """序列化结果用于缓存"""
        if isinstance(result, BaseModel):
            return result.model_dump_json()
        elif isinstance(result, dict):
            return json.dumps(result, ensure_ascii=False)
        else:
            return str(result)
    
    def _reflect(self, intent: Intent, result: Any, duration: float):
        """反思执行结果"""
        reflection = {
            'timestamp': datetime.now().isoformat(),
            'intent_id': intent.intent_id,
            'goal': intent.goal,
            'duration_seconds': duration,
            'success': True,
            'insights': []
        }
        
        # 分析执行结果
        if isinstance(result, AttackResult):
            if result.bypassed:
                reflection['insights'].append("攻击成功绕过安全机制")
                reflection['insights'].append(f"置信度: {result.confidence}")
            else:
                reflection['insights'].append("攻击未能绕过安全机制")
        
        # 性能分析
        if duration > 5.0:
            reflection['insights'].append(f"执行时间较长({duration:.2f}s)，考虑优化")
        
        self._reflections.append(reflection)
        logger.debug(f"反思记录: {reflection}")
    
    def _reflect_failure(self, intent: Intent, error: Exception):
        """反思执行失败"""
        error_analysis = self.runtime.analyze_error(error)
        
        reflection = {
            'timestamp': datetime.now().isoformat(),
            'intent_id': intent.intent_id,
            'goal': intent.goal,
            'success': False,
            'error': error_analysis,
            'suggestions': [error_analysis['suggestion']]
        }
        
        self._reflections.append(reflection)
        logger.warning(f"失败反思: {reflection}")
    
    def get_stats(self) -> Dict[str, Any]:
        """获取执行统计"""
        stats = self._stats.copy()
        
        if stats['total_executions'] > 0:
            stats['success_rate'] = f"{(stats['successful_executions'] / stats['total_executions'] * 100):.2f}%"
            stats['cache_hit_rate'] = f"{(stats['cache_hits'] / stats['total_executions'] * 100):.2f}%"
            stats['avg_time_ms'] = f"{(stats['total_time_ms'] / stats['total_executions']):.2f}"
        
        return stats
    
    def get_reflections(self, limit: int = 10) -> List[Dict[str, Any]]:
        """获取反思历史"""
        return self._reflections[-limit:]
    
    def clear_reflections(self):
        """清空反思历史"""
        self._reflections.clear()


class BatchIntentExecutor:
    """批量意图执行器"""
    
    def __init__(self, executor: IntentExecutor = None, max_workers: int = 5):
        """
        初始化批量执行器
        
        Args:
            executor: 意图执行器
            max_workers: 最大并发数
        """
        self.executor = executor or IntentExecutor()
        self.max_workers = max_workers
    
    def execute_batch(
        self,
        intents: List[Intent],
        input_data_list: List[Dict[str, Any]] = None
    ) -> List[Any]:
        """
        批量执行意图
        
        Args:
            intents: 意图列表
            input_data_list: 输入数据列表
        
        Returns:
            结果列表
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        if input_data_list is None:
            input_data_list = [{}] * len(intents)
        
        results = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {
                pool.submit(self.executor.execute, intent, input_data): i
                for i, (intent, input_data) in enumerate(zip(intents, input_data_list))
            }
            
            for future in as_completed(futures):
                idx = futures[future]
                try:
                    result = future.result()
                    results.append((idx, result))
                except Exception as e:
                    logger.error(f"批量执行失败[{idx}]: {e}")
                    results.append((idx, None))
        
        # 按原顺序排序
        results.sort(key=lambda x: x[0])
        return [r[1] for r in results]


# 便捷函数
def execute_intent(intent: Intent, input_data: Dict[str, Any] = None) -> Any:
    """便捷执行函数"""
    executor = IntentExecutor()
    return executor.execute(intent, input_data)
