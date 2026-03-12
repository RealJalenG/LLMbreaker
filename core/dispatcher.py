"""
LLMbreaker 统一调度器
基于IntentLang理念的智能攻击调度中心

设计理念：
1. 简化入口 - 一个命令完成所有操作
2. 智能策略 - 根据场景自动选择最佳攻击方式
3. 配置分离 - 复杂配置放文件，命令行只保留核心参数
4. 统一接口 - 所有攻击模式通过统一接口调度

使用示例：
    # 快速攻击（自动选择策略）
    llmbreaker attack "越狱测试"
    
    # 指定策略
    llmbreaker attack "敏感话题" --strategy multi-round
    
    # 使用配置文件
    llmbreaker attack --config attack_config.yaml
"""

import logging
import os
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

logger = logging.getLogger(__name__)


class AttackStrategy(Enum):
    """攻击策略枚举"""
    AUTO = "auto"               # 自动选择最佳策略
    SINGLE = "single"           # 单轮攻击
    MULTI_ROUND = "multi-round" # 多轮对话攻击
    STATIC = "static"           # 静态样本攻击
    BATCH = "batch"             # 批量攻击


class TargetType(Enum):
    """目标类型枚举"""
    LLM_API = "llm-api"         # LLM API接口
    CHATBOT = "chatbot"         # 对话机器人
    CUSTOM = "custom"           # 自定义目标


@dataclass
class AttackConfig:
    """
    攻击配置 - 统一的配置数据类
    """
    # 核心参数
    topic: str = ""                          # 攻击话题
    strategy: AttackStrategy = AttackStrategy.AUTO  # 攻击策略
    count: int = 10                          # 攻击数量
    
    # 目标配置
    target_url: str = ""                     # 目标URL
    target_type: TargetType = TargetType.LLM_API
    
    # 执行参数
    max_rounds: int = 10                     # 多轮攻击最大轮次
    max_workers: int = 5                     # 并发数
    qps_limit: int = 10                     # QPS限制
    interval: float = 1.0                    # 请求间隔
    
    # 智能特性开关
    enable_cache: bool = True                # 启用意图缓存
    enable_reflection: bool = True           # 启用AI反思
    enable_induction: bool = True            # 启用诱导策略
    
    # 高级配置
    request_template: Dict = field(default_factory=dict)
    injection_rules: Dict = field(default_factory=dict)
    custom_headers: Dict = field(default_factory=dict)
    session_manager: Optional[Any] = None # 会话管理器

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AttackConfig':
        """从字典创建配置"""
        config = cls()
        for key, value in data.items():
            if hasattr(config, key):
                if key == 'strategy' and isinstance(value, str):
                    value = AttackStrategy(value)
                elif key == 'target_type' and isinstance(value, str):
                    value = TargetType(value)
                setattr(config, key, value)
        return config
    
    @classmethod
    def from_yaml(cls, filepath: str) -> 'AttackConfig':
        """从YAML文件加载配置"""
        import yaml
        with open(filepath, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        return cls.from_dict(data)


@dataclass
class AttackResult:
    """攻击结果数据类"""
    success: bool = False
    total_attacks: int = 0
    bypassed_count: int = 0
    bypass_rate: float = 0.0
    strategy_used: str = ""
    execution_time_ms: float = 0.0
    details: List[Dict] = field(default_factory=list)
    session_info: Dict = field(default_factory=dict)
    reflections: List[Dict] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'success': self.success,
            'total_attacks': self.total_attacks,
            'bypassed_count': self.bypassed_count,
            'bypass_rate': self.bypass_rate,
            'strategy_used': self.strategy_used,
            'execution_time_ms': self.execution_time_ms,
            'details': self.details,
            'session_info': self.session_info,
            'reflections': self.reflections
        }


class AttackDispatcher:
    """
    攻击调度器 - 统一管理所有攻击流程
    
    核心职责：
    1. 解析配置，选择最佳策略
    2. 调度执行器完成攻击
    3. 收集结果，生成报告
    """
    
    def __init__(self, config: AttackConfig = None):
        """
        初始化调度器
        
        Args:
            config: 攻击配置
        """
        self.config = config or AttackConfig()
        self._load_settings()
        
        # 策略映射
        self._strategy_handlers = {
            AttackStrategy.AUTO: self._execute_auto,
            AttackStrategy.SINGLE: self._execute_single,
            AttackStrategy.MULTI_ROUND: self._execute_multi_round,
            AttackStrategy.STATIC: self._execute_static,
            AttackStrategy.BATCH: self._execute_batch,
        }
    
    def _load_settings(self):
        """加载默认设置"""
        try:
            from config.settings import Settings
            self.settings = Settings()
            
            # 填充默认值
            if not self.config.target_url:
                self.config.target_url = self.settings.TARGET_URL
        except Exception as e:
            logger.warning(f"加载设置失败: {e}")
            self.settings = None
    
    def run(self, topic: str = None) -> AttackResult:
        """
        运行攻击
        
        Args:
            topic: 攻击话题（覆盖配置中的topic）
            
        Returns:
            攻击结果
        """
        if topic:
            self.config.topic = topic
        
        if not self.config.topic:
            raise ValueError("必须指定攻击话题")
        
        logger.info("=" * 60)
        logger.info("LLMbreaker 统一调度器")
        logger.info("=" * 60)
        logger.info(f"话题: {self.config.topic}")
        logger.info(f"策略: {self.config.strategy.value}")
        logger.info(f"目标: {self.config.target_url}")
        
        start_time = datetime.now()
        
        # 选择并执行策略
        handler = self._strategy_handlers.get(
            self.config.strategy, 
            self._execute_auto
        )
        result = handler()
        
        # 计算执行时间
        result.execution_time_ms = (datetime.now() - start_time).total_seconds() * 1000
        result.strategy_used = self.config.strategy.value
        
        # 输出结果
        self._print_result(result)
        
        return result
    
    def _execute_auto(self) -> AttackResult:
        """
        自动策略 - 智能选择最佳攻击方式
        """
        logger.info("自动策略选择...")
        
        # 策略选择逻辑
        topic = self.config.topic.lower()
        
        # 1. 如果话题包含敏感词，使用多轮诱导
        sensitive_keywords = ['绕过', '越狱', '破解', '攻击', '漏洞', '注入', '敏感']
        if any(kw in topic for kw in sensitive_keywords):
            logger.info("检测到敏感话题，选择多轮诱导策略")
            self.config.strategy = AttackStrategy.MULTI_ROUND
            return self._execute_multi_round()
        
        # 2. 如果数量较大，使用批量攻击
        if self.config.count > 20:
            logger.info(f"攻击数量较多({self.config.count})，选择批量策略")
            self.config.strategy = AttackStrategy.BATCH
            return self._execute_batch()
        
        # 3. 默认使用单轮攻击
        logger.info("选择单轮攻击策略")
        self.config.strategy = AttackStrategy.SINGLE
        return self._execute_single()
    
    def _execute_single(self) -> AttackResult:
        """
        单轮攻击 - 使用意图驱动生成并执行
        """
        logger.info("执行单轮攻击...")
        
        try:
            from core.intent_attack_generator import IntentDrivenAttackGenerator
            from core.intent_attack_executor import IntentDrivenAttackExecutor
            from intent import get_intent_cache
            
            # 创建生成器
            cache = get_intent_cache() if self.config.enable_cache else None
            generator = IntentDrivenAttackGenerator(
                cache=cache,
                enable_cache=self.config.enable_cache
            )
            
            # 生成攻击
            attacks = generator.generate(
                topic=self.config.topic,
                count=self.config.count,
                category="jailbreak",
                include_jailbreak=True
            )
            
            logger.info(f"生成 {len(attacks)} 个攻击")
            
            # 转换为字典列表（兼容executor期望的格式）
            attack_dicts = [
                a.model_dump() if hasattr(a, 'model_dump') else a
                for a in attacks
            ]
            
            # 创建执行器
            executor_config = self._build_executor_config()
            
            # 注入会话信息
            if self.config.session_manager:
                state = self.config.session_manager.get_fixed_state()
                executor_config.update({
                    'clientid': state['clientid'],
                    'uid': state['uid']
                })
            
            executor = IntentDrivenAttackExecutor(
                config=executor_config,
                cache=cache
            )
            
            # 执行攻击
            bypass_result = executor.run_bypass_test(attack_dicts)
            
            return AttackResult(
                success=bypass_result.successful_bypasses > 0,
                total_attacks=bypass_result.total_attacks,
                bypassed_count=bypass_result.successful_bypasses,
                bypass_rate=bypass_result.bypass_rate,
                details=[r.model_dump() if hasattr(r, 'model_dump') else r for r in bypass_result.attack_results]
            )
            
        except Exception as e:
            logger.error(f"单轮攻击失败: {e}")
            import traceback
            traceback.print_exc()
            return AttackResult(success=False)
    
    def _execute_multi_round(self) -> AttackResult:
        """
        多轮对话攻击 - 固定会话+AI反思+诱导
        """
        logger.info("执行多轮对话攻击...")
        
        try:
            from core.intelligent_multi_round import run_intelligent_multi_round_attack
            
            config = self._build_executor_config()
            
            result = run_intelligent_multi_round_attack(
                config=config,
                topic=self.config.topic,
                max_rounds=self.config.max_rounds,
                use_ai_reflection=self.config.enable_reflection,
                use_induction=self.config.enable_induction,
                session_manager=self.config.session_manager
            )
            
            return AttackResult(
                success=result['attack_success'],
                total_attacks=result['total_rounds'],
                bypassed_count=1 if result['attack_success'] else 0,
                bypass_rate=100.0 if result['attack_success'] else 0.0,
                session_info=result['session_info'],
                reflections=result.get('reflections', [])
            )
            
        except Exception as e:
            logger.error(f"多轮攻击失败: {e}")
            import traceback
            traceback.print_exc()
            return AttackResult(success=False)
    
    def _execute_static(self) -> AttackResult:
        """
        静态样本攻击 - 使用预定义样本库
        """
        logger.info("执行静态样本攻击...")
        
        try:
            from core.static_sample_manager import static_sample_manager
            from custom_attack import run_attack_test
            
            # 获取静态样本
            samples = static_sample_manager.get_random_samples(
                count=self.config.count
            )
            
            if not samples:
                logger.warning("未找到静态样本")
                return AttackResult(success=False)
            
            logger.info(f"获取 {len(samples)} 个静态样本")
            
            # 准备攻击数据
            attack_phrases = [{
                'prompt_text': s.get('payload', ''),
                'attack_type': 'Static',
                'id': s.get('id'),
                'scenario': 'Static Sample'
            } for s in samples]
            
            # 执行攻击
            config = self._build_executor_config()
            results = run_attack_test(
                config=config,
                attack_phrases=attack_phrases,
                source_type='static',
                max_workers=self.config.max_workers
            )
            
            # 统计结果
            bypassed = sum(1 for r in results if r.get('bypassed', False))
            
            return AttackResult(
                success=bypassed > 0,
                total_attacks=len(results),
                bypassed_count=bypassed,
                bypass_rate=(bypassed / len(results) * 100) if results else 0.0,
                details=results
            )
            
        except Exception as e:
            logger.error(f"静态攻击失败: {e}")
            import traceback
            traceback.print_exc()
            return AttackResult(success=False)
    
    def _execute_batch(self) -> AttackResult:
        """
        批量攻击 - 并发执行多个攻击
        """
        logger.info("执行批量攻击...")
        
        try:
            from core.attack_generator import create_attack_generator
            from custom_attack import run_attack_test
            
            # 生成攻击
            generator = create_attack_generator()
            attack_infos = generator.generate_attack_info(
                topic=self.config.topic,
                count=self.config.count
            )
            
            logger.info(f"生成 {len(attack_infos)} 个攻击")
            
            # 准备攻击数据
            attack_phrases = [{
                'prompt_text': a['prompt_text'],
                'attack_type': a.get('attack_type', 'Batch'),
                'id': a.get('id'),
                'scenario': f"Batch attack for: {self.config.topic}"
            } for a in attack_infos]
            
            # 执行攻击
            config = self._build_executor_config()
            results = run_attack_test(
                config=config,
                attack_phrases=attack_phrases,
                source_type='batch',
                max_workers=self.config.max_workers
            )
            
            # 统计结果
            bypassed = sum(1 for r in results if r.get('bypassed', False))
            
            return AttackResult(
                success=bypassed > 0,
                total_attacks=len(results),
                bypassed_count=bypassed,
                bypass_rate=(bypassed / len(results) * 100) if results else 0.0,
                details=results
            )
            
        except Exception as e:
            logger.error(f"批量攻击失败: {e}")
            import traceback
            traceback.print_exc()
            return AttackResult(success=False)
    
    def _build_executor_config(self) -> Dict[str, Any]:
        """构建执行器配置"""
        config = {
            'target_url': self.config.target_url,
            'qps_limit': self.config.qps_limit,
            'interval': self.config.interval,
        }
        
        if self.settings:
            config.update({
                'user_agents': self.settings.USER_AGENTS,
                'xff_ips': self.settings.XFF_IPS,
                'request_template': self.settings.DEFAULT_REQUEST_TEMPLATE,
                'injection_rules': self.settings.DEFAULT_INJECTION_RULES,
            })
        
        if self.config.request_template:
            config['request_template'] = self.config.request_template
        if self.config.injection_rules:
            config['injection_rules'] = self.config.injection_rules
        if self.config.custom_headers:
            config['custom_headers'] = self.config.custom_headers
        
        return config
    
    def _print_result(self, result: AttackResult):
        """打印结果"""
        logger.info("\n" + "=" * 60)
        logger.info("攻击结果")
        logger.info("=" * 60)
        logger.info(f"策略: {result.strategy_used}")
        logger.info(f"总攻击数: {result.total_attacks}")
        logger.info(f"成功绕过: {result.bypassed_count}")
        logger.info(f"绕过率: {result.bypass_rate:.2f}%")
        logger.info(f"执行时间: {result.execution_time_ms:.2f}ms")
        logger.info(f"结果: {'✅ 成功' if result.success else '❌ 未成功'}")
        logger.info("=" * 60)


def quick_attack(topic: str, **kwargs) -> AttackResult:
    """
    快速攻击函数 - 最简化的使用方式
    
    Args:
        topic: 攻击话题
        **kwargs: 其他配置参数
        
    Returns:
        攻击结果
        
    Usage:
        from core.dispatcher import quick_attack
        result = quick_attack("越狱测试")
    """
    config = AttackConfig(topic=topic)
    for key, value in kwargs.items():
        if hasattr(config, key):
            setattr(config, key, value)
    
    dispatcher = AttackDispatcher(config)
    return dispatcher.run()
