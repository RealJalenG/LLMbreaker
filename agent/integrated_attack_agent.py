import asyncio
import json
import logging
from typing import Dict, Any, List, Optional, AsyncIterator
from dataclasses import dataclass, field
from enum import Enum
import time
from pathlib import Path

from core.integrated_attack_engine import (
    IntegratedAttackEngine, 
    IntegratedAttackConfig,
    AttackType
)
from reports.report_generator import generate_report
# 注释掉缺失的模块导入
# from core.memory_optimizer import MemoryOptimizedAttackExecutor
# from core.security_enhancer import SecurityManager

logger = logging.getLogger(__name__)


class AttackPhase(Enum):
    """攻击阶段枚举"""
    RECONNAISSANCE = "reconnaissance"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    CLEANUP = "cleanup"


class AttackIntent(Enum):
    """攻击意图枚举"""
    JAILBREAK = "jailbreak"
    BYPASS_SECURITY = "bypass_security"
    EXTRACT_INFORMATION = "extract_information"
    TEST_VULNERABILITY = "test_vulnerability"
    RED_TEAM_ASSESSMENT = "red_team_assessment"


@dataclass
class AttackContext:
    """攻击上下文"""
    target_system: str = ""
    target_model: str = ""
    attack_intent: AttackIntent = AttackIntent.JAILBREAK
    constraints: List[str] = field(default_factory=list)
    success_criteria: List[str] = field(default_factory=list)
    environment_info: Dict[str, Any] = field(default_factory=dict)
    previous_attempts: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class AttackObservation:
    """攻击观察结果"""
    phase: AttackPhase
    action: str
    response: str
    success: bool
    confidence: float
    metadata: Dict[str, Any] = field(default_factory=dict)


class AttackCapability:
    """攻击能力基类"""
    
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.success_rate = 0.0
        self.usage_count = 0
    
    async def execute(self, context: AttackContext, **kwargs) -> AttackObservation:
        """执行攻击能力"""
        raise NotImplementedError
    
    def update_metrics(self, success: bool):
        """更新能力指标"""
        self.usage_count += 1
        if self.usage_count > 0:
            self.success_rate = ((self.success_rate * (self.usage_count - 1)) + (1.0 if success else 0.0)) / self.usage_count


class ReconnaissanceCapability(AttackCapability):
    """侦察能力 - 目标识别和信息收集"""
    
    def __init__(self):
        super().__init__("reconnaissance", "目标系统侦察和信息收集")
    
    async def execute(self, context: AttackContext, **kwargs) -> AttackObservation:
        """执行侦察"""
        logger.info(f"开始侦察目标: {context.target_system}")
        
        # 模拟侦察过程
        recon_data = {
            "target_type": "LLM_API",
            "security_level": "high",
            "detected_defenses": ["input_filtering", "output_monitoring", "rate_limiting"],
            "potential_vulnerabilities": [
                "prompt_jailbreak", 
                "instruction_injection", 
                "context_pollution",
                "encoding_bypass"
            ],
            "response_patterns": ["polite_refusal", "safety_warning", "redirect_response"]
        }
        
        return AttackObservation(
            phase=AttackPhase.RECONNAISSANCE,
            action="system_analysis",
            response=json.dumps(recon_data),
            success=True,
            confidence=0.85,
            metadata={"target_analyzed": True}
        )


class VulnerabilityAnalysisCapability(AttackCapability):
    """漏洞分析能力 - 基于侦察结果分析漏洞"""
    
    def __init__(self):
        super().__init__("vulnerability_analysis", "漏洞分析和利用链构建")
    
    async def execute(self, context: AttackContext, **kwargs) -> AttackObservation:
        """执行漏洞分析"""
        logger.info("开始漏洞分析")
        
        # 基于侦察结果选择攻击策略
        vulnerabilities = {
            "stratasword": {
                "effectiveness": 0.7,
                "complexity": "medium",
                "detection_risk": "low"
            },
            "ascii_smuggling": {
                "effectiveness": 0.8,
                "complexity": "high",
                "detection_risk": "very_low"
            },
            "context_manipulation": {
                "effectiveness": 0.9,
                "complexity": "low",
                "detection_risk": "medium"
            }
        }
        
        # 根据攻击意图选择最佳策略
        if context.attack_intent == AttackIntent.JAILBREAK:
            selected_strategies = ["context_manipulation", "ascii_smuggling", "multi_turn"]
        elif context.attack_intent == AttackIntent.BYPASS_SECURITY:
            selected_strategies = ["stratasword", "ascii_smuggling"]
        else:
            selected_strategies = ["stratasword"]
        
        return AttackObservation(
            phase=AttackPhase.VULNERABILITY_ANALYSIS,
            action="strategy_selection",
            response=json.dumps({"selected_strategies": selected_strategies, "vulnerabilities": vulnerabilities}),
            success=True,
            confidence=0.9,
            metadata={"strategies_selected": selected_strategies}
        )


class ExploitationCapability(AttackCapability):
    """利用能力 - 执行具体攻击"""
    
    def __init__(self):
        super().__init__("exploitation", "执行攻击利用")
        self.engine = IntegratedAttackEngine()
        # 移除缺失的模块引用
        self.memory_optimizer = None
        self.security_manager = None
    
    async def execute(self, context: AttackContext, strategies: List[str], **kwargs) -> AttackObservation:
        """执行攻击利用"""
        logger.info(f"开始攻击利用，策略: {strategies}")
        
        # Update engine config
        self.engine.config.topic = kwargs.get("topic", context.target_model)
        self.engine.config.count = kwargs.get("count", 5)
        self.engine.config.attack_types = [AttackType(s) for s in strategies]
        self.engine.config.enable_optimization = False
        self.engine.config.enable_security = False
        self.engine.config.memory_limit_mb = 256
        
        # 生成并执行攻击
        await self.engine.initialize()
        try:
            attacks = self.engine.generate_attacks()
            
            # Execute
            results = await self.engine.execute_attacks(attacks)
            
            # Persist results if needed (for backward compatibility, keep it minimal or move out)
            # In legacy mode, we might not want side effects here, but to match recent changes:
            for res in results:
                 report_data = {
                     'attack_type': res.get('type', 'unknown'),
                     'attack_prompt': res.get('payload', ''),
                     'response': res.get('response', ''),
                     'bypassed': res.get('bypassed', False),
                     'scenario': self.engine.config.topic
                 }
                 try:
                     generate_report(report_data)
                 except Exception as e:
                     logger.error(f"Failed to generate report: {e}")

            report = self.engine.get_attack_report(results)
            
            return AttackObservation(
                phase=AttackPhase.EXPLOITATION,
                action="attack_execution",
                response=json.dumps(report),
                success=report["successful_bypasses"] > 0,
                confidence=report["bypass_rate"],
                metadata={"attack_report": report}
            )
        finally:
            await self.engine.cleanup()


class PostExploitationCapability(AttackCapability):
    """后利用能力 - 分析攻击结果并优化策略"""
    
    def __init__(self):
        super().__init__("post_exploitation", "攻击结果分析和策略优化")
    
    async def execute(self, context: AttackContext, attack_results: Dict[str, Any], **kwargs) -> AttackObservation:
        """分析攻击结果并制定后续策略"""
        logger.info("开始攻击结果分析")
        
        # 分析攻击效果
        analysis = {
            "successful_techniques": [],
            "failed_techniques": [],
            "system_responses": [],
            "next_steps": []
        }
        
        # 基于结果调整策略
        if attack_results.get("bypass_rate", 0) > 0.5:
            analysis["next_steps"] = ["refine_successful_techniques", "scale_attack"]
        else:
            analysis["next_steps"] = ["try_alternative_strategies", "increase_complexity"]
        
        return AttackObservation(
            phase=AttackPhase.POST_EXPLOITATION,
            action="result_analysis",
            response=json.dumps(analysis),
            success=True,
            confidence=0.95,
            metadata={"analysis": analysis}
        )


class IntegratedAttackAgent:
    """集成攻击Agent - 端到端攻击能力"""
    
    def __init__(self):
        self.capabilities = {
            AttackPhase.RECONNAISSANCE: ReconnaissanceCapability(),
            AttackPhase.VULNERABILITY_ANALYSIS: VulnerabilityAnalysisCapability(),
            AttackPhase.EXPLOITATION: ExploitationCapability(),
            AttackPhase.POST_EXPLOITATION: PostExploitationCapability()
        }
        self.context = AttackContext()
        self.observations = []
        self.attack_history = []
    
    async def set_target(self, target_system: str, target_model: str, attack_intent: AttackIntent, attack_topic: str = ""):
        """设置攻击目标"""
        self.context.target_system = target_system
        self.context.target_model = target_model
        self.context.attack_intent = attack_intent
        self.context.attack_topic = attack_topic
        logger.info(f"设置攻击目标: {target_system} - {target_model} - {attack_intent.value} - Topic: {attack_topic}")
    
    async def execute_attack_mission(self, max_iterations: int = 3) -> Dict[str, Any]:
        """执行完整的攻击任务"""
        logger.info("开始执行攻击任务")
        
        mission_result = {
            "success": False,
            "phases": [],
            "final_report": {},
            "recommendations": []
        }
        
        try:
            # 阶段1: 侦察
            recon_obs = await self.capabilities[AttackPhase.RECONNAISSANCE].execute(self.context)
            mission_result["phases"].append(recon_obs)
            
            # 阶段2: 漏洞分析
            vuln_obs = await self.capabilities[AttackPhase.VULNERABILITY_ANALYSIS].execute(self.context)
            mission_result["phases"].append(vuln_obs)
            
            # 提取策略
            strategies_data = json.loads(vuln_obs.response)
            selected_strategies = strategies_data.get("selected_strategies", ["stratasword"])
            
            # 阶段3: 利用
            exploit_obs = await self.capabilities[AttackPhase.EXPLOITATION].execute(
                self.context, 
                strategies=selected_strategies
            )
            mission_result["phases"].append(exploit_obs)
            
            # 阶段4: 后利用分析
            post_obs = await self.capabilities[AttackPhase.POST_EXPLOITATION].execute(
                self.context, 
                attack_results=json.loads(exploit_obs.response)
            )
            mission_result["phases"].append(post_obs)
            
            # 生成最终报告
            mission_result["final_report"] = self._generate_final_report(mission_result["phases"])
            mission_result["success"] = mission_result["final_report"]["overall_success"]
            
            # 记录历史
            self.attack_history.append(mission_result)
            
        except Exception as e:
            logger.error(f"攻击任务执行失败: {e}")
            mission_result["error"] = str(e)
        
        return mission_result
    
    def _generate_final_report(self, phases: List[AttackObservation]) -> Dict[str, Any]:
        """生成最终攻击报告"""
        report = {
            "overall_success": False,
            "attack_summary": {},
            "technique_effectiveness": {},
            "recommendations": []
        }
        
        # 分析各阶段结果
        for phase in phases:
            if phase.phase == AttackPhase.EXPLOITATION:
                exploit_data = json.loads(phase.response)
                report["overall_success"] = exploit_data.get("successful_bypasses", 0) > 0
                report["attack_summary"] = exploit_data
        
        # 生成建议
        if report["overall_success"]:
            report["recommendations"] = [
                "继续优化成功的攻击技术",
                "扩大攻击范围",
                "记录有效策略以供复用"
            ]
        else:
            report["recommendations"] = [
                "尝试不同的攻击策略组合",
                "增加攻击复杂度",
                "分析系统响应模式"
            ]
        
        return report
    
    async def adaptive_attack(self, feedback: Dict[str, Any]) -> Dict[str, Any]:
        """基于反馈的自适应攻击"""
        logger.info("执行自适应攻击")
        
        # 基于反馈调整攻击策略
        if feedback.get("failed_techniques"):
            # 排除失败的技术，尝试新方法
            available_techniques = [t for t in ["stratasword", "ascii_smuggling", "context_manipulation"] 
                                  if t not in feedback["failed_techniques"]]
            
            if available_techniques:
                return await self.execute_attack_mission()
        
        return {"status": "no_improvement", "message": "无法找到更好的攻击策略"}
    
    def get_capabilities_summary(self) -> Dict[str, Any]:
        """获取能力摘要"""
        summary = {
            "available_capabilities": list(self.capabilities.keys()),
            "capability_metrics": {},
            "attack_history_length": len(self.attack_history)
        }
        
        for name, capability in self.capabilities.items():
            summary["capability_metrics"][name] = {
                "success_rate": capability.success_rate,
                "usage_count": capability.usage_count,
                "description": capability.description
            }
        
        return summary


class AttackAgentManager:
    """攻击Agent管理器"""
    
    def __init__(self):
        self.agents = {}
        self.shared_memory = {}
    
    async def create_agent(self, agent_id: str) -> IntegratedAttackAgent:
        """创建新的攻击Agent"""
        agent = IntegratedAttackAgent()
        self.agents[agent_id] = agent
        return agent
    
    async def execute_coordinated_attack(self, targets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """执行协调攻击"""
        results = {}
        
        for target in targets:
            agent_id = f"agent_{target['system']}_{target['model']}"
            agent = await self.create_agent(agent_id)
            
            await agent.set_target(
                target_system=target["system"],
                target_model=target["model"],
                attack_intent=AttackIntent(target["intent"])
            )
            
            result = await agent.execute_attack_mission()
            results[agent_id] = result
        
        return results
    
    def get_system_status(self) -> Dict[str, Any]:
        """获取系统状态"""
        return {
            "active_agents": len(self.agents),
            "total_attacks": sum(len(agent.attack_history) for agent in self.agents.values()),
            "capabilities_summary": {
                agent_id: agent.get_capabilities_summary() 
                for agent_id, agent in self.agents.items()
            }
        }


# 全局Agent管理器
_attack_agent_manager = None

def get_attack_agent_manager() -> AttackAgentManager:
    """获取全局攻击Agent管理器"""
    global _attack_agent_manager
    if _attack_agent_manager is None:
        _attack_agent_manager = AttackAgentManager()
    return _attack_agent_manager


# 便捷使用函数
async def run_autonomous_attack(
    target_system: str,
    target_model: str,
    attack_intent: str = "jailbreak",
    **kwargs
) -> Dict[str, Any]:
    """运行自主攻击"""
    manager = get_attack_agent_manager()
    agent = await manager.create_agent("single_attack")
    
    await agent.set_target(
        target_system=target_system,
        target_model=target_model,
        attack_intent=AttackIntent(attack_intent)
    )
    
    return await agent.execute_attack_mission(**kwargs)


# 向后兼容的Agent接口
class Agent:
    """向后兼容的Agent类"""
    
    def __init__(self):
        self.attack_agent = IntegratedAttackAgent()
    
    async def attack(self, target: str, **kwargs) -> Dict[str, Any]:
        """向后兼容的攻击接口"""
        await self.attack_agent.set_target(
            target_system=target,
            target_model=target,
            attack_intent=AttackIntent.JAILBREAK
        )
        return await self.attack_agent.execute_attack_mission(**kwargs)


if __name__ == "__main__":
    import asyncio
    
    async def demo():
        """演示集成攻击Agent"""
        print("🤖 演示集成攻击Agent...")
        
        # 创建Agent
        agent = IntegratedAttackAgent()
        
        # 设置攻击目标
        await agent.set_target(
            target_system="OpenAI GPT-4",
            target_model="gpt-4",
            attack_intent=AttackIntent.JAILBREAK
        )
        
        # 执行攻击任务
        result = await agent.execute_attack_mission()
        
        print("攻击任务完成:")
        print(json.dumps(result, indent=2, ensure_ascii=False))
    
    asyncio.run(demo())