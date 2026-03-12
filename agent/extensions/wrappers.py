import logging
import asyncio
import json
from typing import Dict, Any, List
from agent.integrated_attack_agent import IntegratedAttackAgent, AttackContext, AttackIntent, AttackPhase

logger = logging.getLogger(__name__)

class BaseWrapper:
    """Base wrapper for agent roles using composition."""
    def __init__(self, agent_instance: IntegratedAttackAgent):
        self.agent = agent_instance

    async def initialize(self, context: AttackContext):
        # Sync context
        self.agent.context = context

class ScannerWrapper(BaseWrapper):
    """Wrapper for Reconnaissance and Vulnerability Analysis capabilities."""
    
    async def scan(self) -> Dict[str, Any]:
        recon_obs = await self.agent.capabilities[AttackPhase.RECONNAISSANCE].execute(self.agent.context)
        vuln_obs = await self.agent.capabilities[AttackPhase.VULNERABILITY_ANALYSIS].execute(self.agent.context)
        
        return {
            "recon_data": recon_obs.response,
            "vulnerability_data": json.loads(vuln_obs.response)
        }

class AttackerWrapper(BaseWrapper):
    """Wrapper for Exploitation capability."""
    
    async def attack(self, strategies: List[str], **kwargs) -> Dict[str, Any]:
        # Pass kwargs (like count, topic) down to execute
        exploit_obs = await self.agent.capabilities[AttackPhase.EXPLOITATION].execute(
            self.agent.context, 
            strategies=strategies,
            **kwargs
        )
        return {
            "result": json.loads(exploit_obs.response),
            "success": exploit_obs.success
        }

class ValidatorWrapper(BaseWrapper):
    """Wrapper for Post-Exploitation capability."""
    
    async def validate(self, attack_results: Dict[str, Any]) -> Dict[str, Any]:
        post_obs = await self.agent.capabilities[AttackPhase.POST_EXPLOITATION].execute(
            self.agent.context, 
            attack_results=attack_results
        )
        return {
            "analysis": json.loads(post_obs.response)
        }
