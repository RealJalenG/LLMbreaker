import os
import functools
import logging
from typing import Callable, Any

logger = logging.getLogger(__name__)

def is_collaborative_mode_enabled() -> bool:
    """Check if multi-agent collaborative mode is enabled via config or env."""
    try:
        from config import settings
        if hasattr(settings, 'MULTI_AGENT_COLLABORATION_ENABLED'):
            return settings.MULTI_AGENT_COLLABORATION_ENABLED
    except ImportError:
        pass
    
    return os.getenv('MULTI_AGENT_COLLABORATION_ENABLED', 'False').lower() == 'true'

def collaborative_mode(func: Callable) -> Callable:
    """
    Decorator to intercept SecurityAgent calls and route them to 
    the Multi-Agent Orchestrator if collaborative mode is enabled.
    """
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        if is_collaborative_mode_enabled():
            logger.info(f"Collaborative Mode ENABLED. Intercepting call to {func.__name__}")
            try:
                # Import here to avoid circular dependencies and ensure isolation
                from agent.extensions.orchestrator import get_orchestrator
                
                orchestrator = get_orchestrator()
                
                # Map arguments based on function name
                if func.__name__ == 'execute_integrated_attack':
                    topic = kwargs.get('topic') or (args[0] if args else None)
                    count = kwargs.get('count', 10)
                    intent = kwargs.get('attack_intent', 'jailbreak')
                    return orchestrator.run_mission(
                        target_system="default", # Or fetch from self
                        target_model=topic or "default",
                        attack_intent=intent,
                        topic=topic,
                        count=count
                    )
                elif func.__name__ == 'run_autonomous_attack':
                    target_system = kwargs.get('target_system') or (args[0] if args else "")
                    target_model = kwargs.get('target_model') or (args[1] if len(args) > 1 else "")
                    attack_intent = kwargs.get('attack_intent') or (args[2] if len(args) > 2 else "jailbreak")
                    return orchestrator.run_mission(
                        target_system=target_system,
                        target_model=target_model,
                        attack_intent=attack_intent
                    )
                else:
                    logger.warning(f"Collaborative mode not supported for {func.__name__}, falling back to legacy.")
            except Exception as e:
                logger.error(f"Failed to run in collaborative mode: {e}. Falling back to legacy.")
                # Fallback to original function on error
                return func(self, *args, **kwargs)
        
        # Default: Legacy execution
        return func(self, *args, **kwargs)
    
    return wrapper
