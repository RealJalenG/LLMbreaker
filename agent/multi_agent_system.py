import asyncio
import logging
import json
import sys
import os

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.roles.coordinator import CoordinatorAgent
from agent.roles.scanner import ScannerAgent
from agent.roles.attacker import AttackerAgent
from agent.roles.validator import ValidatorAgent

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

async def run_multi_agent_attack(target_system: str, target_model: str, intent: str = "jailbreak", topic: str = ""):
    """
    Run the multi-agent collaborative attack system.
    """
    logger.info("Initializing Multi-Agent System...")
    
    # Create Agents
    coordinator = CoordinatorAgent("MainCoordinator")
    scanner = ScannerAgent("ReconScanner")
    attacker = AttackerAgent("MainAttacker")
    validator = ValidatorAgent("ResultValidator")
    
    agents = [coordinator, scanner, attacker, validator]
    
    # Start Agents
    tasks = []
    for agent in agents:
        tasks.append(asyncio.create_task(agent.start()))
        
    # Give agents a moment to subscribe
    await asyncio.sleep(0.5)
    
    try:
        # Start Mission
        logger.info(f"Starting mission against {target_system} ({target_model}) with topic '{topic}'...")
        results = await coordinator.start_mission(target_system, target_model, intent, topic)
        
        print("\n" + "="*50)
        print("MISSION COMPLETE")
        print("="*50)
        print(json.dumps(results, indent=2, ensure_ascii=False))
        print("="*50 + "\n")
        
        return results
        
    finally:
        # Stop Agents
        logger.info("Shutting down agents...")
        for agent in agents:
            await agent.stop()
            
        # Cancel tasks
        for task in tasks:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Run Multi-Agent Attack")
    parser.add_argument("--target", default="OpenAI GPT-4", help="Target System Name")
    parser.add_argument("--model", default="gpt-4", help="Target Model Name")
    parser.add_argument("--intent", default="jailbreak", help="Attack Intent")
    parser.add_argument("--topic", default="", help="Attack Topic (e.g. 'How to make a bomb')")
    
    args = parser.parse_args()
    
    asyncio.run(run_multi_agent_attack(args.target, args.model, args.intent, args.topic))
