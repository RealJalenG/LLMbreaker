import asyncio
import logging
from typing import Dict, Any, Optional
from abc import ABC, abstractmethod
from .message_bus import MessageBus, Message, MessageType, get_message_bus

logger = logging.getLogger(__name__)

class BaseAgent(ABC):
    """
    Base class for all agents in the multi-agent system.
    """
    def __init__(self, name: str, role: str):
        self.name = name
        self.role = role
        self.id = f"{role}_{name}"
        self.bus = get_message_bus()
        self.running = False
        self.task_queue = asyncio.Queue()
        
    async def start(self):
        """Start the agent's main loop."""
        self.running = True
        logger.info(f"Agent {self.name} ({self.role}) started.")
        self._setup_subscriptions()
        
        while self.running:
            # Process internal task queue if needed
            try:
                task = await asyncio.wait_for(self.task_queue.get(), timeout=1.0)
                await self.process_task(task)
            except asyncio.TimeoutError:
                pass
            except Exception as e:
                logger.error(f"Error in agent loop: {e}")
                
    async def stop(self):
        """Stop the agent."""
        self.running = False
        logger.info(f"Agent {self.name} stopped.")
        
    def _setup_subscriptions(self):
        """Setup default message subscriptions."""
        self.bus.subscribe_all(self._handle_message_wrapper)
        
    async def _handle_message_wrapper(self, message: Message):
        """Wrapper to filter messages intended for this agent."""
        if message.target_id == "*" or message.target_id == self.id:
            if message.sender_id != self.id: # Don't process own messages
                await self.handle_message(message)
                
    @abstractmethod
    async def handle_message(self, message: Message):
        """Handle incoming messages."""
        pass
        
    @abstractmethod
    async def process_task(self, task: Any):
        """Process internal tasks."""
        pass
    
    async def send_message(self, msg_type: MessageType, content: Dict[str, Any], target_id: str = "*"):
        """Send a message to the bus."""
        msg = Message(
            type=msg_type,
            sender_id=self.id,
            content=content,
            target_id=target_id
        )
        await self.bus.publish(msg)
