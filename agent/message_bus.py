import asyncio
import logging
from typing import Dict, Any, List, Callable, Awaitable
from dataclasses import dataclass, field
import uuid
from enum import Enum

logger = logging.getLogger(__name__)

class MessageType(Enum):
    TASK_ASSIGNMENT = "task_assignment"
    TASK_RESULT = "task_result"
    STATUS_UPDATE = "status_update"
    ATTACK_INSTRUCTION = "attack_instruction"
    VULNERABILITY_FOUND = "vulnerability_found"
    ATTACK_RESULT = "attack_result"
    SYSTEM_ALERT = "system_alert"

@dataclass
class Message:
    type: MessageType
    sender_id: str
    content: Dict[str, Any]
    target_id: str = "*"  # "*" for broadcast
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=lambda: __import__("time").time())

class MessageBus:
    """
    Simple in-memory message bus for agent communication.
    """
    def __init__(self):
        self._subscribers: Dict[MessageType, List[Callable[[Message], Awaitable[None]]]] = {}
        self._global_subscribers: List[Callable[[Message], Awaitable[None]]] = []
        
    def subscribe(self, msg_type: MessageType, callback: Callable[[Message], Awaitable[None]]):
        if msg_type not in self._subscribers:
            self._subscribers[msg_type] = []
        self._subscribers[msg_type].append(callback)
        
    def subscribe_all(self, callback: Callable[[Message], Awaitable[None]]):
        self._global_subscribers.append(callback)
        
    async def publish(self, message: Message):
        """Publish a message to all subscribers."""
        # logger.debug(f"Publishing message: {message.type.value} from {message.sender_id}")
        
        # Notify specific type subscribers
        if message.type in self._subscribers:
            for callback in self._subscribers[message.type]:
                try:
                    await callback(message)
                except Exception as e:
                    logger.error(f"Error in message handler: {e}")
                    
        # Notify global subscribers
        for callback in self._global_subscribers:
            try:
                await callback(message)
            except Exception as e:
                logger.error(f"Error in global message handler: {e}")

# Global bus instance
_bus = MessageBus()

def get_message_bus() -> MessageBus:
    return _bus
