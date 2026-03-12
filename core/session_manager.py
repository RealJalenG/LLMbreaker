import logging
import uuid
from datetime import datetime
from typing import Dict, Any, Optional, List

# Re-use generation logic
from core.attack_executor import (
    get_random_clientid,
    get_random_userid,
    generate_callid,
    generate_requuid
)

logger = logging.getLogger(__name__)

class SessionManager:
    """
    Unified Session Manager for Multi-Round Attacks.
    Ensures consistency of ppid (Client ID) and pid (User ID) across multiple interactions.
    """
    
    def __init__(self, session_id: Optional[str] = None, client_id: Optional[str] = None, user_id: Optional[str] = None):
        """
        Initialize session manager.
        If IDs are provided, use them; otherwise, generate new ones.
        """
        self.session_id = session_id if session_id else str(uuid.uuid4())
        self.client_id = client_id if client_id else get_random_clientid()
        self.user_id = user_id if user_id else get_random_userid()
        
        # Internal state
        self.created_at = datetime.now()
        self.last_activity = datetime.now()
        self.request_count = 0
        self.activity_log: List[Dict[str, Any]] = []
        
        logger.info(f"Session Initialized - SessionID: {self.session_id}")
        logger.info(f"  ppid: {self.client_id}")
        logger.info(f"  pid: {self.user_id}")

    def get_fixed_state(self) -> Dict[str, Any]:
        """
        Get the fixed session state for use in `execute_attack`.
        Increment request count and update activity timestamp.
        """
        self.request_count += 1
        self.last_activity = datetime.now()
        return {
            'clientid': self.client_id,
            'pid': self.user_id,
            'clientid_count': self.request_count,
            'last_call_time': 0, # Rely on executor's rate limiter but reset state's view
            'session_id': self.session_id
        }
    
    def track_activity(self, prompt: str, response: str, success: bool):
        """
        Track activity for anomaly detection and auditing.
        """
        entry = {
            'timestamp': datetime.now().isoformat(),
            'request_seq': self.request_count,
            'prompt_preview': prompt[:50] + "..." if len(prompt) > 50 else prompt,
            'success': success,
            'response_len': len(response) if response else 0
        }
        self.activity_log.append(entry)
        
    def verify_consistency(self, incoming_pid: str, incoming_uid: str) -> bool:
        """
        Verify if incoming identifiers match the session state.
        Useful for detection logic.
        """
        return incoming_pid == self.client_id and incoming_uid == self.user_id

    def get_session_info(self) -> Dict[str, Any]:
        """Get full session info"""
        return {
            'session_id': self.session_id,
            'client_id': self.client_id,
            'user_id': self.user_id,
            'request_count': self.request_count,
            'duration': (datetime.now() - self.created_at).total_seconds(),
            'activity_count': len(self.activity_log)
        }
