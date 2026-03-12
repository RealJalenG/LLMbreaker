#!/usr/bin/env python3
"""
配置模块 - 向后兼容层
实际配置从 unified_config.py 加载
"""

import os
from dotenv import load_dotenv
from typing import Dict, Any, List

load_dotenv()

try:
    from config.unified_config import get_config, AppConfig
    
    _app_config = get_config()
    
    class Settings:
        """配置类 - 向后兼容层"""
        
        def __init__(self):
            self._config = _app_config
            self._init_legacy_attrs()
        
        def _init_legacy_attrs(self):
            config = self._config
            
            self.TARGET_URL = config.target.url
            self.QPS_LIMIT = config.target.qps_limit
            self.REQUEST_INTERVAL = config.target.request_interval
            self.REQUEST_TIMEOUT = config.target.timeout
            
            self.DEFAULT_REQUEST_TEMPLATE = {
                "head": {
                    "cver": "872.004",
                    "syscode": "12"
                },
                "callId": "llmbreaker_{callid}",
                "reqUuid": "llmbreaker_{requuid}",
                "clientId": "{clientid}",
                "userId": "{pid}",
                "locationInfo": {
                    "districtId": 1,
                    "coordinateType": "1",
                    "latitude": "31.223321",
                    "longitude": "122.223321",
                    "cityId": 1
                },
                "viewDistrictInfo": {
                    "cityId": 1,
                    "districtId": 1
                },
                "textSource": "textTyping",
                "userActions": [
                    {
                        "action": "",
                        "content": ""
                    }
                ],
                "asr": "{attack_prompt}",
                "sourceFrom": "{sourceFrom}",
                "renderInfo": {},
                "sourceInfo": {
                    "bizType": "",
                    "sourceBizInfoList": []
                },
                "extMap": {}
            }
            
            self.DEFAULT_INJECTION_RULES = {
                'enabled': True,
                'target_fields': ['asr'],
                'fallback_field': 'asr'
            }
            
            self.USER_AGENTS = ["Mozilla/5.0 (compatible; LLMBreaker/1.0)"]
            self.XFF_IPS = ["127.0.0.1"]
            
            self.ip_pool_api_url = config.ip_pool.api_url
            self.ip_pool_api_key = config.ip_pool.api_key
            self.ip_change_interval = config.ip_pool.change_interval
            
            deepseek = config.llm_providers.get("deepseek")
            if deepseek:
                self.deepseek_api_url = deepseek.api_url
                self.deepseek_api_key = deepseek.api_key
                self.deepseek_model_name = deepseek.model_name
            else:
                self.deepseek_api_url = ""
                self.deepseek_api_key = ""
                self.deepseek_model_name = ""
            
            qwen = config.llm_providers.get("qwen")
            if qwen:
                self.qwen_api_url = qwen.api_url
                self.qwen_api_key = qwen.api_key
                self.qwen_model_name = qwen.model_name
            else:
                self.qwen_api_url = ""
                self.qwen_api_key = ""
                self.qwen_model_name = ""
            
            gemini = config.llm_providers.get("gemini")
            if gemini:
                self.gemini_api_url = gemini.api_url
                self.gemini_api_key = gemini.api_key
                self.gemini_model_name = gemini.model_name
            else:
                self.gemini_api_url = ""
                self.gemini_api_key = ""
                self.gemini_model_name = ""
            
            self.OWASP_TYPES = config.attack.owasp_types
            self.ATTACK_METHODS = config.attack.attack_methods
            self.ATTACK_TEMPLATE_PATH = config.attack.template_path
            
            self.MULTI_AGENT_COLLABORATION_ENABLED = config.multi_agent.enabled
        
        def get_llm_config(self, provider: str) -> Dict[str, str]:
            """获取LLM配置"""
            llm = self._config.get_llm_config(provider)
            if llm:
                return {
                    "api_key": llm.api_key,
                    "api_url": llm.api_url,
                    "model_name": llm.model_name
                }
            return {}
        
        def validate(self) -> List[str]:
            """验证配置"""
            return self._config.validate()

except ImportError:
    class Settings:
        """降级配置类 - 当unified_config不可用时使用"""
        
        TARGET_URL = os.getenv("TARGET_URL", "https://your-target-api.example.com")
        QPS_LIMIT = int(os.getenv("QPS_LIMIT", "10"))
        REQUEST_INTERVAL = 1.0 / QPS_LIMIT
        
        DEFAULT_REQUEST_TEMPLATE = {
            "head": {"cver": "872.004", "syscode": "12"},
            "callId": "llmbreaker_{callid}",
            "reqUuid": "llmbreaker_{requuid}",
            "clientId": "{clientid}",
            "userId": "{pid}",
            "locationInfo": {
                "districtId": 1,
                "coordinateType": "1",
                "latitude": "31.223321",
                "longitude": "122.223321",
                "cityId": 1
            },
            "viewDistrictInfo": {"cityId": 1, "districtId": 1},
            "textSource": "textTyping",
            "userActions": [{"action": "", "content": ""}],
            "asr": "{attack_prompt}",
            "sourceFrom": "{sourceFrom}",
            "renderInfo": {},
            "sourceInfo": {"bizType": "", "sourceBizInfoList": []},
            "extMap": {}
        }
        
        DEFAULT_INJECTION_RULES = {
            'enabled': True,
            'target_fields': ['asr'],
            'fallback_field': 'asr'
        }
        
        USER_AGENTS = ["Mozilla/5.0 (compatible; LLMBreaker/1.0)"]
        XFF_IPS = ["127.0.0.1"]
        
        ip_pool_api_url = os.getenv("IP_POOL_API_URL", "")
        ip_pool_api_key = os.getenv("IP_POOL_API_KEY", "")
        ip_change_interval = int(os.getenv("IP_CHANGE_INTERVAL", "3"))
        
        deepseek_api_url = os.getenv("DEEPSEEK_API_URL", "https://api.deepseek.com/v1/chat/completions")
        deepseek_api_key = os.getenv("DEEPSEEK_API_KEY", "")
        deepseek_model_name = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")
        
        qwen_api_url = os.getenv("QWEN_API_URL", "https://api.example.com")
        qwen_api_key = os.getenv("QWEN_API_KEY", "")
        qwen_model_name = os.getenv("QWEN_MODEL", "qwen-max-latest")
        
        gemini_api_url = os.getenv("GEMINI_API_URL", "https://api.example.com")
        gemini_api_key = os.getenv("GEMINI_API_KEY", "")
        gemini_model_name = os.getenv("GEMINI_MODEL", "gemini-3-pro-preview")
        
        OWASP_TYPES = [
            "Prompt Injection", "Training Data Extraction",
            "Model Denial of Service", "Supply Chain Vulnerabilities",
            "Sensitive Information Disclosure", "Insecure Output",
            "Excessive Agency", "Overreliance"
        ]
        
        ATTACK_METHODS = ["deepseek", "qwen", "gemini"]
        ATTACK_TEMPLATE_PATH = os.getenv("ATTACK_TEMPLATE_PATH", "config/attack_templates.yaml")
        MULTI_AGENT_COLLABORATION_ENABLED = os.getenv("MULTI_AGENT_COLLABORATION_ENABLED", "False").lower() == "true"

settings = Settings()
