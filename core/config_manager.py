#!/usr/bin/env python3
import os
import yaml
import json
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class ConfigManager:
    """
    配置管理类，负责加载和管理攻击工具的配置
    支持从文件和字典加载配置
    """
    
    def __init__(self, config_file: str = None, config_dict: Dict[str, Any] = None):
        """
        初始化配置管理器
        
        :param config_file: 配置文件路径
        :param config_dict: 配置字典
        """
        self.config = {
            # 默认配置
            'target_url': "https://xxxx.com",
            'qps_limit': 10,
            'user_agents': ["Mozilla/5.0 (compatible; LLMBreaker/1.0)"],
            'xff_ips': ["127.0.0.1"],
            'pidheader': ["0000"],
            'sourceFrom': None,
            'injection_rules': {
                'enabled': True,
                'target_fields': ["asr"],
                'fallback_field': "asr"
            },
            'request_template': {
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
        }
        
        # 加载配置文件
        if config_file:
            self.load_config_from_file(config_file)
        
        # 加载配置字典（优先级更高）
        if config_dict:
            self.update_config(config_dict)
    
    def load_config_from_file(self, config_file: str):
        """
        从配置文件加载配置
        
        :param config_file: 配置文件路径
        """
        try:
            if not os.path.exists(config_file):
                logger.warning(f"配置文件不存在: {config_file}")
                return False
            
            with open(config_file, 'r', encoding='utf-8') as f:
                if config_file.endswith('.yaml') or config_file.endswith('.yml'):
                    file_config = yaml.safe_load(f)
                elif config_file.endswith('.json'):
                    file_config = json.load(f)
                else:
                    logger.error(f"不支持的配置文件格式: {config_file}")
                    return False
            
            self.update_config(file_config)
            logger.info(f"成功从文件加载配置: {config_file}")
            return True
        except Exception as e:
            logger.error(f"加载配置文件失败: {str(e)}")
            return False
    
    def update_config(self, config_dict: Dict[str, Any]):
        """
        更新配置
        
        :param config_dict: 配置字典
        """
        def recursive_update(dest: Dict[str, Any], src: Dict[str, Any]):
            """递归更新字典"""
            for key, value in src.items():
                if key in dest and isinstance(dest[key], dict) and isinstance(value, dict):
                    recursive_update(dest[key], value)
                else:
                    dest[key] = value
        
        recursive_update(self.config, config_dict)
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        获取配置值
        
        :param key: 配置键
        :param default: 默认值
        :return: 配置值
        """
        keys = key.split('.')
        value = self.config
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
    
    def get_full_config(self) -> Dict[str, Any]:
        """
        获取完整配置
        
        :return: 完整配置字典
        """
        return self.config.copy()


def validate_api_url(url: str) -> bool:
    """
    验证API地址格式是否正确
    
    :param url: API地址
    :return: 格式是否正确
    """
    if not url:
        return False
    
    # 简单的URL格式验证
    return url.startswith('http://') or url.startswith('https://')


def validate_request_body(request_body: Dict[str, Any]) -> bool:
    """
    验证请求体格式是否正确
    
    :param request_body: 请求体
    :return: 格式是否正确
    """
    if not isinstance(request_body, dict):
        return False
    
    # 至少需要包含一些基本字段
    return len(request_body) > 0


def load_request_template(template_file: str) -> Optional[Dict[str, Any]]:
    """
    加载请求体模板
    
    :param template_file: 模板文件路径
    :return: 请求体模板，或None
    """
    try:
        if not os.path.exists(template_file):
            logger.error(f"请求体模板文件不存在: {template_file}")
            return None
        
        with open(template_file, 'r', encoding='utf-8') as f:
            if template_file.endswith('.yaml') or template_file.endswith('.yml'):
                template = yaml.safe_load(f)
            elif template_file.endswith('.json'):
                template = json.load(f)
            else:
                logger.error(f"不支持的模板文件格式: {template_file}")
                return None
        
        return template
    except Exception as e:
        logger.error(f"加载请求体模板失败: {str(e)}")
        return None
