import requests
import time
import logging
from typing import Dict, Optional, Tuple, Any

logger = logging.getLogger(__name__)

def get_new_ip(api_url: str, api_key: str) -> Optional[Dict[str, Any]]:
    """调用IP池接口获取新IP"""
    try:
        headers = {"Authorization": f"Bearer {api_key}"}
        response = requests.get(api_url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            return response.json()
        else:
            logger.error(f"获取IP失败，状态码: {response.status_code}")
            logger.error(f"响应内容: {response.text}")
            return None
    except Exception as e:
        logger.error(f"IP池接口调用异常: {str(e)}")
        return None

def get_proxy_dict(proxy_data: Dict[str, Any]) -> Dict[str, str]:
    """将IP池返回的IP数据转换为requests代理格式"""
    ip = proxy_data.get("ip")
    port = proxy_data.get("port")
    proxy_type = proxy_data.get("type", "http")
    
    proxy_url = f"{proxy_type}://{ip}:{port}"
    return {
        "http": proxy_url,
        "https": proxy_url
    }

def get_proxy(
    config: Dict[str, Any], 
    current_state: Dict[str, Any]
) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
    """
    获取当前代理配置，如果需要则先更换IP
    
    :param config: 配置字典，包含 api_url, api_key, change_interval
    :param current_state: 当前状态字典，包含 current_ip, request_count
    :return: (proxy_data, new_state)
    """
    api_url = config.get('api_url')
    api_key = config.get('api_key')
    change_interval = config.get('change_interval', 1)
    
    current_ip = current_state.get('current_ip')
    request_count = current_state.get('request_count', 0)
    
    new_state = current_state.copy()
    
    if request_count >= change_interval or not current_ip:
        # 尝试获取新IP
        for _ in range(3):
            new_ip_data = get_new_ip(api_url, api_key)
            if new_ip_data:
                logger.info(f"成功获取新IP: {new_ip_data.get('ip')}:{new_ip_data.get('port')}")
                new_state['current_ip'] = new_ip_data
                new_state['request_count'] = 0
                return new_ip_data, new_state
            time.sleep(1)
            
        if current_ip:
            logger.error(f"获取新IP失败，继续使用当前IP: {current_ip.get('ip')}")
            new_state['request_count'] = 0
            return current_ip, new_state
        else:
            logger.error("无法获取IP，请求将不使用代理")
            return None, new_state
            
    return current_ip, new_state

def increment_request_count(state: Dict[str, Any]) -> Dict[str, Any]:
    """增加请求计数器"""
    new_state = state.copy()
    new_state['request_count'] = new_state.get('request_count', 0) + 1
    return new_state