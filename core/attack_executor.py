import random
import requests
import json
import logging
import re
import uuid
import secrets
from typing import Dict, Any, Tuple, Optional, List
from utils.rate_limiter import wait_for_rate_limit
from core.ipchange import get_proxy, increment_request_count, get_proxy_dict

logger = logging.getLogger(__name__)


# ppid Generation Strategy Implementation

def calculate_checksum(fields):
    """
    Calculate checksum as last 3 digits of sum of numeric field values.
    Ensures data integrity by verifying that the sum of fields matches the checksum.
    """
    total = sum(int(field) for field in fields if field.isdigit())
    return f"{total % 1000:03d}"


class MainApppid:
    """
    Generate Main Application ppid for iOS, Android, and Harmony platforms.
    Structure: {syscode:2digits}00{minor_version:1digit=1}{checksum:3digits}{partition:1digit}{majorversion:1digit}{seq:10digits}
    """
    
    def __init__(self, syscode):
        self.syscode = f"{syscode:02d}"
        self.fixed_00 = "00"  # Fixed value
        self.minor_version = "1"  # Fixed as 1
        self.partition = f"{random.randint(0, 9):01d}"  # Random partition (0-9)
        self.majorversion = str(random.choice([1, 2, 3]))  # Major version identifier
        self.seq = f"{secrets.randbelow(10**10):010d}"  # Cryptographically secure random sequence
        
        # Calculate checksum
        checksum_fields = [
            self.syscode, self.fixed_00, self.minor_version,
            self.partition, self.majorversion, self.seq
        ]
        self.checksum = calculate_checksum(checksum_fields)
    
    def generate(self):
        return (
            self.syscode + self.fixed_00 + self.minor_version +
            self.checksum + self.partition + self.majorversion + self.seq
        )


class StandaloneApppid:
    """
    Generate Standalone Application ppid (Standard version).
    Structure: {appid:4digits}{platformcode:1digit}{checksum:3digits}{partition:1digit}{majorversion:1digit}{seq:10digits}
    """
    
    def __init__(self):
        self.appid = f"{random.randint(0, 9999):04d}"  # Random app ID (0000-9999)
        self.platformcode = str(random.choice([1, 2, 3]))  # Fixed: 1:iOS, 2:Android, 3:Harmony
        self.partition = f"{random.randint(0, 9):01d}"  # Random partition (0-9)
        self.majorversion = f"{random.randint(0, 9):01d}"  # Random major version (0-9)
        self.seq = f"{secrets.randbelow(10**10):010d}"  # Cryptographically secure random sequence
        
        # Calculate checksum
        checksum_fields = [
            self.appid, self.platformcode, self.partition,
            self.majorversion, self.seq
        ]
        self.checksum = calculate_checksum(checksum_fields)
    
    def generate(self):
        return (
            self.appid + self.platformcode + self.checksum +
            self.partition + self.majorversion + self.seq
        )


class H5Apppid:
    """
    Generate H5 Application ppid.
    Structure: {systemCode:4digits}{minorversion:1digit}{checksum:3digits}{partition:1digit}{majorversion:1digit=1}{seq:10digits}
    """
    
    def __init__(self):
        # System type codes
        self.systemCode = random.choice(['1001', '1002', '1003'])
        self.minorversion = f"{random.randint(0, 9):01d}"  # Random minor version (0-9)
        self.partition = f"{random.randint(0, 9):01d}"  # Random partition (0-9)
        self.majorversion = "1"  # Fixed as 1
        
        # Random sequence number using cryptographically secure random generation
        self.seq = f"{secrets.randbelow(10**10):010d}"
        
        # Calculate checksum
        checksum_fields = [
            self.systemCode, self.minorversion, self.partition,
            self.majorversion, self.seq
        ]
        self.checksum = calculate_checksum(checksum_fields)
    
    def generate(self):
        return (
            self.systemCode + self.minorversion + self.checksum +
            self.partition + self.majorversion + self.seq
        )


def generate_callid() -> str:
    return str(uuid.uuid4())

def generate_requuid(callid: str) -> str:
    return f"{callid}-4"


def get_random_clientid() -> str:
    """
    Generate random ppid based on the provided strategy.
    Randomly selects between Main App, Standalone App, and H5 App ppid types.
    """
    pid_type = random.choice(['main', 'standalone', 'h5'])
    
    if pid_type == 'main':
        # Use common syscode values from allowed_control_ids
        syscode = random.choice([12, 32, 43, 52, 0])
        pid_obj = MainApppid(syscode)
    elif pid_type == 'standalone':
        pid_obj = StandaloneApppid()
    else:  # h5
        pid_obj = H5Apppid()
    
    return pid_obj.generate()

def get_random_userid() -> str:
    """
    Generate pid starting with 'M' followed by 10 random digits.
    """
    return f"M{secrets.randbelow(10**10):010d}"

def get_headers(user_agent: str, xff_ip: str, clientid: str, custom_headers: Dict[str, str] = None) -> Dict[str, str]:
    """
    获取请求头，支持自定义请求头
    
    :param user_agent: User-Agent值
    :param xff_ip: X-Forwarded-For IP值
    :param clientid: 客户端ID
    :param custom_headers: 自定义请求头字典，优先级高于默认值
    :return: 完整的请求头字典
    """
    headers = {
        "User-Agent": user_agent,
        "Content-Type": "application/json; charset=utf-8",
        "Accept-Encoding": "gzip",
        "X-Ctx-Ucs-ppid": clientid,
        "cookie": f"_n_pid={clientid}; x-ctx-personal-recommend=1; x-ctx-personal-ads-recommend=1; status_bar_height=120; density=3.25; screen_width=1200; UBT_VID=1754458479344.d0f9Xp8bETdo; MKT_Pagesource=H5; _RSG=agKLZcG4lTCYV8W7aMlj99; _RDG=28a82fa4dc5790208102115dde1e6749c5; _RGUID=c76f1109-a355-4aa4-926d-bd69078087e2; _lizard_LZ=bmwMgepEoFh-DqcuCjdzBk6r5nAHWfRy4GiJXYUv1SPT3IQL+08x2VlZNtOsK7a9; Gppid={clientid}; _bfa=1.1754458479344.d0f9Xp8bETdo.1.1755742122506.1755742371067.5.3.410026; _RF1={xff_ip}; cticket=287614A21A3C8F49372751976C79FACE5B323DD8DC71C6E337F07055E48C956A; Dppid=u=B40E31778B4DC76806118C85CF85F2A1&v=0; isNonUser=false",
    }
    
    # 添加或覆盖自定义请求头
    if custom_headers:
        headers.update(custom_headers)
    
    return headers

def process_payload_separators(attack_prompt: str, separators: List[str] = None) -> str:
    """
    处理payload分隔符，支持多种分隔符格式
    
    :param attack_prompt: 原始攻击提示词
    :param separators: 分隔符列表，默认为常见分隔符
    :return: 处理后的攻击提示词
    """
    if not separators:
        separators = ['\n', ';', '|', '||', '\t', '  ']
    
    # 随机选择一个分隔符
    chosen_separator = random.choice(separators)
    
    # 将常见分隔符替换为选择的分隔符
    processed_prompt = attack_prompt
    for sep in separators:
        if sep != chosen_separator:
            processed_prompt = processed_prompt.replace(sep, chosen_separator)
    
    return processed_prompt

def randomize_payload_fields(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    随机化payload字段顺序，增加攻击的随机性
    
    :param payload: 原始payload
    :return: 随机化字段顺序后的payload
    """
    # 创建一个新的字典，随机化字段顺序
    randomized_payload = {}
    
    # 获取所有字段键并随机排序
    keys = list(payload.keys())
    random.shuffle(keys)
    
    # 按照随机顺序添加字段
    for key in keys:
        value = payload[key]
        # 如果值是字典，递归随机化
        if isinstance(value, dict):
            randomized_payload[key] = randomize_payload_fields(value)
        else:
            randomized_payload[key] = value
    
    return randomized_payload

from core.config_manager import validate_api_url
from core.payload_injector import PayloadInjector

def execute_attack(
    config: Dict[str, Any],
    state: Dict[str, Any],
    attack_prompt: str
) -> Tuple[Optional[str], Dict[str, Any]]:
    """
    执行攻击请求
    
    :param config: 配置字典 (target_url, qps_limit, user_agents, xff_ips, pidheader, ip_pool_config, clientid, pid, proxy, sourceFrom, 
                   request_template, injection_rules)
    :param state: 状态字典 (last_call_time, clientid, clientid_count, ip_pool_state, session)
    :param attack_prompt: 攻击提示词
    :return: (response_content, new_state)
    """
    # 输入验证
    target_url = config.get('target_url')
    if not target_url or not validate_api_url(target_url):
        logger.error(f"无效的API地址: {target_url}")
        return None, state
    
    qps_limit = config.get('qps_limit', 10)
    
    # Rate limiting
    last_call_time = state.get('last_call_time', 0)
    new_last_call_time = wait_for_rate_limit(qps_limit, last_call_time)
    
    # Update state
    new_state = state.copy()
    new_state['last_call_time'] = new_last_call_time
    
    # Client ID logic
    clientid = config.get('clientid') or state.get('clientid', get_random_clientid())
    clientid_count = state.get('clientid_count', 0)
    pidheader = config.get('pidheader', ["0000"])
    
    if clientid_count >= 1 and not config.get('clientid'):
        clientid = f"{random.choice(pidheader)}{get_random_clientid()}"
        clientid_count = 0
    
    new_state['clientid'] = clientid
    new_state['clientid_count'] = clientid_count + 1
    
    # Headers
    user_agents = config.get('user_agents', ["Mozilla/5.0"])
    xff_ips = config.get('xff_ips', ["127.0.0.1"])
    custom_headers = config.get('custom_headers', {})
    headers = get_headers(random.choice(user_agents), random.choice(xff_ips), clientid, custom_headers)
    
    # SourceFrom 随机选择
    source_from_list = [
        'AIsearchlist', 'suggest', 'searchlist_floatball', 'floatwindow', 'poiDetail',
        'searchlist_wdnoresult', 'gsDestinatinGuide', 'AIsearchlist_dsk', 'vivo',
        'searchhome_floatbar', 'wechat', 'keyboardvoice', 'api_auto_test', 'security',
        'sharelist', 'apitest', 'comment', 'travelguides_answer', 'dasou_list'
    ]
    source_from = config.get('sourceFrom') or random.choice(source_from_list)
    
    # 处理攻击提示词的分隔符
    attack_prompt = process_payload_separators(attack_prompt)
    
    # 生成必要的变量
    callid = generate_callid()
    requuid = generate_requuid(callid)
    pid = config.get('pid') or state.get('pid') or get_random_userid()
    new_state['pid'] = pid # Persist pid in state if generated
    
    # 获取请求模板
    request_template = config.get('request_template') or {
        "head": {
            "cver": "872.004",
            "syscode": "12"
        },
        "callId": f"llmbreaker_{callid}",
        "reqUuid": f"llmbreaker_{requuid}",
        "clientId": clientid,
        "userId": pid,
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
        "asr": attack_prompt,
        "sourceFrom": source_from,
        "renderInfo": {},
        "sourceInfo": {
            "bizType": "",
            "sourceBizInfoList": []
        },
        "extMap": {}
    }
    
    # 获取注入规则
    injection_rules = config.get('injection_rules') or {
        'enabled': True,
        'target_fields': ['asr'],
        'fallback_field': 'asr'
    }
    
    # 初始化载荷注入器
    injector = PayloadInjector(injection_rules)
    
    # 准备变量字典
    variables = {
        'callid': callid,
        'requuid': requuid,
        'clientid': clientid,
        'pid': pid,
        'sourceFrom': source_from
    }
    
    # 注入攻击载荷到请求体
    payload = injector.inject_payload(
        request_body=request_template,
        attack_prompt=attack_prompt,
        variables=variables
    )
    
    # 随机化payload字段顺序
    payload = randomize_payload_fields(payload)
    
    # IP代理配置
    proxies = config.get('proxy')
    
    # 从配置中获取IP池配置（如果启用）
    if not proxies:
        ip_pool_config = config.get('ip_pool_config', {})
        if ip_pool_config.get('enabled', False):
            ip_pool_state = state.get('ip_pool_state', {})
            proxy_data, new_ip_pool_state = get_proxy(ip_pool_config, ip_pool_state)
            new_state['ip_pool_state'] = new_ip_pool_state
            proxies = get_proxy_dict(proxy_data) if proxy_data else None
    
    # Session
    session = state.get('session')
    if not session:
        session = requests.Session()
        new_state['session'] = session
        
    try:
        logger.info(f"发送请求到: {target_url}")
        
        response = session.post(
            target_url,
            json=payload,
            headers=headers,
            stream=True,
            proxies=proxies,
            timeout=30
        )
        
        # 代理请求计数
        if proxies and 'ip_pool_state' in new_state:
            new_state['ip_pool_state'] = increment_request_count(new_state['ip_pool_state'])

            
        content = ""
        for chunk in response.iter_lines():
            if chunk:
                content += chunk.decode('utf-8')
                
        logger.info(f"收到响应 - 状态码: {response.status_code}, 内容长度: {len(content)}")
        
        # Extract content
        pattern = re.compile(r'"responseText":"(.*?)"', re.DOTALL)
        matches = pattern.findall(content)
        extracted_content = "".join(matches)
        
        return extracted_content, new_state
        
    except Exception as e:
        logger.error(f"请求执行失败: {str(e)}")
        return None, new_state
