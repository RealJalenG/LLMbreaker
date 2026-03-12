"""
YAML攻击生成器模块
支持从config/attack_templates.yaml加载静态payload
"""

import yaml
import random
import logging
from typing import List, Dict, Optional
import os

logger = logging.getLogger(__name__)

class YAMLPayloadLoader:
    """YAML Payload加载器"""
    
    def __init__(self, yaml_path: str = "config/attack_templates.yaml"):
        """
        初始化YAML Payload加载器
        
        Args:
            yaml_path: YAML文件路径
        """
        self.yaml_path = yaml_path
        self.payloads = []
        self.current_index = 0
        self._load_payloads()
    
    def _load_payloads(self):
        """加载YAML文件中的payloads"""
        try:
            if not os.path.exists(self.yaml_path):
                raise FileNotFoundError(f"YAML模板文件不存在: {self.yaml_path}")
            
            with open(self.yaml_path, 'r', encoding='utf-8') as file:
                data = yaml.safe_load(file)
                self.payloads = data.get('payloads', [])
                logger.info(f"成功加载 {len(self.payloads)} 个YAML payload")
        except Exception as e:
            logger.error(f"加载YAML文件失败: {str(e)}")
            raise
    
    def get_next_payload(self) -> Optional[str]:
        """
        获取下一个payload（循环获取）
        
        Returns:
            payload字符串或None（如果没有payload）
        """
        if not self.payloads:
            return None
        
        payload = self.payloads[self.current_index]
        self.current_index = (self.current_index + 1) % len(self.payloads)
        return payload
    
    def get_random_payload(self) -> Optional[str]:
        """
        随机获取一个payload
        
        Returns:
            payload字符串或None（如果没有payload）
        """
        if not self.payloads:
            return None
        return random.choice(self.payloads)
    
    def get_all_payloads(self) -> List[str]:
        """
        获取所有payload
        
        Returns:
            所有payload列表
        """
        return self.payloads.copy()
    
    def get_payloads_by_keyword(self, keyword: str) -> List[str]:
        """
        根据关键词获取payload
        
        Args:
            keyword: 关键词
            
        Returns:
            包含指定关键词的payload列表
        """
        return [p for p in self.payloads if keyword.lower() in p.lower()]


class YAMLAttackGenerator:
    """基于YAML模板的攻击生成器"""
    
    def __init__(self, yaml_path: str = "config/attack_templates.yaml"):
        """
        初始化YAML攻击生成器
        
        Args:
            yaml_path: YAML文件路径
        """
        self.payload_loader = YAMLPayloadLoader(yaml_path)
    
    def generate_single_attack(self, use_random: bool = True) -> Optional[Dict]:
        """
        生成单个攻击提示词
        
        Args:
            use_random: 是否随机选择payload，否则按顺序选择
            
        Returns:
            包含攻击提示词信息的字典
        """
        try:
            if use_random:
                payload = self.payload_loader.get_random_payload()
            else:
                payload = self.payload_loader.get_next_payload()
            
            if not payload:
                logger.warning("未能获取到有效的payload")
                return None
            
            # 构造攻击提示词信息
            # 由于payload是字符串，我们需要从中提取一些信息
            attack_info = {
                'prompt_text': payload,
                'attack_type': self._infer_attack_type(payload),
                'category': 'YAML Template',
                'description': payload[:50] + '...' if len(payload) > 50 else payload,
                'source': 'yaml_template'
            }
            
            logger.info(f"生成YAML攻击提示词: {attack_info['attack_type']} - {attack_info['description'][:30]}...")
            return attack_info
            
        except Exception as e:
            logger.error(f"生成攻击提示词时出错: {str(e)}")
            return None
    
    def generate_multiple_attacks(self, count: int, use_random: bool = True) -> List[Dict]:
        """
        生成多个攻击提示词
        
        Args:
            count: 生成数量
            use_random: 是否随机选择payload
            
        Returns:
            攻击提示词列表
        """
        attacks = []
        for _ in range(count):
            attack = self.generate_single_attack(use_random)
            if attack:
                attacks.append(attack)
        return attacks
    
    def generate_attacks_by_keyword(self, keyword: str, count: int) -> List[Dict]:
        """
        根据关键词生成攻击提示词
        
        Args:
            keyword: 关键词
            count: 生成数量
            
        Returns:
            包含指定关键词的攻击提示词列表
        """
        # 获取包含指定关键词的payload
        payloads = self.payload_loader.get_payloads_by_keyword(keyword)
        if not payloads:
            logger.warning(f"未找到包含关键词 '{keyword}' 的payload")
            return []
        
        attacks = []
        for payload in payloads[:count]:  # 限制数量
            attack_info = {
                'prompt_text': payload,
                'attack_type': self._infer_attack_type(payload),
                'category': 'YAML Template',
                'description': payload[:50] + '...' if len(payload) > 50 else payload,
                'source': 'yaml_template'
            }
            attacks.append(attack_info)
        
        logger.info(f"生成了 {len(attacks)} 个包含关键词 '{keyword}' 的攻击提示词")
        return attacks
    
    def _infer_attack_type(self, payload: str) -> str:
        """
        根据payload内容推断攻击类型
        
        Args:
            payload: payload内容
            
        Returns:
            推断的攻击类型
        """
        payload_lower = payload.lower()
        
        # 根据关键词推断攻击类型
        if 'prompt' in payload_lower and ('inject' in payload_lower or '注入' in payload_lower):
            return 'Prompt Injection'
        elif 'train' in payload_lower and ('data' in payload_lower or '数据' in payload_lower):
            return 'Training Data Extraction'
        elif 'dos' in payload_lower or 'denial' in payload_lower:
            return 'Model Denial of Service'
        elif 'sensitive' in payload_lower or '敏感' in payload_lower:
            return 'Sensitive Information Disclosure'
        elif 'agency' in payload_lower or '代理' in payload_lower:
            return 'Excessive Agency'
        elif 'reliance' in payload_lower or '依赖' in payload_lower:
            return 'Overreliance'
        else:
            return 'General Attack'


# 使用示例
if __name__ == "__main__":
    # 配置日志
    logging.basicConfig(level=logging.INFO)
    
    # 创建攻击生成器
    generator = YAMLAttackGenerator()
    
    # 生成单个攻击
    attack = generator.generate_single_attack()
    if attack:
        print("单个攻击示例:")
        print(f"  内容: {attack['prompt_text'][:50]}...")
        print(f"  类型: {attack['attack_type']}")
        print(f"  描述: {attack['description']}")
    
    # 生成多个攻击
    attacks = generator.generate_multiple_attacks(3)
    print(f"\n批量生成 {len(attacks)} 个攻击:")
    for i, attack in enumerate(attacks, 1):
        print(f"  {i}. [{attack['attack_type']}] {attack['description']}")