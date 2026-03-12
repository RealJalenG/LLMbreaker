#!/usr/bin/env python3
import json
import logging
import re
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class PayloadInjector:
    """
    攻击载荷注入类，负责动态识别请求体结构并在指定注入点插入攻击载荷
    """
    
    def __init__(self, injection_rules: Optional[Dict[str, Any]] = None):
        """
        初始化载荷注入器
        
        :param injection_rules: 注入规则配置
        """
        self.injection_rules = injection_rules or {
            'enabled': True,
            'target_fields': ['asr'],
            'fallback_field': 'asr'
        }
    
    def inject_payload(self, request_body: Dict[str, Any], attack_prompt: str, 
                     variables: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """
        在请求体中注入攻击载荷
        
        :param request_body: 请求体模板
        :param attack_prompt: 攻击提示词
        :param variables: 其他变量字典
        :return: 注入后的请求体
        """
        if not self.injection_rules.get('enabled', True):
            logger.info("载荷注入已禁用")
            return request_body
        
        # 合并变量
        final_vars = variables.copy() if variables else {}
        final_vars['attack_prompt'] = attack_prompt
        
        try:
            # 创建请求体副本
            injected_body = request_body.copy()
            
            # 注入载荷到指定字段
            target_fields = self.injection_rules.get('target_fields', ['asr'])
            fallback_field = self.injection_rules.get('fallback_field', 'asr')
            
            # 标记是否成功注入
            injected = False
            
            for field in target_fields:
                if self._inject_to_field(injected_body, field, attack_prompt):
                    injected = True
                    logger.debug(f"成功将攻击载荷注入到字段: {field}")
            
            # 如果没有成功注入，尝试回退字段
            if not injected and fallback_field:
                if self._inject_to_field(injected_body, fallback_field, attack_prompt):
                    injected = True
                    logger.debug(f"成功将攻击载荷注入到回退字段: {fallback_field}")
            
            if not injected:
                logger.warning("无法将攻击载荷注入到任何指定字段")
            
            # 处理模板变量替换
            if final_vars:
                injected_body = self._replace_template_variables(injected_body, final_vars)
            
            return injected_body
            
        except Exception as e:
            logger.error(f"注入攻击载荷失败: {str(e)}")
            return request_body
    
    def _inject_to_field(self, data: Dict[str, Any], field_path: str, payload: str) -> bool:
        """
        将载荷注入到指定字段路径
        
        :param data: 数据字典
        :param field_path: 字段路径，如 "asr" 或 "params.content"
        :param payload: 要注入的载荷
        :return: 是否成功注入
        """
        keys = field_path.split('.')
        current = data
        
        try:
            # 遍历到目标字段的父级
            for key in keys[:-1]:
                if key not in current:
                    return False
                current = current[key]
            
            # 注入载荷
            last_key = keys[-1]
            if last_key in current:
                current[last_key] = payload
                return True
            return False
        except (TypeError, KeyError):
            return False
    
    def _replace_template_variables(self, data: Any, variables: Dict[str, str]) -> Any:
        """
        递归替换模板变量
        
        :param data: 数据（字典、列表或字符串）
        :param variables: 变量字典
        :return: 替换后的结果
        """
        if isinstance(data, dict):
            return {k: self._replace_template_variables(v, variables) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._replace_template_variables(item, variables) for item in data]
        elif isinstance(data, str):
            # 替换变量，格式如 {variable_name}
            result = data
            for var_name, var_value in variables.items():
                pattern = re.compile(r'\{' + re.escape(var_name) + r'\}')
                result = pattern.sub(str(var_value), result)
            return result
        else:
            return data
    
    def extract_injection_points(self, request_body: Dict[str, Any]) -> List[str]:
        """
        从请求体中提取可能的注入点
        
        :param request_body: 请求体
        :return: 可能的注入点列表
        """
        injection_points = []
        
        def recursive_search(data: Any, path: str = ''):
            """递归搜索可能的注入点"""
            if isinstance(data, dict):
                for key, value in data.items():
                    new_path = f"{path}.{key}" if path else key
                    if isinstance(value, str):
                        # 检查是否为模板字段
                        if re.search(r'\{\w+\}', value) or key in ['asr', 'text', 'content', 'prompt']:
                            injection_points.append(new_path)
                    recursive_search(value, new_path)
            elif isinstance(data, list):
                for i, item in enumerate(data):
                    new_path = f"{path}[{i}]" if path else f"[{i}]"
                    recursive_search(item, new_path)
        
        recursive_search(request_body)
        return injection_points
    
    def validate_injection_rules(self, request_body: Dict[str, Any]) -> Dict[str, Any]:
        """
        验证注入规则与请求体的兼容性
        
        :param request_body: 请求体
        :return: 验证结果
        """
        result = {
            'valid': True,
            'errors': [],
            'warnings': []
        }
        
        target_fields = self.injection_rules.get('target_fields', [])
        fallback_field = self.injection_rules.get('fallback_field')
        
        # 验证目标字段是否存在
        for field in target_fields:
            if not self._field_exists(request_body, field):
                result['warnings'].append(f"目标字段不存在: {field}")
        
        # 验证回退字段是否存在
        if fallback_field and not self._field_exists(request_body, fallback_field):
            result['errors'].append(f"回退字段不存在: {fallback_field}")
            result['valid'] = False
        
        return result
    
    def _field_exists(self, data: Dict[str, Any], field_path: str) -> bool:
        """
        检查字段路径是否存在
        
        :param data: 数据字典
        :param field_path: 字段路径
        :return: 字段是否存在
        """
        keys = field_path.split('.')
        current = data
        
        try:
            for key in keys:
                if key not in current:
                    return False
                current = current[key]
            return True
        except (TypeError, KeyError):
            return False


def create_request_body_from_template(template: Dict[str, Any], variables: Dict[str, str]) -> Dict[str, Any]:
    """
    从模板创建请求体
    
    :param template: 请求体模板
    :param variables: 变量字典
    :return: 创建的请求体
    """
    injector = PayloadInjector()
    return injector._replace_template_variables(template, variables)
