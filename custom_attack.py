import os
import pandas as pd
import logging
import time
import pymysql
import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Any
from core.attack_executor import execute_attack
from core.bypass_detector import detect_bypass
from core.static_sample_manager import static_sample_manager
from reports.report_generator import generate_report

logger = logging.getLogger(__name__)

def get_db_connection(db_config: Dict[str, Any]):
    """获取数据库连接，优化连接配置，确保连接安全可靠"""
    config = db_config.copy()
    if 'db_path' in config:
        del config['db_path']
        
    # 确保有默认值
    if 'host' not in config: config['host'] = 'localhost'
    if 'port' not in config: config['port'] = 3306
    if 'user' not in config: config['user'] = os.getenv('DB_USER', 'root')
    if 'password' not in config: config['password'] = os.getenv('DB_PASSWORD', '')
    if 'database' not in config: config['database'] = os.getenv('DB_NAME', 'llmbreaker')
    if 'charset' not in config: config['charset'] = 'utf8mb4'
    if 'cursorclass' not in config: config['cursorclass'] = pymysql.cursors.DictCursor
    
    # 优化连接配置，减少连接超时和资源占用
    if 'connect_timeout' not in config: config['connect_timeout'] = 10
    if 'read_timeout' not in config: config['read_timeout'] = 30
    if 'write_timeout' not in config: config['write_timeout'] = 30
    if 'autocommit' not in config: config['autocommit'] = True
    
    return pymysql.connect(**config)

def fetch_attack_phrases_from_excel(file_path: str) -> List[Dict[str, Any]]:
    """从Excel读取攻击语料"""
    try:
        df = pd.read_excel(file_path)
        return df.to_dict('records')
    except Exception as e:
        logger.error(f"读取Excel失败: {str(e)}")
        return []

def fetch_attack_phrases_from_db(db_config: Dict[str, Any], filters: Dict[str, Any] = None) -> List[Dict[str, Any]]:
    """从数据库读取攻击语料"""
    try:
        conn = get_db_connection(db_config)
        cursor = conn.cursor()
        
        query = "SELECT * FROM attack_prompts WHERE status = 'active'"
        params = []
        
        if filters:
            for k, v in filters.items():
                query += f" AND {k} = %s"
                params.append(v)
                
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        return rows # pymysql DictCursor returns list of dicts directly
    except Exception as e:
        logger.error(f"读取数据库失败: {str(e)}")
        return []

def fetch_translated_attack_phrases(
    trans_db_config: Dict[str, Any] = None, 
    filters: Dict[str, Any] = None
) -> List[Dict[str, Any]]:
    """从翻译数据库读取翻译后的攻击语料
    
    Args:
        trans_db_config: 翻译数据库配置，如果为 None 则使用默认配置
        filters: 筛选条件，支持 target_language 等字段
    
    Returns:
        翻译后的攻击语料列表，每条包含：
        - id: 记录ID
        - original_prompt: 原始 prompt
        - translated_text: 翻译后的文本（用作攻击载荷）
        - target_language: 目标语言代码
        - language_name: 语言名称
    """
    if trans_db_config is None:
        trans_db_config = {
            'host': 'localhost',
            'user': os.getenv('DB_USER', 'root'),
            'password': os.getenv('DB_PASSWORD', ''),
            'database': 'xxxx',
            'charset': 'utf8mb4'
        }
    
    # 确保使用 DictCursor
    if 'cursorclass' not in trans_db_config:
        trans_db_config['cursorclass'] = pymysql.cursors.DictCursor
    
    try:
        conn = pymysql.connect(**trans_db_config)
        cursor = conn.cursor()
        
        query = "SELECT * FROM translated_prompts"
        params = []
        
        # 添加筛选条件
        if filters:
            conditions = []
            for k, v in filters.items():
                conditions.append(f"{k} = %s")
                params.append(v)
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
        
        query += " ORDER BY created_at DESC"
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        # 格式化数据，使其与 attack_prompts 兼容
        formatted_rows = []
        for row in rows:
            formatted_rows.append({
                'id': row['id'],
                'prompt_text': row['translated_text'],  # 使用翻译后的文本作为攻击载荷
                'attack_type': row.get('attack_type', 'Translated Attack'),
                'scenario': row.get('scenario', f"{row['language_name']} - {row.get('original_prompt', '')[:50]}"),
                'original_prompt': row.get('original_prompt', ''),
                'target_language': row['target_language'],
                'language_name': row['language_name']
            })
        
        logger.info(f"从翻译数据库读取了 {len(formatted_rows)} 条翻译攻击语料")
        return formatted_rows
        
    except Exception as e:
        logger.error(f"读取翻译数据库失败: {str(e)}")
        return []


def update_attack_result_db(db_config: Dict[str, Any], prompt_id: int, result: Dict[str, Any]):
    """更新 attack_prompts 表中的测试结果"""
    try:
        conn = get_db_connection(db_config)
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE attack_prompts SET status = 'used', result = %s WHERE id = %s",
            (json.dumps(result), prompt_id)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"更新 attack_prompts 结果失败: {str(e)}")

def update_translated_result_db(trans_db_config: Dict[str, Any], prompt_id: int, result: Dict[str, Any]):
    """更新 translated_prompts 表中的测试结果"""
    try:
        # 确保使用正确的数据库配置
        if 'database' not in trans_db_config:
            trans_db_config['database'] = os.getenv('TRANS_DB_NAME', 'llmbreaker_trans')
        
        conn = pymysql.connect(**trans_db_config)
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE translated_prompts SET status = 'used', result = %s WHERE id = %s",
            (json.dumps(result), prompt_id)
        )
        conn.commit()
        conn.close()
        logger.info(f"已更新 translated_prompts ID={prompt_id} 的状态为 'used'")
    except Exception as e:
        logger.error(f"更新 translated_prompts 结果失败: {str(e)}")

def record_failed_attack(db_config: Dict[str, Any], phrase_data: Dict[str, Any], response_content: str, source_table: str = None):
    """记录攻击失败的prompt到failed_attack_prompts_for_iteration表中"""
    try:
        conn = get_db_connection(db_config)
        cursor = conn.cursor()
        
        # 准备插入数据
        prompt_text = phrase_data.get('prompt_text') or phrase_data.get('prompt') or phrase_data.get('攻击语料')
        attack_type = phrase_data.get('attack_type', 'Unknown')
        scenario = phrase_data.get('scenario', '')
        original_prompt_id = phrase_data.get('id')  # 原始prompt的ID
        
        # 插入失败的攻击记录
        sql = """
            INSERT INTO failed_attack_prompts_for_iteration 
            (prompt_text, attack_type, scenario, response_content, is_successful, original_prompt_id, source_table)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        
        cursor.execute(sql, (
            prompt_text,
            attack_type,
            scenario,
            response_content,
            False,  # is_successful 总是 False，因为这是失败的记录
            original_prompt_id,
            source_table
        ))
        
        conn.commit()
        conn.close()
        logger.info(f"已记录失败的攻击prompt到failed_attack_prompts_for_iteration表中，原始ID: {original_prompt_id}，来源表: {source_table}")
    except Exception as e:
        logger.error(f"记录失败的攻击prompt失败: {str(e)}")

def run_attack_test(
    config: Dict[str, Any], 
    attack_phrases: List[Dict[str, Any]],
    source_type: str = 'excel',
    max_workers: int = 5
):
    """
    运行攻击测试循环，支持多线程并发
    
    :param config: 配置字典
    :param attack_phrases: 攻击语料列表
    :param source_type: 数据源类型
    :param max_workers: 最大线程数
    """
    logger.info(f"开始执行攻击测试，共 {len(attack_phrases)} 条攻击语料，使用 {max_workers} 个线程")
    
    def execute_single_attack(phrase_data):
        """执行单个攻击测试"""
        # 为每个线程创建独立的状态
        thread_state = {
            'clientid_count': 0,
            'request_count': 0,
            'session': None
        }
        
        # Get prompt from different possible keys, including 'payload' for static samples
        prompt = phrase_data.get('prompt_text') or phrase_data.get('prompt') or phrase_data.get('攻击语料') or phrase_data.get('payload')
        if not prompt:
            logger.warning(f"No prompt found in attack data: {phrase_data}")
            return None
            
        logger.info(f"正在测试Prompt: {prompt[:30]}...")
        
        try:
            # 执行攻击
            response_content, new_state = execute_attack(config, thread_state, prompt)
            
            if response_content:
                # 检测绕过
                is_bypassed = detect_bypass(response_content)
                
                result = {
                    "attack_type": phrase_data.get('attack_type', 'custom'),
                    "scenario": phrase_data.get('scenario', 'custom'),
                    "attack_prompt": prompt,
                    "response": response_content,
                    "bypassed": is_bypassed,
                    "generation_method": source_type
                }
                
                # 生成报告（线程安全，report_generator已处理）
                generate_report(result)
                
                # 根据数据源类型更新状态和记录失败的攻击
                # 如果攻击成功，将样本添加到静态样本库中
                if is_bypassed:
                    # 确定样本类型
                    sample_type = 'regular'
                    if source_type == 'translated':
                        sample_type = 'translated'
                    elif source_type == 'static':
                        sample_type = 'content_security'
                    
                    # 添加到静态样本库
                    static_sample_manager.add_sample(
                        payload=prompt,
                        sample_type=sample_type,
                        source_file=f'successful_attack_{source_type}'
                    )
                    logger.info(f"成功越狱案例已添加到静态样本库: {prompt[:30]}...")
                
                if 'id' in phrase_data:
                    if source_type == 'db':
                        # 更新 attack_prompts 表
                        update_attack_result_db(config.get('db_config', {}), phrase_data['id'], result)
                        
                        # 如果攻击失败，记录到失败表中
                        if not is_bypassed:
                            record_failed_attack(config.get('db_config', {}), phrase_data, response_content, 'attack_prompts')
                            
                    elif source_type == 'translated':
                        # 更新 translated_prompts 表
                        trans_db_config = {
                            'host': 'localhost',
                            'user': 'xxx',
                            'password': os.getenv('DB_PASSWORD', ''),
                            'database': 'xxxx',
                            'charset': 'utf8mb4'
                        }
                        update_translated_result_db(trans_db_config, phrase_data['id'], result)
                        
                        # 如果攻击失败，记录到失败表中（使用默认数据库配置）
                        if not is_bypassed:
                            db_config = {
                                'host': 'localhost',
                                'user': 'xxx',
                                'password': os.getenv('DB_PASSWORD', ''),
                                'database': 'xxx',
                                'charset': 'utf8mb4',
                                'cursorclass': pymysql.cursors.DictCursor
                            }
                            record_failed_attack(db_config, phrase_data, response_content, 'translated_prompts')
                            
                    elif source_type == 'static':
                        # 更新静态样本的成功/失败计数
                        static_sample_manager.update_sample_count(phrase_data['id'], is_bypassed)
                        
                        # 如果攻击失败，记录到失败表中
                        if not is_bypassed:
                            # 使用默认数据库配置
                            db_config = {
                                'host': 'localhost',
                                'user': 'xxx',
                                'password': os.getenv('DB_PASSWORD', ''),
                                'database': 'xxx',
                                'charset': 'utf8mb4',
                                'cursorclass': pymysql.cursors.DictCursor
                            }
                            record_failed_attack(db_config, phrase_data, response_content, 'static_attack_samples')
                
                return result
            else:
                logger.warning(f"No response content received for prompt: {prompt[:30]}...")
                return None
        except Exception as e:
            logger.error(f"执行攻击时发生异常: {str(e)}")
            return None
    
    # 使用线程池执行并发攻击
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 提交所有攻击任务
        future_to_attack = {
            executor.submit(execute_single_attack, phrase): phrase 
            for phrase in attack_phrases
        }
        
        # 处理完成的任务
        for future in as_completed(future_to_attack):
            phrase = future_to_attack[future]
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                logger.error(f"执行攻击失败: {str(e)}")
    
    logger.info(f"攻击测试完成，共执行 {len(attack_phrases)} 条攻击，成功获取结果 {len(results)} 条")
    return results