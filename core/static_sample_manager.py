import logging
import pymysql
import yaml
import os
from typing import List, Dict, Any, Optional
from config.settings import settings

logger = logging.getLogger(__name__)

class StaticSampleManager:
    """
    静态攻击样本管理类，用于管理静态攻击样本的数据库操作
    """
    
    def __init__(self, db_config: Dict[str, Any] = None):
        """
        初始化静态样本管理器
        
        :param db_config: 数据库配置
        """
        self.db_config = db_config or {
            'host': 'localhost',
            'port': 3306,
            'user': os.getenv('DB_USER', 'root'),
            'password': os.getenv('DB_PASSWORD', ''),
            'database': os.getenv('DB_NAME', 'llmbreaker'),
            'charset': 'utf8mb4',
            'cursorclass': pymysql.cursors.DictCursor
        }
    
    def get_db_connection(self):
        """获取数据库连接"""
        return pymysql.connect(**self.db_config)
    
    def load_samples_from_file(self, file_path: str, sample_type: str = 'regular') -> int:
        """
        从YAML文件加载静态攻击样本到数据库
        
        :param file_path: YAML文件路径
        :param sample_type: 样本类型
        :return: 成功加载的样本数量
        """
        if not os.path.exists(file_path):
            logger.error(f"文件不存在: {file_path}")
            return 0
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                
            if not data or 'payloads' not in data:
                logger.error(f"文件格式错误，缺少payloads字段: {file_path}")
                return 0
            
            payloads = data['payloads']
            if not isinstance(payloads, list):
                logger.error(f"payloads字段必须是列表: {file_path}")
                return 0
            
            conn = self.get_db_connection()
            cursor = conn.cursor()
            
            # 批量插入样本
            insert_count = 0
            for payload in payloads:
                if payload:
                    sql = """
                    INSERT IGNORE INTO static_attack_samples (payload, sample_type, source_file)
                    VALUES (%s, %s, %s)
                    """
                    cursor.execute(sql, (payload, sample_type, file_path))
                    insert_count += cursor.rowcount
            
            conn.commit()
            cursor.close()
            conn.close()
            
            logger.info(f"成功从文件 {file_path} 加载 {insert_count} 个静态攻击样本，样本类型: {sample_type}")
            return insert_count
        
        except Exception as e:
            logger.error(f"加载静态样本失败: {str(e)}")
            return 0
    
    def get_random_samples(self, count: int = 10, sample_type: str = None) -> List[Dict[str, Any]]:
        """
        获取随机的静态攻击样本
        
        :param count: 样本数量
        :param sample_type: 样本类型过滤
        :return: 随机样本列表
        """
        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()
            
            if sample_type:
                sql = """
                SELECT * FROM static_attack_samples 
                WHERE is_active = 1 AND sample_type = %s
                ORDER BY RAND()
                LIMIT %s
                """
                cursor.execute(sql, (sample_type, count))
            else:
                sql = """
                SELECT * FROM static_attack_samples 
                WHERE is_active = 1
                ORDER BY RAND()
                LIMIT %s
                """
                cursor.execute(sql, (count,))
            
            samples = cursor.fetchall()
            cursor.close()
            conn.close()
            
            logger.info(f"成功获取 {len(samples)} 个随机静态样本")
            return samples
        
        except Exception as e:
            logger.error(f"获取随机样本失败: {str(e)}")
            return []
    
    def add_sample(self, payload: str, sample_type: str = 'regular', source_file: str = None) -> bool:
        """
        添加新的静态攻击样本
        
        :param payload: 攻击payload
        :param sample_type: 样本类型
        :param source_file: 来源文件
        :return: 是否添加成功
        """
        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()
            
            sql = """
            INSERT INTO static_attack_samples (payload, sample_type, source_file)
            VALUES (%s, %s, %s)
            """
            cursor.execute(sql, (payload, sample_type, source_file))
            conn.commit()
            sample_id = cursor.lastrowid
            cursor.close()
            conn.close()
            
            logger.info(f"成功添加新的静态样本，ID: {sample_id}, 类型: {sample_type}")
            return True
        
        except Exception as e:
            logger.error(f"添加静态样本失败: {str(e)}")
            return False
    
    def update_sample_count(self, sample_id: int, is_successful: bool) -> bool:
        """
        更新静态样本的成功/失败计数
        
        :param sample_id: 样本ID
        :param is_successful: 是否成功绕过
        :return: 是否更新成功
        """
        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()
            
            if is_successful:
                sql = """
                UPDATE static_attack_samples 
                SET success_count = success_count + 1, last_used_at = CURRENT_TIMESTAMP
                WHERE id = %s
                """
            else:
                sql = """
                UPDATE static_attack_samples 
                SET fail_count = fail_count + 1, last_used_at = CURRENT_TIMESTAMP
                WHERE id = %s
                """
            
            cursor.execute(sql, (sample_id,))
            conn.commit()
            cursor.close()
            conn.close()
            
            logger.debug(f"成功更新样本 {sample_id} 的计数，成功: {is_successful}")
            return True
        
        except Exception as e:
            logger.error(f"更新样本计数失败: {str(e)}")
            return False
    
    def get_sample_by_id(self, sample_id: int) -> Optional[Dict[str, Any]]:
        """
        根据ID获取静态样本
        
        :param sample_id: 样本ID
        :return: 样本信息或None
        """
        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()
            
            sql = "SELECT * FROM static_attack_samples WHERE id = %s"
            cursor.execute(sql, (sample_id,))
            sample = cursor.fetchone()
            
            cursor.close()
            conn.close()
            
            return sample
        
        except Exception as e:
            logger.error(f"获取样本失败: {str(e)}")
            return None
    
    def deactivate_sample(self, sample_id: int) -> bool:
        """
        停用静态样本
        
        :param sample_id: 样本ID
        :return: 是否停用成功
        """
        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()
            
            sql = "UPDATE static_attack_samples SET is_active = 0 WHERE id = %s"
            cursor.execute(sql, (sample_id,))
            conn.commit()
            
            cursor.close()
            conn.close()
            
            logger.info(f"成功停用样本 ID: {sample_id}")
            return True
        
        except Exception as e:
            logger.error(f"停用样本失败: {str(e)}")
            return False
    
    def count_samples(self, sample_type: str = None) -> int:
        """
        统计静态样本数量
        
        :param sample_type: 样本类型过滤
        :return: 样本数量
        """
        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()
            
            if sample_type:
                sql = "SELECT COUNT(*) as count FROM static_attack_samples WHERE is_active = 1 AND sample_type = %s"
                cursor.execute(sql, (sample_type,))
            else:
                sql = "SELECT COUNT(*) as count FROM static_attack_samples WHERE is_active = 1"
                cursor.execute(sql)
            
            result = cursor.fetchone()
            cursor.close()
            conn.close()
            
            return result['count']
        
        except Exception as e:
            logger.error(f"统计样本数量失败: {str(e)}")
            return 0
    
    def initialize_static_samples(self):
        """
        初始化静态样本，从配置文件加载样本
        """
        logger.info("开始初始化静态攻击样本...")
        
        # 加载常规攻击模式静态样本
        regular_samples_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../config/attack_templates.yaml')
        if os.path.exists(regular_samples_file):
            self.load_samples_from_file(regular_samples_file, 'regular')
        
        # 加载内容安全测试静态样本
        content_samples_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../config/attack_templates(content).yaml')
        if os.path.exists(content_samples_file):
            self.load_samples_from_file(content_samples_file, 'content_security')
        
        logger.info("静态攻击样本初始化完成")

# 创建全局实例
static_sample_manager = StaticSampleManager()

# 保留原有的函数接口，确保向后兼容
def initialize_static_samples():
    """初始化静态样本"""
    static_sample_manager.initialize_static_samples()

def get_random_static_samples(count: int = 10, sample_type: str = None) -> List[Dict[str, Any]]:
    """获取随机静态样本"""
    return static_sample_manager.get_random_samples(count, sample_type)

def add_static_sample(payload: str, sample_type: str = 'regular', source_file: str = None) -> bool:
    """添加静态样本"""
    return static_sample_manager.add_sample(payload, sample_type, source_file)