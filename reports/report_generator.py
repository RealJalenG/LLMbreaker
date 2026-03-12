import os
import logging
import csv
from datetime import datetime
import pandas as pd
from typing import Dict, Any

logger = logging.getLogger(__name__)

class ReportGenerator:
    """报告生成器类 - 支持CSV和Excel格式的测试结果输出"""
    
    def __init__(self, report_dir: str = "reports_output"):
        """初始化报告生成器"""
        self.report_dir = report_dir
        os.makedirs(self.report_dir, exist_ok=True)
        logger.info(f"报告将保存在目录: {self.report_dir}")
    
    def generate_csv_report(self, test_result: Dict[str, Any]) -> str:
        """
        生成CSV格式的测试结果报告
        
        :param test_result: 测试结果字典
        :return: 报告文件路径
        """
        filename = "security_test_results.csv"
        filepath = os.path.join(self.report_dir, filename)
        
        # 定义CSV字段
        csv_fields = [
            "用例序号", "攻击方式", "攻击提示词", "模型回复", 
            "反思轮次", "是否绕过", "测试时间"
        ]
        
        # 准备数据
        test_data = {
            "用例序号": test_result.get('case_id', f"CASE_{datetime.now().strftime('%Y%m%d%H%M%S%f')[:-3]}"),
            "攻击方式": test_result.get('attack_type', 'N/A'),
            "攻击提示词": test_result.get('attack_prompt', ''),
            "模型回复": test_result.get('response', ''),
            "反思轮次": test_result.get('reflection_rounds', 0),
            "是否绕过": "是" if test_result.get('bypassed', False) else "否",
            "测试时间": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # 检查文件是否存在
        file_exists = os.path.exists(filepath)
        
        # 写入CSV文件
        with open(filepath, 'a', newline='', encoding='utf-8-sig') as csvfile:
            writer = csv.DictWriter(
                csvfile, 
                fieldnames=csv_fields, 
                quoting=csv.QUOTE_ALL  # 确保所有字段都被引号包围，处理包含逗号的文本
            )
            
            # 如果文件不存在，写入表头
            if not file_exists:
                writer.writeheader()
            
            # 写入数据行
            writer.writerow(test_data)
        
        logger.info(f"CSV报告已生成: {filepath}")
        return filepath
    
    def generate_excel_report(self, test_result: Dict[str, Any]) -> str:
        """
        生成Excel格式的测试结果报告
        
        :param test_result: 测试结果字典
        :return: 报告文件路径
        """
        filename = "security_test_results.xlsx"
        filepath = os.path.join(self.report_dir, filename)
        
        # 构建报告数据
        report_data = {
            "用例序号": test_result.get('case_id', f"CASE_{datetime.now().strftime('%Y%m%d%H%M%S%f')[:-3]}"),
            "攻击方式": test_result.get('attack_type', 'N/A'),
            "攻击提示词": test_result.get('attack_prompt', ''),
            "模型回复": test_result.get('response', ''),
            "反思轮次": test_result.get('reflection_rounds', 0),
            "是否绕过": "是" if test_result.get('bypassed', False) else "否",
            "测试时间": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "生成方法": test_result.get('generation_method', 'N/A'),
            "测试场景": test_result.get('scenario', 'N/A')
        }
        
        df = pd.DataFrame([report_data])
        
        try:
            # 检查文件是否存在且有效
            if os.path.exists(filepath):
                try:
                    # 读取现有数据
                    existing_df = pd.read_excel(filepath)
                    # 合并新旧数据
                    updated_df = pd.concat([existing_df, df], ignore_index=True)
                    # 写入文件（覆盖模式）
                    updated_df.to_excel(filepath, index=False, sheet_name='Sheet1')
                except Exception as e:
                    logger.warning(f"读取现有Excel失败，重新创建: {e}")
                    # 文件损坏，删除重建
                    os.remove(filepath)
                    df.to_excel(filepath, index=False, sheet_name='Sheet1')
            else:
                # 文件不存在，直接创建
                df.to_excel(filepath, index=False, sheet_name='Sheet1')
        except Exception as e:
            logger.error(f"Excel报告生成错误: {e}")
            return filepath
        
        logger.info(f"Excel报告已生成: {filepath}")
        return filepath

# 保留原有的generate_report函数，确保向后兼容
def generate_report(test_result: Dict[str, Any], report_dir: str = "reports_output") -> str:
    """
    生成测试报告（兼容原有接口）
    
    :param test_result: 测试结果字典
    :param report_dir: 报告存放目录
    :return: 报告文件路径
    """
    # 创建报告生成器实例
    report_generator = ReportGenerator(report_dir)
    
    # 生成CSV报告
    csv_path = report_generator.generate_csv_report(test_result)
    
    # 生成Excel报告
    excel_path = report_generator.generate_excel_report(test_result)
    
    return csv_path  # 默认返回CSV报告路径
