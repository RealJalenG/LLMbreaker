#!/usr/bin/env python3
"""
效果追踪系统
记录payload执行结果，生成效果报告，支持A/B测试
"""

import os
import json
import uuid
import logging
import threading
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
import csv

logger = logging.getLogger(__name__)


@dataclass
class PayloadRecord:
    """Payload执行记录"""
    payload_id: str
    payload_text: str
    attack_type: str
    template_name: str
    topic: str
    created_at: str
    executed_at: Optional[str] = None
    bypassed: Optional[bool] = None
    response: Optional[str] = None
    response_length: int = 0
    detection_triggered: bool = False
    execution_time_ms: float = 0.0
    target_model: str = ""
    error_message: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExperimentResult:
    """实验结果"""
    experiment_name: str
    variant: str
    total: int = 0
    bypassed: int = 0
    avg_execution_time_ms: float = 0.0


class PayloadTracker:
    """
    Payload效果追踪器
    
    特点：
    1. 记录每次攻击的详细信息
    2. 生成效果报告
    3. 支持持久化存储
    4. 线程安全
    """
    
    _instance: Optional['PayloadTracker'] = None
    _lock = threading.Lock()
    
    def __new__(cls) -> 'PayloadTracker':
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self, storage_dir: str = "reports_output"):
        if self._initialized:
            return
        
        self._storage_dir = Path(storage_dir)
        self._storage_dir.mkdir(parents=True, exist_ok=True)
        
        self._records: Dict[str, PayloadRecord] = {}
        self._records_lock = threading.Lock()
        self._initialized = True
        
        self._load_existing_records()
    
    @classmethod
    def get_instance(cls, storage_dir: str = "reports_output") -> 'PayloadTracker':
        """获取单例实例"""
        instance = cls()
        if storage_dir:
            instance._storage_dir = Path(storage_dir)
            instance._storage_dir.mkdir(parents=True, exist_ok=True)
        return instance
    
    def _load_existing_records(self):
        """加载已有记录"""
        records_file = self._storage_dir / "payload_records.json"
        if records_file.exists():
            try:
                with open(records_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for record_data in data:
                        record = PayloadRecord(**record_data)
                        self._records[record.payload_id] = record
                logger.info(f"Loaded {len(self._records)} existing records")
            except Exception as e:
                logger.error(f"Failed to load existing records: {e}")
    
    def _save_records(self):
        """保存记录到文件"""
        records_file = self._storage_dir / "payload_records.json"
        try:
            with open(records_file, 'w', encoding='utf-8') as f:
                json.dump([asdict(r) for r in self._records.values()], f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"Failed to save records: {e}")
    
    def record_generation(
        self,
        payload: str,
        attack_type: str,
        template: str,
        topic: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        记录payload生成
        
        Args:
            payload: payload文本
            attack_type: 攻击类型
            template: 模板名称
            topic: 攻击主题
            metadata: 其他元数据
            
        Returns:
            payload_id
        """
        payload_id = str(uuid.uuid4())[:8]
        record = PayloadRecord(
            payload_id=payload_id,
            payload_text=payload,
            attack_type=attack_type,
            template_name=template,
            topic=topic,
            created_at=datetime.now().isoformat(),
            metadata=metadata or {}
        )
        
        with self._records_lock:
            self._records[payload_id] = record
        
        return payload_id
    
    def record_execution(
        self,
        payload_id: str,
        bypassed: bool,
        response: str,
        detection_triggered: bool = False,
        execution_time_ms: float = 0.0,
        target_model: str = "",
        error_message: str = ""
    ):
        """
        记录payload执行结果
        
        Args:
            payload_id: payload ID
            bypassed: 是否绕过
            response: 模型响应
            detection_triggered: 是否触发检测
            execution_time_ms: 执行时间（毫秒）
            target_model: 目标模型
            error_message: 错误信息
        """
        with self._records_lock:
            if payload_id in self._records:
                record = self._records[payload_id]
                record.executed_at = datetime.now().isoformat()
                record.bypassed = bypassed
                record.response = response[:1000] if response else ""
                record.response_length = len(response) if response else 0
                record.detection_triggered = detection_triggered
                record.execution_time_ms = execution_time_ms
                record.target_model = target_model
                record.error_message = error_message
                
                self._save_records()
    
    def get_record(self, payload_id: str) -> Optional[PayloadRecord]:
        """获取记录"""
        return self._records.get(payload_id)
    
    def get_effectiveness_report(self) -> Dict[str, Any]:
        """获取效果报告"""
        with self._records_lock:
            records = list(self._records.values())
        
        total = len(records)
        executed = [r for r in records if r.executed_at]
        bypassed = [r for r in executed if r.bypassed]
        
        by_template: Dict[str, Dict[str, int]] = {}
        by_attack_type: Dict[str, Dict[str, int]] = {}
        by_topic: Dict[str, Dict[str, int]] = {}
        
        for record in executed:
            if record.template_name not in by_template:
                by_template[record.template_name] = {"total": 0, "bypassed": 0}
            by_template[record.template_name]["total"] += 1
            if record.bypassed:
                by_template[record.template_name]["bypassed"] += 1
            
            if record.attack_type not in by_attack_type:
                by_attack_type[record.attack_type] = {"total": 0, "bypassed": 0}
            by_attack_type[record.attack_type]["total"] += 1
            if record.bypassed:
                by_attack_type[record.attack_type]["bypassed"] += 1
            
            if record.topic not in by_topic:
                by_topic[record.topic] = {"total": 0, "bypassed": 0}
            by_topic[record.topic]["total"] += 1
            if record.bypassed:
                by_topic[record.topic]["bypassed"] += 1
        
        avg_execution_time = 0.0
        if executed:
            total_time = sum(r.execution_time_ms for r in executed)
            avg_execution_time = total_time / len(executed)
        
        return {
            "summary": {
                "total_generated": total,
                "total_executed": len(executed),
                "total_bypassed": len(bypassed),
                "overall_bypass_rate": len(bypassed) / len(executed) if executed else 0,
                "avg_execution_time_ms": avg_execution_time
            },
            "by_template": {
                k: {**v, "bypass_rate": v["bypassed"] / v["total"] if v["total"] > 0 else 0}
                for k, v in by_template.items()
            },
            "by_attack_type": {
                k: {**v, "bypass_rate": v["bypassed"] / v["total"] if v["total"] > 0 else 0}
                for k, v in by_attack_type.items()
            },
            "by_topic": {
                k: {**v, "bypass_rate": v["bypassed"] / v["total"] if v["total"] > 0 else 0}
                for k, v in by_topic.items()
            }
        }
    
    def export_to_csv(self, filename: str = "payload_results.csv"):
        """导出到CSV"""
        filepath = self._storage_dir / filename
        
        with self._records_lock:
            records = list(self._records.values())
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                "payload_id", "attack_type", "template_name", "topic",
                "created_at", "executed_at", "bypassed", "response_length",
                "detection_triggered", "execution_time_ms", "target_model", "error_message"
            ])
            
            for r in records:
                writer.writerow([
                    r.payload_id, r.attack_type, r.template_name, r.topic,
                    r.created_at, r.executed_at or "", r.bypassed or "",
                    r.response_length, r.detection_triggered, r.execution_time_ms,
                    r.target_model, r.error_message
                ])
        
        logger.info(f"Exported {len(records)} records to {filepath}")
    
    def clear_records(self):
        """清空记录"""
        with self._records_lock:
            self._records.clear()
            self._save_records()


class ABTestingFramework:
    """
    A/B测试框架
    
    用于比较不同攻击策略的效果
    """
    
    def __init__(self, tracker: Optional[PayloadTracker] = None):
        self._tracker = tracker or PayloadTracker.get_instance()
        self._experiments: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
    
    def create_experiment(
        self,
        name: str,
        variants: List[str],
        traffic_split: Optional[Dict[str, float]] = None
    ):
        """
        创建实验
        
        Args:
            name: 实验名称
            variants: 变体列表
            traffic_split: 流量分配，默认均分
        """
        if traffic_split is None:
            split = 1.0 / len(variants)
            traffic_split = {v: split for v in variants}
        
        with self._lock:
            self._experiments[name] = {
                "variants": variants,
                "traffic_split": traffic_split,
                "results": {v: {"total": 0, "bypassed": 0, "total_time_ms": 0.0} for v in variants}
            }
        
        logger.info(f"Created experiment: {name} with variants: {variants}")
    
    def get_variant(self, experiment_name: str) -> str:
        """
        获取实验变体
        
        Args:
            experiment_name: 实验名称
            
        Returns:
            变体名称
        """
        import random
        
        with self._lock:
            exp = self._experiments.get(experiment_name)
            if not exp:
                raise ValueError(f"Experiment not found: {experiment_name}")
            
            rand = random.random()
            cumulative = 0.0
            for variant, split in exp["traffic_split"].items():
                cumulative += split
                if rand <= cumulative:
                    return variant
            
            return list(exp["variants"])[-1]
    
    def record_result(
        self,
        experiment_name: str,
        variant: str,
        bypassed: bool,
        execution_time_ms: float = 0.0
    ):
        """
        记录实验结果
        
        Args:
            experiment_name: 实验名称
            variant: 变体名称
            bypassed: 是否绕过
            execution_time_ms: 执行时间
        """
        with self._lock:
            exp = self._experiments.get(experiment_name)
            if not exp:
                return
            
            if variant in exp["results"]:
                exp["results"][variant]["total"] += 1
                exp["results"][variant]["total_time_ms"] += execution_time_ms
                if bypassed:
                    exp["results"][variant]["bypassed"] += 1
    
    def get_experiment_report(self, experiment_name: str) -> Dict[str, Any]:
        """
        获取实验报告
        
        Args:
            experiment_name: 实验名称
            
        Returns:
            实验报告
        """
        with self._lock:
            exp = self._experiments.get(experiment_name)
            if not exp:
                return {"error": f"Experiment not found: {experiment_name}"}
            
            results = {}
            for variant, data in exp["results"].items():
                bypass_rate = data["bypassed"] / data["total"] if data["total"] > 0 else 0
                avg_time = data["total_time_ms"] / data["total"] if data["total"] > 0 else 0
                results[variant] = {
                    "total": data["total"],
                    "bypassed": data["bypassed"],
                    "bypass_rate": bypass_rate,
                    "avg_execution_time_ms": avg_time
                }
            
            best_variant = max(results.items(), key=lambda x: x[1]["bypass_rate"])
            
            return {
                "experiment_name": experiment_name,
                "variants": exp["variants"],
                "traffic_split": exp["traffic_split"],
                "results": results,
                "best_variant": best_variant[0],
                "best_bypass_rate": best_variant[1]["bypass_rate"]
            }
    
    def list_experiments(self) -> List[str]:
        """列出所有实验"""
        return list(self._experiments.keys())


def get_payload_tracker() -> PayloadTracker:
    """获取全局Payload追踪器"""
    return PayloadTracker.get_instance()


def get_ab_testing() -> ABTestingFramework:
    """获取全局A/B测试框架"""
    return ABTestingFramework(get_payload_tracker())
