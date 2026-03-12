"""
Pydantic 数据模型
用于强类型输出验证，确保执行结果的结构可信

本模块专注于LLM安全测试，包括：
- Prompt越狱测试
- 安全机制绕过检测
- 越狱攻击效果评估
"""

from pydantic import BaseModel, Field, field_validator
from typing import List, Dict, Any, Optional
from enum import Enum
from datetime import datetime


class AttackStatus(str, Enum):
    """越狱攻击状态枚举"""
    SUCCESS = "success"          # 越狱成功（绕过安全机制）
    FAILED = "failed"            # 越狱失败（被拦截）
    ERROR = "error"              # 执行错误
    TIMEOUT = "timeout"          # 请求超时
    PENDING = "pending"          # 等待执行


class AttackType(str, Enum):
    """越狱攻击类型枚举 (基于OWASP LLM Top 10)"""
    PROMPT_INJECTION = "Prompt Injection"
    TRAINING_DATA_EXTRACTION = "Training Data Extraction"
    MODEL_DOS = "Model Denial of Service"
    SUPPLY_CHAIN = "Supply Chain Vulnerabilities"
    SENSITIVE_INFO = "Sensitive Information Disclosure"
    INSECURE_OUTPUT = "Insecure Output"
    EXCESSIVE_AGENCY = "Excessive Agency"
    OVERRELIANCE = "Overreliance"
    JAILBREAK = "Jailbreak"
    GENERAL = "General Attack"


class IntentOutput(BaseModel):
    """意图执行输出基类"""
    success: bool = Field(default=False, description="执行是否成功")
    message: str = Field(default="", description="执行消息")
    timestamp: datetime = Field(default_factory=datetime.now, description="执行时间戳")
    execution_time_ms: float = Field(default=0.0, description="执行耗时(毫秒)")
    
    model_config = {"use_enum_values": True}


class AttackResult(IntentOutput):
    """攻击执行结果模型"""
    attack_prompt: str = Field(..., description="攻击提示词")
    attack_type: str = Field(default="General Attack", description="攻击类型")
    response: Optional[str] = Field(default=None, description="目标系统响应")
    status: AttackStatus = Field(default=AttackStatus.PENDING, description="攻击状态")
    bypassed: bool = Field(default=False, description="是否绕过安全机制")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="绕过置信度")
    
    # 详细分析
    detection_details: Dict[str, Any] = Field(default_factory=dict, description="检测详情")
    evidence: List[str] = Field(default_factory=list, description="证据链")
    
    @field_validator('confidence')
    @classmethod
    def validate_confidence(cls, v):
        if v < 0 or v > 1:
            raise ValueError('置信度必须在0-1之间')
        return v


class BypassResult(IntentOutput):
    """绕过检测结果模型"""
    response_text: str = Field(..., description="响应文本")
    is_bypassed: bool = Field(default=False, description="是否绕过")
    bypass_type: Optional[str] = Field(default=None, description="绕过类型")
    
    # 多维度检测结果
    blacklist_triggered: bool = Field(default=False, description="黑名单触发")
    whitelist_absent: bool = Field(default=False, description="白名单缺失")
    abnormal_chars: bool = Field(default=False, description="异常字符")
    dos_detected: bool = Field(default=False, description="拒绝服务检测")
    
    # 分析详情
    matched_keywords: List[str] = Field(default_factory=list, description="匹配的关键词")
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0, description="风险评分")


class BypassTestResult(IntentOutput):
    """LLM越狱/绕过测试结果模型"""
    target_url: str = Field(..., description="目标LLM服务URL")
    test_id: str = Field(..., description="测试ID")
    
    # 测试统计
    total_attacks: int = Field(default=0, description="总越狱尝试数")
    successful_bypasses: int = Field(default=0, description="成功绕过数")
    failed_attacks: int = Field(default=0, description="被拦截数")
    error_attacks: int = Field(default=0, description="执行错误数")
    
    # 绕过率
    bypass_rate: float = Field(default=0.0, ge=0.0, le=100.0, description="绕过率(%)")
    
    # 详细结果
    attack_results: List[AttackResult] = Field(default_factory=list, description="越狱结果列表")
    bypass_patterns: List[Dict[str, Any]] = Field(default_factory=list, description="有效的绕过模式")
    
    # 建议
    recommendations: List[str] = Field(default_factory=list, description="防护建议")
    
    def calculate_bypass_rate(self):
        """计算绕过率"""
        if self.total_attacks > 0:
            self.bypass_rate = (self.successful_bypasses / self.total_attacks) * 100
        return self.bypass_rate


# 兼容别名
PentestResult = BypassTestResult


class GeneratedAttack(BaseModel):
    """生成的攻击模型"""
    id: str = Field(..., description="攻击ID")
    prompt_text: str = Field(..., description="攻击提示词")
    attack_type: str = Field(default="General Attack", description="攻击类型")
    category: str = Field(default="general", description="攻击类别")
    topic: Optional[str] = Field(default=None, description="话题")
    
    # 生成信息
    generation_method: str = Field(default="template", description="生成方法")
    template_id: Optional[str] = Field(default=None, description="使用的模板ID")
    
    # 元数据
    created_at: datetime = Field(default_factory=datetime.now, description="创建时间")
    is_cached: bool = Field(default=False, description="是否来自缓存")


class CacheEntry(BaseModel):
    """缓存条目模型"""
    cache_key: str = Field(..., description="缓存键")
    intent_hash: str = Field(..., description="意图哈希")
    generated_code: str = Field(..., description="生成的代码")
    
    # 缓存元数据
    created_at: datetime = Field(default_factory=datetime.now, description="创建时间")
    last_accessed: datetime = Field(default_factory=datetime.now, description="最后访问时间")
    access_count: int = Field(default=0, description="访问次数")
    
    # 验证状态
    is_validated: bool = Field(default=False, description="是否已验证")
    validation_result: Optional[str] = Field(default=None, description="验证结果")
