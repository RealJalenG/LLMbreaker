import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from jinja2 import Template
from openai import OpenAI
from pydantic import BaseModel
from ..models import CodeEngine, EngineFactory

# 导入 LLMbreaker 设置
try:
    from config.settings import Settings
except ImportError:
    # Fallback for testing isolation
    class Settings:
        deepseek_api_url = "https://api.deepseek.com/v1"
        deepseek_api_key = ""
        deepseek_model_name = "deepseek-chat"
        qwen_api_url = ""
        qwen_api_key = ""
        qwen_model_name = ""
        gemini_api_url = ""
        gemini_api_key = ""
        gemini_model_name = ""

logger = logging.getLogger(__name__)
settings = Settings()

class LLMConfig(BaseModel):
    base_url: str
    api_key: str
    model_name: str
    extra_body: dict | None = None

class MultiModelLLM:
    """支持多模型路由和降级的LLM包装器"""
    
    def __init__(self):
        self._clients: Dict[str, OpenAI] = {}
        self._configs: Dict[str, LLMConfig] = {}
        self._models: Dict[str, str] = {}
        
        self._init_models()
        
        self.input_tokens = 0
        self.output_tokens = 0
        self.total_tokens = 0
        
        self._messages = [{"role": "system", "content": ""}]

    def _init_models(self):
        """初始化所有可用的模型客户端"""
        # 1. DeepSeek (Primary)
        if settings.deepseek_api_key:
            self._add_model("deepseek", 
                            settings.deepseek_api_url.replace("/chat/completions", ""), # OpenAI client adds suffix
                            settings.deepseek_api_key,
                            settings.deepseek_model_name)
            
        # 2. Qwen
        if hasattr(settings, 'qwen_api_key') and settings.qwen_api_key:
            self._add_model("qwen",
                            settings.qwen_api_url,
                            settings.qwen_api_key,
                            settings.qwen_model_name)
                            
        # 3. Gemini
        if hasattr(settings, 'gemini_api_key') and settings.gemini_api_key:
            self._add_model("gemini",
                            settings.gemini_api_url,
                            settings.gemini_api_key,
                            settings.gemini_model_name)

    def _add_model(self, name: str, base_url: str, api_key: str, model_name: str):
        try:
            self._clients[name] = OpenAI(base_url=base_url, api_key=api_key)
            self._configs[name] = LLMConfig(base_url=base_url, api_key=api_key, model_name=model_name)
            self._models[name] = model_name
            logger.info(f"LLM Agent: Registered model '{name}' ({model_name})")
        except Exception as e:
            logger.warning(f"LLM Agent: Failed to register model '{name}': {e}")

    def set_system_prompt(self, system_prompt: str):
        self._messages[0]["content"] = system_prompt

    def _route_model(self, prompt: str) -> str:
        """简单的路由策略"""
        # 如果提示词包含复杂的推理关键词，优先使用更强的模型（如果有）
        if "analyze" in prompt.lower() or "reason" in prompt.lower():
            if "gemini" in self._clients:
                return "gemini"
            if "qwen" in self._clients:
                return "qwen"
        
        # 默认使用 DeepSeek
        if "deepseek" in self._clients:
            return "deepseek"
        
        # Fallback to any available
        if self._clients:
            return list(self._clients.keys())[0]
            
        raise RuntimeError("No LLM models available. Please check config/settings.py")

    def chat(self, user_prompt: str | List[str]) -> str:
        if isinstance(user_prompt, str):
            prompts = [user_prompt]
        else:
            prompts = user_prompt

        for prompt in prompts:
            self._messages.append({"role": "user", "content": prompt})

        # Select model
        model_key = self._route_model(prompts[-1])
        client = self._clients[model_key]
        model_name = self._models[model_key]
        
        logger.info(f"LLM Agent: Routing request to '{model_key}' ({model_name})")

        try:
            completion = client.chat.completions.create(
                model=model_name,
                messages=self._messages,
                stream=False
            )
            
            if not completion.choices:
                raise Exception(f"No Choices returned from LLM {model_key}")
                
            response = completion.choices[0].message.content
            self._messages.append({"role": "assistant", "content": response})
            
            # Update tokens
            if completion.usage:
                self.input_tokens += completion.usage.prompt_tokens
                self.output_tokens += completion.usage.completion_tokens
                self.total_tokens += completion.usage.total_tokens
                
            return response
            
        except Exception as e:
            logger.error(f"LLM Agent: Request to '{model_key}' failed: {e}")
            # Try fallback logic here if needed
            raise e

class LLMEngineFactory(EngineFactory):
    def create(self) -> CodeEngine:
        return LLMEngine()

class LLMEngine(CodeEngine):
    def __init__(self):
        self._llm = MultiModelLLM()
        self._custom_template_path = None
        self._custom_template_content = None

    def set_custom_template_path(self, template_path: str):
        """Set a custom path for the instruction template"""
        self._custom_template_path = Path(template_path)

    def set_custom_template_content(self, template_content: str):
        """Set custom content for the instruction template"""
        self._custom_template_content = template_content

    def configure(self, intent_ir: str, runtime_context: str):
        instruction = None
        
        # Try custom template content first
        if self._custom_template_content:
            try:
                instruction_template = Template(self._custom_template_content)
                instruction = instruction_template.render(
                    intent_ir=intent_ir, runtime_context=runtime_context)
                logger.info("Using custom instruction template content")
            except Exception as e:
                logger.error(f"Failed to render custom template content: {e}")
        
        # Try custom template path
        elif self._custom_template_path:
            try:
                instruction_template = Template(self._custom_template_path.read_text())
                instruction = instruction_template.render(
                    intent_ir=intent_ir, runtime_context=runtime_context)
                logger.info(f"Using custom instruction template from: {self._custom_template_path}")
            except Exception as e:
                logger.error(f"Failed to read custom template: {e}")
        
        # Fallback to default template
        if not instruction:
            instruction_template_path = Path(__file__).parent.parent / "prompts" / "llm_instruction.md"
            # If template doesn't exist (e.g. not copied yet), use a basic string or fail
            if instruction_template_path.exists():
                instruction_template = Template(instruction_template_path.read_text())
                instruction = instruction_template.render(
                    intent_ir=intent_ir, runtime_context=runtime_context)
                logger.info("Using default instruction template")
            else:
                logger.warning("Agent prompt template not found, using raw context.")
                instruction = f"Intent:\n{intent_ir}\nContext:\n{runtime_context}"
        
        self._llm.set_system_prompt(instruction)

    def request(self, prompt: str) -> str:
        res = self._llm.chat(prompt)
        return res
    
    @property
    def input_tokens(self) -> int:
        return self._llm.input_tokens
    
    @property
    def output_tokens(self) -> int:
        return self._llm.output_tokens
    
    @property
    def total_tokens(self) -> int:
        return self._llm.total_tokens
