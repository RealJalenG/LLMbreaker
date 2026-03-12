#!/usr/bin/env python3
"""
LLMbreaker - 自动化越狱测试工具

专注于：
- LLM Prompt越狱攻击
- 安全机制绕过检测
- 越狱效果评估

核心能力:
1. 静态样本攻击 - 使用预定义的越狱样本库
2. 动态生成攻击 - 调用AI根据话题动态生成越狱prompt
3. 意图驱动模式 - 七要素意图模型智能生成
4. P-E-R认知循环 - Planner-Executor-Reflector智能架构

使用示例:
    # 静态样本攻击
    python main.py --static-attacks --static-sample-count 50
    
    # 动态生成攻击（根据话题生成越狱prompt）
    python main.py --dynamic-attack "旅游安全" -n 10
    
    # 意图驱动模式
    python main.py --intent-mode --topic "敏感信息" -n 10
    
    # P-E-R认知循环模式
    python main.py --per-mode --goal "全面越狱测试" --pattern jailbreak
"""
import argparse
import logging
import sys
import os
from config.settings import Settings
from core.static_sample_manager import static_sample_manager
from custom_attack import (
    run_attack_test,
    fetch_attack_phrases_from_db,
    fetch_translated_attack_phrases
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('attack_test.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)


def parse_arguments():
    """
    解析命令行参数
    """
    parser = argparse.ArgumentParser(
        description='LLMbreaker - 自动化越狱测试工具 (IntentLang融合版)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
    # 静态样本攻击 - 使用预定义越狱样本库
    python main.py --static-attacks --static-sample-count 50 --max-workers 5
    
    # 动态生成攻击 - 根据话题AI生成越狱prompt
    python main.py --dynamic-attack "旅游安全" -n 10
    
    # 意图驱动模式 - 智能生成并执行越狱攻击
    python main.py --intent-mode --topic "敏感信息" -n 10
    
    # P-E-R认知循环模式 - 完整越狱测试
    python main.py --per-mode --goal "全面越狱测试" --pattern jailbreak
    
    # 显示缓存统计
    python main.py --cache-stats
        """
    )
    
    # 主功能模式（必选其一）
    main_group = parser.add_mutually_exclusive_group()
    main_group.add_argument('--full-cycle', '-f', action='store_true', help='运行完整流程：生成攻击 → 执行攻击 → 优化 → 再次执行')
    main_group.add_argument('--generate', '-g', action='store_true', help='仅生成攻击payload')
    main_group.add_argument('--execute', '-e', action='store_true', help='仅执行攻击测试')
    main_group.add_argument('--static-attacks', '-s', action='store_true', help='执行静态样本攻击测试')
    main_group.add_argument('--initialize-static', action='store_true', help='初始化静态攻击样本到数据库')
    main_group.add_argument('--optimize', '-o', action='store_true', help='仅优化失败的攻击prompt')
    main_group.add_argument('--dynamic-attack', '-d', type=str, metavar='TOPIC', help='动态生成payload攻击：根据指定话题生成攻击prompt并执行攻击')
    
    # ===== IntentLang 融合模式 =====
    main_group.add_argument('--intent-mode', '-i', action='store_true', 
        help='意图驱动模式：使用七要素意图模型进行智能攻击生成和执行')
    main_group.add_argument('--per-mode', '-p', action='store_true',
        help='P-E-R认知循环模式：Planner-Executor-Reflector智能架构')
    main_group.add_argument('--cache-stats', action='store_true',
        help='显示意图缓存统计信息')
    main_group.add_argument('--clear-cache', action='store_true',
        help='清空意图缓存')
    main_group.add_argument('--multi-round', '-m', type=str, metavar='TOPIC',
        help='智能多轮对话攻击：固定会话+AI反思+自动诱导')
    
    # IntentLang 相关参数
    parser.add_argument('--topic', type=str, help='意图驱动模式的话题（用于生成越狱prompt）')
    parser.add_argument('--goal', type=str, help='P-E-R模式的目标描述')
    parser.add_argument('--pattern', type=str, default='jailbreak',
        choices=['jailbreak', 'bypass_detection', 'comprehensive', 'dynamic'],
        help='攻击模式：jailbreak(越狱), bypass_detection(绕过检测), comprehensive(全面), dynamic(动态)')
    parser.add_argument('--max-iterations', type=int, default=3, help='P-E-R循环最大迭代次数')
    parser.add_argument('--no-cache', action='store_true', help='禁用意图缓存')
    parser.add_argument('--no-reflection', action='store_true', help='禁用反思学习')
    
    # 智能多轮攻击参数
    parser.add_argument('--max-rounds', type=int, default=10, help='多轮攻击最大轮次，默认10')
    parser.add_argument('--use-induction', action='store_true', default=True, help='启用诱导策略（默认启用）')
    parser.add_argument('--no-induction', action='store_true', help='禁用诱导策略')
    
    # 攻击生成参数
    parser.add_argument('--num-attacks', '-n', type=int, default=10, help='每个类别的生成数量，默认10')
    parser.add_argument('--model', type=str, default='deepseek', help='使用的AI模型，默认deepseek')
    parser.add_argument('--categories', type=str, nargs='+', help='攻击类别列表，默认所有OWASP类型')
    
    # 静态样本攻击参数
    parser.add_argument('--static-sample-count', type=int, default=50, help='静态样本攻击数量，默认50')
    parser.add_argument('--static-sample-type', type=str, help='静态样本类型过滤，可选值：regular, content_security')
    
    # 攻击执行参数
    parser.add_argument('--source', type=str, default='yaml_templates', help='攻击payload来源，默认yaml_templates')
    parser.add_argument('--attack-type', type=str, help='攻击类型筛选')
    parser.add_argument('--language', type=str, help='语言筛选（仅对翻译语料有效）')
    parser.add_argument('--limit', type=int, help='攻击测试数量限制')
    parser.add_argument('--target-url', type=str, help='目标LLM服务URL')
    parser.add_argument('--qps-limit', type=int, help='每秒请求数限制')
    parser.add_argument('--interval', type=float, default=1.5, help='请求间隔时间(秒)，默认1.5')
    parser.add_argument('--max-workers', type=int, default=5, help='最大线程数，默认5')
    
    # 配置化参数
    parser.add_argument('--config-file', type=str, help='配置文件路径')
    parser.add_argument('--request-template', type=str, help='请求体模板文件路径')
    parser.add_argument('--injection-rules', type=str, help='注入规则文件路径')
    parser.add_argument('--custom-headers', type=str, help='自定义请求头，格式：Key1=Value1,Key2=Value2')
    
    # 优化参数
    parser.add_argument('--num-optimize', type=int, default=10, help='优化的prompt数量，默认10')
    parser.add_argument('--optimize-interval', type=float, default=3, help='优化间隔时间(秒)，默认3')
    
    # 日志参数
    parser.add_argument('--log-level', type=str, default='INFO', help='日志级别，默认INFO')
    
    return parser.parse_args()


def initialize_static_samples(args):
    """
    初始化静态攻击样本到数据库
    """
    logger.info("开始初始化静态攻击样本...")
    
    try:
        static_sample_manager.initialize_static_samples()
        logger.info("静态攻击样本初始化完成")
        return True
    except Exception as e:
        logger.error(f"静态攻击样本初始化失败: {str(e)}")
        return False


def run_static_attacks(args, settings):
    """
    执行静态样本攻击测试
    """
    logger.info("开始执行静态样本攻击测试...")
    
    try:
        from core.config_manager import ConfigManager, load_request_template
        
        # 从静态样本库获取样本
        samples = static_sample_manager.get_random_samples(
            count=args.static_sample_count,
            sample_type=args.static_sample_type
        )
        
        if not samples:
            logger.error("未获取到静态攻击样本")
            return False
        
        logger.info(f"成功获取 {len(samples)} 个静态攻击样本")
        
        # 解析自定义请求头
        custom_headers = {}
        if args.custom_headers:
            for header in args.custom_headers.split(','):
                if '=' in header:
                    key, value = header.split('=', 1)
                    custom_headers[key.strip()] = value.strip()
        
        # 准备配置字典
        config_dict = {
            'target_url': args.target_url or settings.TARGET_URL,
            'qps_limit': args.qps_limit or settings.QPS_LIMIT,
            'user_agents': settings.USER_AGENTS,
            'xff_ips': settings.XFF_IPS,
            'request_template': settings.DEFAULT_REQUEST_TEMPLATE,
            'injection_rules': settings.DEFAULT_INJECTION_RULES,
            'custom_headers': custom_headers
        }
        
        # 创建配置管理器
        config_manager = ConfigManager(config_file=args.config_file, config_dict=config_dict)
        
        # 加载请求体模板文件（如果指定）
        if args.request_template:
            template = load_request_template(args.request_template)
            if template:
                config_manager.update_config({'request_template': template})
        
        # 加载注入规则文件（如果指定）
        if args.injection_rules:
            from core.config_manager import load_request_template as load_injection_rules
            injection_rules = load_injection_rules(args.injection_rules)
            if injection_rules:
                config_manager.update_config({'injection_rules': injection_rules})
        
        # 获取完整配置
        config = config_manager.get_full_config()
        
        # 执行攻击测试
        results = run_attack_test(
            config=config,
            attack_phrases=samples,
            source_type='static',
            max_workers=args.max_workers
        )
        
        logger.info(f"静态样本攻击测试完成，共执行 {len(results)} 条攻击")
        return True
    except Exception as e:
        logger.error(f"静态样本攻击测试失败: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


def generate_attacks(args, settings):
    """
    生成攻击payload
    """
    logger.info("开始生成攻击payload...")
    
    try:
        from core.attack_generator import create_attack_generator
        
        # 创建攻击生成器
        attack_generator = create_attack_generator()
        
        # 生成攻击提示词
        if args.categories:
            # 根据指定类别生成
            all_prompts = []
            for category in args.categories:
                prompts = attack_generator.generate_attack_prompts(
                    topic=category, 
                    count=args.num_attacks
                )
                all_prompts.extend(prompts)
        else:
            # 默认生成一些常见话题的攻击提示词
            common_topics = ["Python", "SQL", "网络安全", "人工智能", "区块链"]
            all_prompts = []
            for topic in common_topics:
                prompts = attack_generator.generate_attack_prompts(
                    topic=topic, 
                    count=args.num_attacks // len(common_topics)
                )
                all_prompts.extend(prompts)
        
        logger.info(f"成功生成 {len(all_prompts)} 个攻击提示词")
        
        # 保存生成的攻击提示词到文件
        output_file = "generated_attacks.txt"
        with open(output_file, 'w', encoding='utf-8') as f:
            for prompt in all_prompts:
                f.write(f"{prompt}\n\n")
        
        logger.info(f"攻击提示词已保存到 {output_file}")
        return True
    except ImportError:
        logger.error("攻击生成模块未找到，请确保core.attack_generator模块存在")
        return False
    except Exception as e:
        logger.error(f"生成攻击payload失败: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

def run_dynamic_attack(args, settings):
    """
    运行动态生成payload攻击
    
    动态生成payload攻击定义：系统接收用户指定的话题，自动生成针对该话题的相关越狱提示词，用于攻击大语言模型
    """
    logger.info(f"开始动态生成payload攻击，话题: {args.dynamic_attack}")
    
    try:
        from core.attack_generator import create_attack_generator
        from core.config_manager import ConfigManager
        
        # 创建攻击生成器
        attack_generator = create_attack_generator()
        
        # 生成攻击提示词信息
        attack_info_list = attack_generator.generate_attack_info(
            topic=args.dynamic_attack, 
            count=args.num_attacks, 
            category="general"
        )
        
        logger.info(f"成功生成 {len(attack_info_list)} 个针对 '{args.dynamic_attack}' 的攻击提示词")
        
        # 转换为run_attack_test需要的格式
        attack_phrases = []
        for attack_info in attack_info_list:
            attack_phrases.append({
                'prompt_text': attack_info['prompt_text'],
                'attack_type': attack_info['attack_type'],
                'id': attack_info['id'],
                'scenario': f"Dynamic attack for topic: {args.dynamic_attack}"
            })
        
        # 准备配置字典
        config_dict = {
            'target_url': settings.TARGET_URL,
            'qps_limit': settings.QPS_LIMIT,
            'user_agents': settings.USER_AGENTS,
            'xff_ips': settings.XFF_IPS,
            'request_template': settings.DEFAULT_REQUEST_TEMPLATE,
            'injection_rules': settings.DEFAULT_INJECTION_RULES,
            'custom_headers': {}
        }
        
        # 创建配置管理器
        config_manager = ConfigManager(config_dict=config_dict)
        
        # 获取完整配置
        config = config_manager.get_full_config()
        
        # 执行攻击测试
        results = run_attack_test(
            config=config,
            attack_phrases=attack_phrases,
            source_type='dynamic',
            max_workers=args.max_workers
        )
        
        logger.info(f"动态生成payload攻击完成，共执行 {len(results)} 条攻击")
        return True
    except ImportError as e:
        logger.error(f"导入模块失败: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"动态生成payload攻击失败: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


def run_optimize(args, settings):
    """
    运行AI反思优化功能
    分析失败的攻击，使用策略库优化prompt后重新执行
    """
    logger.info("=== 启动AI反思优化功能 ===")
    
    try:
        from core.prompt_optimizer import PromptOptimizer, run_optimization
        from core.config_manager import ConfigManager
        
        # 准备配置
        config_dict = {
            'target_url': settings.TARGET_URL,
            'qps_limit': settings.QPS_LIMIT,
            'user_agents': settings.USER_AGENTS,
            'xff_ips': settings.XFF_IPS,
            'request_template': settings.DEFAULT_REQUEST_TEMPLATE,
            'injection_rules': settings.DEFAULT_INJECTION_RULES,
            'db_config': {
                'host': 'localhost',
                'user': 'root',
                'password': settings.DB_PASSWORD if hasattr(settings, 'DB_PASSWORD') else '',
                'database': os.getenv('DB_NAME', 'llmbreaker')
            }
        }
        
        # 创建配置管理器
        config_manager = ConfigManager(config_dict=config_dict)
        config = config_manager.get_full_config()
        
        # 运行优化
        result = run_optimization(
            config=config,
            num_optimize=args.num_optimize,
            execute_optimized=True  # 执行优化后的攻击
        )
        
        # 输出结果
        logger.info(f"=== 优化结果 ===")
        logger.info(f"状态: {result.get('status')}")
        logger.info(f"优化数量: {result.get('optimized_count', 0)}")
        
        if result.get('executed_count'):
            logger.info(f"执行数量: {result.get('executed_count')}")
            logger.info(f"成功数量: {result.get('success_count', 0)}")
            success_rate = (result.get('success_count', 0) / result.get('executed_count', 1)) * 100
            logger.info(f"成功率: {success_rate:.2f}%")
        
        if result.get('optimizer_stats'):
            stats = result['optimizer_stats']
            logger.info(f"策略使用统计: {stats.get('strategy_usage', {})}")
        
        return True
        
    except Exception as e:
        logger.error(f"优化功能执行失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def execute_attacks(args, settings):
    """
    执行攻击测试
    """
    logger.info("开始执行攻击测试...")
    
    try:
        from core.config_manager import ConfigManager, load_request_template
        
        # 根据来源获取攻击语料
        if args.source == 'db':
            filters = {}
            if args.attack_type:
                filters['attack_type'] = args.attack_type
            
            attack_phrases = fetch_attack_phrases_from_db(settings.DB_CONFIG, filters)
        elif args.source == 'translated':
            filters = {}
            if args.language:
                filters['target_language'] = args.language
            
            attack_phrases = fetch_translated_attack_phrases(settings.DB_CONFIG, filters)
        elif args.source == 'yaml_templates':
            # 从YAML模板文件直接获取样本，不经过数据库
            from core.yaml_attack_generator import YAMLAttackGenerator
            
            # 创建YAML攻击生成器实例
            yaml_generator = YAMLAttackGenerator()
            # 生成指定数量的攻击
            attack_infos = yaml_generator.generate_multiple_attacks(
                count=args.limit or 50,
                use_random=True
            )
            
            # 转换为run_attack_test需要的格式
            attack_phrases = []
            for attack_info in attack_infos:
                attack_phrases.append({
                    'prompt_text': attack_info['prompt_text'],
                    'attack_type': attack_info['attack_type'],
                    'id': None,  # YAML模板生成的攻击没有数据库ID
                    'scenario': attack_info['description']
                })
        else:
            logger.error(f"不支持的攻击来源: {args.source}")
            return False
        
        # 应用限制
        if args.limit and len(attack_phrases) > args.limit:
            attack_phrases = attack_phrases[:args.limit]
        
        logger.info(f"成功获取 {len(attack_phrases)} 条攻击语料")
        
        # 解析自定义请求头
        custom_headers = {}
        if args.custom_headers:
            for header in args.custom_headers.split(','):
                if '=' in header:
                    key, value = header.split('=', 1)
                    custom_headers[key.strip()] = value.strip()
        
        # 准备配置字典
        config_dict = {
            'target_url': args.target_url or settings.TARGET_URL,
            'qps_limit': args.qps_limit or settings.QPS_LIMIT,
            'user_agents': settings.USER_AGENTS,
            'xff_ips': settings.XFF_IPS,
            'request_template': settings.DEFAULT_REQUEST_TEMPLATE,
            'injection_rules': settings.DEFAULT_INJECTION_RULES,
            'custom_headers': custom_headers
        }
        
        # 创建配置管理器
        config_manager = ConfigManager(config_file=args.config_file, config_dict=config_dict)
        
        # 加载请求体模板文件（如果指定）
        if args.request_template:
            template = load_request_template(args.request_template)
            if template:
                config_manager.update_config({'request_template': template})
        
        # 加载注入规则文件（如果指定）
        if args.injection_rules:
            injection_rules = load_request_template(args.injection_rules)
            if injection_rules:
                config_manager.update_config({'injection_rules': injection_rules})
        
        # 获取完整配置
        config = config_manager.get_full_config()
        
        # 执行攻击测试
        results = run_attack_test(
            config=config,
            attack_phrases=attack_phrases,
            source_type=args.source,
            max_workers=args.max_workers
        )
        
        logger.info(f"攻击测试完成，共执行 {len(results)} 条攻击")
        return True
    except Exception as e:
        logger.error(f"攻击测试执行失败: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


def run_intent_mode(args, settings):
    """
    运行意图驱动模式
    使用IntentLang七要素意图模型进行智能越狱攻击生成和执行
    """
    logger.info("=== 启动意图驱动模式（LLM越狱测试）===")
    
    try:
        from core.intent_attack_generator import IntentDrivenAttackGenerator
        from core.intent_attack_executor import IntentDrivenAttackExecutor
        from intent import get_intent_cache
        
        # 获取缓存
        cache = get_intent_cache()
        
        # 创建生成器
        generator = IntentDrivenAttackGenerator(
            cache=cache,
            enable_cache=not args.no_cache
        )
        
        # 获取话题（用于生成越狱prompt）
        topic = args.topic or "旅游安全"
        # 越狱测试默认使用jailbreak类别
        category = "jailbreak"
        
        logger.info(f"话题: {topic}, 类别: {category}, 数量: {args.num_attacks}")
        
        # 生成攻击
        attacks = generator.generate(
            topic=topic,
            count=args.num_attacks,
            category=category,
            use_cache=not args.no_cache
        )
        
        logger.info(f"生成 {len(attacks)} 个攻击")
        
        # 显示生成统计
        gen_stats = generator.get_stats()
        logger.info(f"生成统计: {gen_stats}")
        
        # 创建执行器
        config = {
            'target_url': args.target_url or settings.TARGET_URL,
            'qps_limit': args.qps_limit or settings.QPS_LIMIT,
            'user_agents': settings.USER_AGENTS,
            'xff_ips': settings.XFF_IPS,
            'request_template': settings.DEFAULT_REQUEST_TEMPLATE,
            'injection_rules': settings.DEFAULT_INJECTION_RULES
        }
        
        executor = IntentDrivenAttackExecutor(config=config)
        
        # 转换为执行格式
        attack_list = [
            {
                'prompt_text': a.prompt_text,
                'attack_type': a.attack_type
            }
            for a in attacks
        ]
        
        # 执行越狱测试
        result = executor.run_bypass_test(attack_list, config)
        
        # 输出结果
        logger.info("=== 越狱测试结果 ===")
        logger.info(f"测试ID: {result.test_id}")
        logger.info(f"总攻击数: {result.total_attacks}")
        logger.info(f"成功绕过: {result.successful_bypasses}")
        logger.info(f"绕过率: {result.bypass_rate:.2f}%")
        logger.info(f"执行时间: {result.execution_time_ms:.2f}ms")
        
        if result.bypass_patterns:
            logger.warning("=== 有效的绕过模式 ===")
            for pattern in result.bypass_patterns:
                logger.warning(f"  - {pattern['type']}: 有效性={pattern['effectiveness']} ({pattern['success_count']}次成功)")
        
        if result.recommendations:
            logger.info("=== 安全建议 ===")
            for rec in result.recommendations:
                logger.info(f"  - {rec}")
        
        # 显示缓存统计
        cache_stats = cache.get_stats()
        logger.info(f"缓存统计: 命中率={cache_stats['hit_rate']}, 条目数={cache_stats['memory_entries']}")
        
        return True
        
    except Exception as e:
        logger.error(f"意图驱动模式执行失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def run_per_mode(args, settings):
    """
    运行P-E-R认知循环模式
    Planner-Executor-Reflector智能架构
    专注于LLM越狱攻击的规划、执行和反思优化
    """
    logger.info("=== 启动P-E-R认知循环模式（LLM越狱测试）===")
    
    try:
        from intent import PERLoop, get_intent_cache
        
        # 获取目标
        goal = args.goal or "执行全面的LLM越狱/绕过测试"
        pattern = args.pattern
        
        logger.info(f"目标: {goal}")
        logger.info(f"攻击模式: {pattern}")
        logger.info(f"最大迭代次数: {args.max_iterations}")
        
        # 准备上下文
        context = {
            'target_url': args.target_url or settings.TARGET_URL,
            'topic': args.dynamic_attack or "安全测试",
            'count': args.num_attacks,
            'config': {
                'target_url': args.target_url or settings.TARGET_URL,
                'qps_limit': args.qps_limit or settings.QPS_LIMIT,
                'user_agents': settings.USER_AGENTS,
                'xff_ips': settings.XFF_IPS,
                'request_template': settings.DEFAULT_REQUEST_TEMPLATE,
                'injection_rules': settings.DEFAULT_INJECTION_RULES
            }
        }
        
        # 创建P-E-R循环
        per_loop = PERLoop(max_iterations=args.max_iterations)
        
        # 运行循环
        result = per_loop.run(goal, context, pattern)
        
        # 输出结果
        logger.info("=== P-E-R循环结果 ===")
        logger.info(f"目标: {result['goal']}")
        logger.info(f"迭代次数: {result['iterations']}")
        
        # 输出反思洞察
        if result.get('reflections'):
            logger.info("=== 反思洞察 ===")
            for reflection in result['reflections']:
                for insight in reflection.get('insights', []):
                    logger.info(f"  - {insight}")
        
        # 输出学习到的模式
        learned = result.get('learned_patterns', {})
        if learned.get('successful_patterns'):
            logger.info(f"成功模式: {len(learned['successful_patterns'])} 个")
        if learned.get('failed_patterns'):
            logger.info(f"失败模式: {len(learned['failed_patterns'])} 个")
        
        # 显示缓存统计
        cache = get_intent_cache()
        cache_stats = cache.get_stats()
        logger.info(f"缓存统计: 命中率={cache_stats['hit_rate']}, 条目数={cache_stats['memory_entries']}")
        
        return True
        
    except Exception as e:
        logger.error(f"P-E-R模式执行失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def show_cache_stats():
    """显示缓存统计"""
    try:
        from intent import get_intent_cache
        
        cache = get_intent_cache()
        stats = cache.get_stats()
        
        print("\n=== 意图缓存统计 ===")
        print(f"内存条目数: {stats['memory_entries']}/{stats['max_memory_entries']}")
        print(f"命中次数: {stats['hits']}")
        print(f"未命中次数: {stats['misses']}")
        print(f"命中率: {stats['hit_rate']}")
        print(f"淘汰次数: {stats['evictions']}")
        print(f"磁盘读取: {stats['disk_reads']}")
        print(f"磁盘写入: {stats['disk_writes']}")
        
        return True
    except Exception as e:
        logger.error(f"获取缓存统计失败: {e}")
        return False


def clear_cache():
    """清空缓存"""
    try:
        from intent import get_intent_cache
        
        cache = get_intent_cache()
        cache.clear()
        
        print("意图缓存已清空")
        return True
    except Exception as e:
        logger.error(f"清空缓存失败: {e}")
        return False


def run_multi_round_attack(args, settings):
    """
    运行智能多轮对话攻击
    特性：
    1. 固定pid/ppid确保会话一致性
    2. AI反思分析拒绝原因
    3. 智能Payload动态生成
    4. 自动化诱导策略
    """
    logger.info("=== 启动智能多轮对话攻击 ===")
    
    try:
        from core.intelligent_multi_round import run_intelligent_multi_round_attack
        from core.config_manager import ConfigManager
        
        # 准备配置
        config_dict = {
            'target_url': args.target_url or settings.TARGET_URL,
            'qps_limit': args.qps_limit or settings.QPS_LIMIT,
            'user_agents': settings.USER_AGENTS,
            'xff_ips': settings.XFF_IPS,
            'request_template': settings.DEFAULT_REQUEST_TEMPLATE,
            'injection_rules': settings.DEFAULT_INJECTION_RULES,
            'interval': args.interval or 1.0
        }
        
        # 创建配置管理器
        config_manager = ConfigManager(config_dict=config_dict)
        config = config_manager.get_full_config()
        
        # 运行智能多轮攻击
        result = run_intelligent_multi_round_attack(
            config=config,
            topic=args.multi_round,
            max_rounds=args.max_rounds,
            use_ai_reflection=not args.no_reflection,
            use_induction=not args.no_induction
        )
        
        # 输出结果
        logger.info("\n" + "=" * 60)
        logger.info("智能多轮攻击结果")
        logger.info("=" * 60)
        logger.info(f"会话ID: {result['session_info']['session_id']}")
        logger.info(f"固定pid: {result['session_info']['client_id']}")
        logger.info(f"固定ppid: {result['session_info']['user_id']}")
        logger.info(f"执行轮次: {result['total_rounds']}/{result['max_rounds']}")
        logger.info(f"攻击结果: {'✅ 成功绕过' if result['attack_success'] else '❌ 未能绕过'}")
        
        if result['attack_success']:
            logger.info(f"成功轮次: 第{result['success_round']}轮")
            logger.info(f"成功原因: {result['success_reason']}")
        
        if result.get('reflections'):
            logger.info(f"\n反思记录 ({len(result['reflections'])}条):")
            for ref in result['reflections'][-3:]:  # 显示最近3条
                logger.info(f"  轮次{ref['round']}: {ref['analysis']['pattern']} → {ref['analysis']['strategy']}")
        
        return True
        
    except Exception as e:
        logger.error(f"智能多轮攻击失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """
    主函数
    """
    # 解析命令行参数
    args = parse_arguments()
    
    # 配置日志级别
    logging.getLogger().setLevel(getattr(logging, args.log_level.upper()))
    
    # 加载配置
    settings = Settings()
    
    logger.info("LLMbreaker 启动 (IntentLang融合版)")
    
    try:
        # ===== IntentLang 融合模式 =====
        if args.intent_mode:
            # 意图驱动模式
            success = run_intent_mode(args, settings)
        elif args.per_mode:
            # P-E-R认知循环模式
            success = run_per_mode(args, settings)
        elif args.cache_stats:
            # 显示缓存统计
            success = show_cache_stats()
        elif args.clear_cache:
            # 清空缓存
            success = clear_cache()
        elif args.multi_round:
            # 智能多轮对话攻击
            success = run_multi_round_attack(args, settings)
        # ===== 传统模式 =====
        elif args.initialize_static:
            # 初始化静态样本
            success = initialize_static_samples(args)
        elif args.static_attacks:
            # 执行静态样本攻击
            success = run_static_attacks(args, settings)
        elif args.generate:
            # 仅生成攻击payload
            success = generate_attacks(args, settings)
        elif args.execute:
            # 仅执行攻击测试
            success = execute_attacks(args, settings)
        elif args.optimize:
            # 仅优化失败的攻击prompt（AI反思功能）
            success = run_optimize(args, settings)
        elif args.full_cycle:
            # 运行完整流程
            logger.info("完整流程功能暂未实现")
            success = True
        elif args.dynamic_attack:
            # 执行动态生成payload攻击 - 使用原有AI生成逻辑
            success = run_dynamic_attack(args, settings)
        else:
            # 默认执行静态样本攻击
            logger.info("未指定功能，默认执行静态样本攻击")
            success = run_static_attacks(args, settings)
        
        if success:
            logger.info("LLMbreaker 执行完成")
            sys.exit(0)
        else:
            logger.error("LLMbreaker 执行失败")
            sys.exit(1)
    except KeyboardInterrupt:
        logger.info("LLMbreaker 被用户中断")
        sys.exit(0)
    except Exception as e:
        logger.error(f"LLMbreaker 执行过程中发生错误: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
