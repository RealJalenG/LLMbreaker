#!/usr/bin/env python3
"""
LLMbreaker - 简化命令行入口

设计理念：
1. 极简参数 - 只保留必要参数，复杂配置用配置文件
2. 子命令模式 - attack/manage/analyze 三大功能分区
3. 智能默认 - 自动选择最佳策略

使用示例：
    # 快速攻击（自动策略）
    python llmbreaker.py attack "越狱测试"
    
    # 指定策略
    python llmbreaker.py attack "敏感话题" -s multi-round
    
    # 批量攻击
    python llmbreaker.py attack "安全测试" -n 50
    
    # 使用配置文件
    python llmbreaker.py attack --config attack.yaml
    
    # 管理样本库
    python llmbreaker.py manage --list
    python llmbreaker.py manage --import samples.xlsx
    
    # 分析结果
    python llmbreaker.py analyze --report
    python llmbreaker.py analyze --cache-stats
"""

import argparse
import logging
import sys
import os

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.dispatcher import AttackDispatcher, AttackConfig, AttackStrategy, AttackResult


def setup_logging(level: str = "INFO"):
    """配置日志"""
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )


def cmd_attack(args):
    """
    攻击命令处理
    """
    logger = logging.getLogger(__name__)
    
    # 构建配置
    if args.config:
        config = AttackConfig.from_yaml(args.config)
        # 命令行参数覆盖配置文件
        if args.topic:
            config.topic = args.topic
    else:
        config = AttackConfig()
        if args.topic:
            config.topic = args.topic
    
    # 应用命令行参数
    if args.strategy:
        config.strategy = AttackStrategy(args.strategy)
    if args.count:
        config.count = args.count
    if args.rounds:
        config.max_rounds = args.rounds
    if args.target:
        config.target_url = args.target
    if args.no_cache:
        config.enable_cache = False
    if args.no_reflect:
        config.enable_reflection = False
    
    # 验证
    if not config.topic:
        logger.error("必须指定攻击话题，使用 attack <话题> 或 attack --config <配置文件>")
        return False
    
    # 执行攻击
    dispatcher = AttackDispatcher(config)
    result = dispatcher.run()
    
    return result.success


def cmd_manage(args):
    """
    管理命令处理
    """
    logger = logging.getLogger(__name__)
    
    if args.list:
        # 列出样本
        from core.static_sample_manager import static_sample_manager
        samples = static_sample_manager.get_random_samples(count=50)
        
        print("\n" + "=" * 60)
        print("静态样本库")
        print("=" * 60)
        print(f"共 {len(samples)} 个样本\n")
        
        for i, s in enumerate(samples[:10], 1):
            print(f"{i}. [{s.get('type', 'unknown')}] {s.get('payload', '')[:50]}...")
        
        if len(samples) > 10:
            print(f"\n... 还有 {len(samples) - 10} 个样本")
        
        return True
    
    elif args.import_file:
        # 导入样本
        filepath = args.import_file
        if not os.path.exists(filepath):
            logger.error(f"文件不存在: {filepath}")
            return False
        
        logger.info(f"导入样本: {filepath}")
        
        if filepath.endswith('.xlsx'):
            from import_xlsx_samples import import_from_xlsx
            import_from_xlsx(filepath)
        elif filepath.endswith('.yaml') or filepath.endswith('.yml'):
            from core.static_sample_manager import static_sample_manager
            static_sample_manager.initialize_from_yaml(filepath)
        else:
            logger.error("不支持的文件格式，请使用 .xlsx 或 .yaml")
            return False
        
        logger.info("导入完成")
        return True
    
    elif args.init:
        # 初始化样本库
        from core.static_sample_manager import static_sample_manager
        static_sample_manager.initialize_from_yaml()
        logger.info("静态样本库初始化完成")
        return True
    
    else:
        logger.info("使用 --list 列出样本, --import 导入样本, --init 初始化样本库")
        return True


def cmd_regression(args):
    """
    回归测试命令处理
    """
    logger = logging.getLogger(__name__)
    
    try:
        from core.regression_test import get_regression_manager
        manager = get_regression_manager()
    except ImportError as e:
        logger.error(f"回归测试模块加载失败: {e}")
        return False
    
    if args.list:
        # 列出测试用例
        cases = manager.list_cases()
        
        print("\n" + "=" * 70)
        print("回归测试用例列表")
        print("=" * 70)
        
        if not cases:
            print("暂无测试用例。运行攻击测试后会自动收集失败样本。")
        else:
            print(f"{'ID':<20} {'拒绝模式':<18} {'变式数':<8} {'成功率':<10} {'最后运行':<20}")
            print("-" * 70)
            for case in cases:
                print(f"{case['id']:<20} {case['rejection_pattern']:<18} "
                      f"{case['variants_count']:<8} {case['success_rate']:.1f}%"
                      f"{'':>6} {case['last_run'] or '从未':>20}")
        
        print("=" * 70)
        return True
    
    elif args.run:
        # 运行回归测试
        print("\n" + "=" * 60)
        print("运行回归测试")
        print("=" * 60)
        
        results = manager.run_regression_test(case_id=args.case_id)
        
        print(f"\n测试结果:")
        print(f"  总用例数: {results['total_cases']}")
        print(f"  通过: {results['passed']}")
        print(f"  失败: {results['failed']}")
        
        if results['details']:
            print("\n详细结果:")
            for detail in results['details']:
                status = "✅ 通过" if detail['passed'] else "❌ 失败"
                print(f"  {detail['case_id']}: {status}")
                print(f"    测试变式: {detail['variants_tested']}")
                if detail['bypassed_variants']:
                    print(f"    成功绕过的变式:")
                    for v in detail['bypassed_variants']:
                        print(f"      - [{v['strategy']}] {v['prompt'][:50]}...")
        
        print("=" * 60)
        return results['passed'] > 0 or results['total_cases'] == 0
    
    elif args.stats:
        # 显示统计
        stats = manager.get_statistics()
        
        print("\n" + "=" * 60)
        print("回归测试统计")
        print("=" * 60)
        print(f"收集的拒绝样本: {stats['total_rejected_samples']}")
        print(f"测试用例数: {stats['total_test_cases']}")
        print(f"总运行次数: {stats['total_runs']}")
        print(f"整体成功率: {stats['overall_success_rate']:.2f}%")
        
        if stats['pattern_statistics']:
            print("\n拒绝模式分布:")
            for pattern, data in stats['pattern_statistics'].items():
                bypass_rate = (data['bypassed'] / data['count'] * 100) if data['count'] > 0 else 0
                print(f"  {pattern}: {data['count']}个样本, 绕过率 {bypass_rate:.1f}%")
        
        if stats['strategy_statistics']:
            print("\n变式策略效果:")
            for strategy, data in stats['strategy_statistics'].items():
                success_rate = (data['success'] / data['used'] * 100) if data['used'] > 0 else 0
                print(f"  {strategy}: 使用{data['used']}次, 成功率 {success_rate:.1f}%")
        
        print("=" * 60)
        return True
    
    elif args.export:
        # 导出报告
        output_path = manager.export_report()
        print(f"\n回归测试报告已导出: {output_path}")
        return True
    
    elif args.generate_variants:
        # 生成变式
        sample_id = args.generate_variants
        if sample_id in manager.rejected_samples:
            sample = manager.rejected_samples[sample_id]
            case = manager.create_test_case(sample)
            
            print(f"\n为样本 {sample_id} 生成的变式攻击:")
            for i, variant in enumerate(case.variant_prompts, 1):
                print(f"\n{i}. [{variant['strategy']}]")
                print(f"   {variant['prompt'][:100]}...")
            
            return True
        else:
            logger.error(f"样本不存在: {sample_id}")
            return False
    
    else:
        logger.info("使用 --list 列出用例, --run 运行测试, --stats 查看统计")
        return True


def cmd_agent(args):
    """
    Agent命令处理
    """
    logger = logging.getLogger(__name__)
    
    try:
        from agent.core import get_agent
        agent = get_agent()
    except ImportError as e:
        logger.error(f"Agent模块加载失败: {e}")
        # Hint for missing dependencies if any
        if "openai" in str(e):
             logger.error("请确保已安装 'openai' 库: pip install openai")
        return False

    if args.interactive:
        print("\n" + "=" * 60)
        print("进入 LLMbreaker Security Agent 交互模式")
        print("输入 'exit' 或 'quit' 退出")
        print("=" * 60)
        
        while True:
            try:
                user_input = input("\nAgent> ").strip()
                if user_input.lower() in ('exit', 'quit'):
                    break
                if not user_input:
                    continue
                
                print("Agent正在思考和规划...")
                result = agent.execute(user_input)
                
                print("\n" + "-" * 40)
                print(f"执行结果: {'✅ 成功' if result.success else '❌ 失败'}")
                print("-" * 40)
                print(f"摘要: {result.summary}")
                if result.key_findings:
                    print("\n关键发现:")
                    for finding in result.key_findings:
                        print(f"  - {finding}")
                if result.recommendations:
                    print("\n建议:")
                    for rec in result.recommendations:
                        print(f"  - {rec}")
                        
            except KeyboardInterrupt:
                print("\n操作已取消")
                break
            except Exception as e:
                logger.error(f"执行出错: {e}")
        return True
        
    elif args.goal:
        print(f"Agent目标: {args.goal}")
        print("Agent正在思考和规划...")
        
        try:
            result = agent.execute(args.goal)
            
            print("\n" + "=" * 60)
            print("Agent执行报告")
            print("=" * 60)
            print(f"状态: {'✅ 成功' if result.success else '❌ 失败'}")
            print(f"摘要: {result.summary}")
            
            if result.key_findings:
                print("\n关键发现:")
                for finding in result.key_findings:
                    print(f"  - {finding}")
                    
            if result.recommendations:
                print("\n建议:")
                for rec in result.recommendations:
                    print(f"  - {rec}")
            
            return result.success
        except Exception as e:
             logger.error(f"Agent执行失败: {e}")
             return False
    else:
        logger.error("请提供测试目标，或使用 --interactive 进入交互模式")
        return False


def cmd_multi_agent(args):
    """
    多Agent协同攻击命令处理
    
    使用三个专业Agent协同工作：
    - Agent1 (DeepSeek): 生成恶意Prompt
    - Agent2 (Qwen): 判断绕过是否成功
    - Agent3 (Gemini): 变形失败样本
    """
    logger = logging.getLogger(__name__)
    
    try:
        from agent.orchestrator import MultiAgentOrchestrator, run_multi_agent_attack
        from agent.extensions.specialized_agents import AttackStrategy
    except ImportError as e:
        logger.error(f"多Agent模块加载失败: {e}")
        logger.error("请确保已安装必要依赖: pip install openai")
        return False
    
    topic = args.topic
    if not topic:
        logger.error("必须指定攻击话题，使用 multi-agent <话题>")
        return False
    
    # 构建配置
    config = {}
    if args.target:
        config['url'] = args.target
    
    # 解析策略
    strategies = None
    if args.strategies:
        strategy_map = {
            'implicit': AttackStrategy.IMPLICIT_INJECTION,
            'roleplay': AttackStrategy.ROLEPLAY,
            'multi-turn': AttackStrategy.MULTI_TURN,
            'encoding': AttackStrategy.ENCODING,
            'low-resource': AttackStrategy.LOW_RESOURCE_LANG,
            'hypothetical': AttackStrategy.HYPOTHETICAL,
            'academic': AttackStrategy.ACADEMIC,
            'nested': AttackStrategy.NESTED
        }
        strategies = [strategy_map.get(s, AttackStrategy.ACADEMIC) for s in args.strategies.split(',')]
    
    print("\n" + "="*60)
    print("🤖 LLMbreaker 多Agent协同攻击模式")
    print("="*60)
    print(f"话题: {topic}")
    print(f"最大尝试次数: {args.max_attempts}")
    print(f"请求间隔: {args.interval}秒")
    print("="*60)
    print("\n初始化Agent系统...")
    
    try:
        orchestrator = MultiAgentOrchestrator(config)
        session = orchestrator.run_collaborative_attack(
            topic=topic,
            max_attempts=args.max_attempts,
            strategies=strategies,
            interval=args.interval
        )
        
        # 输出结果
        result = session.to_dict()
        
        print("\n" + "="*60)
        print("📊 最终结果")
        print("="*60)
        print(f"总尝试次数: {result['total_attempts']}")
        print(f"成功次数: {result['success_count']}")
        print(f"成功率: {result['success_rate']*100:.1f}%")
        
        if result['duration']:
            print(f"总耗时: {result['duration']:.1f}秒")
        
        if result['successful_prompts']:
            print("\n✅ 成功的攻击Prompt:")
            for i, p in enumerate(result['successful_prompts'], 1):
                print(f"  {i}. {p[:80]}...")
        
        print("="*60)
        
        return result['success_count'] > 0
        
    except Exception as e:
        logger.error(f"多Agent攻击执行失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def cmd_analyze(args):
    """
    分析命令处理
    """
    logger = logging.getLogger(__name__)
    
    if args.cache_stats:
        # 显示缓存统计
        from intent import get_intent_cache
        cache = get_intent_cache()
        stats = cache.get_stats()
        
        print("\n" + "=" * 60)
        print("意图缓存统计")
        print("=" * 60)
        print(f"总条目数: {stats.get('total_entries', 0)}")
        print(f"缓存命中: {stats.get('hits', 0)}")
        print(f"缓存未命中: {stats.get('misses', 0)}")
        hit_rate = stats.get('hit_rate', 0)
        try:
            hit_rate_val = float(hit_rate) if hit_rate else 0.0
        except (ValueError, TypeError):
            hit_rate_val = 0.0
        print(f"命中率: {hit_rate_val:.2f}%")
        print("=" * 60)
        
        return True
    
    elif args.clear_cache:
        # 清除缓存
        from intent import get_intent_cache
        cache = get_intent_cache()
        cache.clear()
        logger.info("缓存已清除")
        return True
    
    elif args.report:
        # 生成报告
        from reports.report_generator import ReportGenerator
        
        output_dir = args.output or "reports_output"
        generator = ReportGenerator(output_dir=output_dir)
        
        # 读取最近的测试结果
        csv_path = os.path.join(output_dir, "security_test_results.csv")
        if os.path.exists(csv_path):
            import pandas as pd
            df = pd.read_csv(csv_path)
            
            print("\n" + "=" * 60)
            print("测试报告汇总")
            print("=" * 60)
            print(f"总测试数: {len(df)}")
            if 'bypassed' in df.columns:
                bypassed = df['bypassed'].sum()
                print(f"绕过成功: {bypassed}")
                print(f"绕过率: {bypassed / len(df) * 100:.2f}%")
            print("=" * 60)
            
            return True
        else:
            logger.info("暂无测试报告")
            return True
    
    else:
        logger.info("使用 --cache-stats 查看缓存, --clear-cache 清除缓存, --report 查看报告")
        return True


def main():
    """主入口"""
    parser = argparse.ArgumentParser(
        prog='llmbreaker',
        description='''
LLMbreaker - LLM安全测试工具（简化版）

三大功能模块：
  attack  - 执行攻击测试
  manage  - 管理样本库
  analyze - 分析和报告
''',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
使用示例：
  # 快速攻击
  python llmbreaker.py attack "越狱测试"
  
  # 多轮攻击
  python llmbreaker.py attack "绕过安全限制" -s multi-round
  
  # 批量攻击
  python llmbreaker.py attack "敏感话题" -n 50
  
  # 使用配置文件
  python llmbreaker.py attack --config attack.yaml
  
  # 管理样本
  python llmbreaker.py manage --list
  
  # 查看统计
  python llmbreaker.py analyze --cache-stats
'''
    )
    
    parser.add_argument(
        '--log-level', '-l',
        default='INFO',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        help='日志级别'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='功能命令')
    
    # ==================== attack 子命令 ====================
    attack_parser = subparsers.add_parser(
        'attack',
        help='执行攻击测试',
        description='执行LLM越狱/绕过测试'
    )
    
    attack_parser.add_argument(
        'topic',
        nargs='?',
        help='攻击话题（如：越狱测试、敏感话题绕过）'
    )
    
    attack_parser.add_argument(
        '-s', '--strategy',
        choices=['auto', 'single', 'multi-round', 'static', 'batch'],
        default='auto',
        help='攻击策略（默认: auto 自动选择）'
    )
    
    attack_parser.add_argument(
        '-n', '--count',
        type=int,
        default=10,
        help='攻击数量（默认: 10）'
    )
    
    attack_parser.add_argument(
        '-r', '--rounds',
        type=int,
        default=10,
        help='多轮攻击最大轮次（默认: 10）'
    )
    
    attack_parser.add_argument(
        '-t', '--target',
        help='目标URL'
    )
    
    attack_parser.add_argument(
        '-c', '--config',
        help='配置文件路径'
    )
    
    attack_parser.add_argument(
        '--no-cache',
        action='store_true',
        help='禁用意图缓存'
    )
    
    attack_parser.add_argument(
        '--no-reflect',
        action='store_true',
        help='禁用AI反思'
    )
    
    # ==================== manage 子命令 ====================
    manage_parser = subparsers.add_parser(
        'manage',
        help='管理样本库',
        description='管理静态攻击样本库'
    )
    
    manage_parser.add_argument(
        '--list', '-l',
        action='store_true',
        help='列出样本'
    )
    
    manage_parser.add_argument(
        '--import', '-i',
        dest='import_file',
        help='导入样本文件（支持 .xlsx, .yaml）'
    )
    
    manage_parser.add_argument(
        '--init',
        action='store_true',
        help='初始化样本库'
    )
    
    # ==================== analyze 子命令 ====================
    analyze_parser = subparsers.add_parser(
        'analyze',
        help='分析和报告',
        description='查看缓存统计和测试报告'
    )
    
    analyze_parser.add_argument(
        '--cache-stats',
        action='store_true',
        help='显示意图缓存统计'
    )
    
    analyze_parser.add_argument(
        '--clear-cache',
        action='store_true',
        help='清除意图缓存'
    )
    
    analyze_parser.add_argument(
        '--report',
        action='store_true',
        help='生成测试报告'
    )
    
    analyze_parser.add_argument(
        '-o', '--output',
        help='报告输出目录'
    )
    
    # ==================== regression 子命令 ====================
    regression_parser = subparsers.add_parser(
        'regression',
        help='回归测试',
        description='管理和运行LLM对抗性回归测试'
    )
    
    regression_parser.add_argument(
        '--list', '-l',
        action='store_true',
        help='列出所有回归测试用例'
    )
    
    regression_parser.add_argument(
        '--run', '-r',
        action='store_true',
        help='运行回归测试'
    )
    
    regression_parser.add_argument(
        '--case-id',
        help='指定运行的测试用例ID'
    )
    
    regression_parser.add_argument(
        '--stats',
        action='store_true',
        help='显示回归测试统计'
    )
    
    regression_parser.add_argument(
        '--export',
        action='store_true',
        help='导出回归测试报告'
    )
    
    regression_parser.add_argument(
        '--generate-variants',
        metavar='SAMPLE_ID',
        help='为指定样本生成变式攻击'
    )

    # ==================== agent 子命令 ====================
    agent_parser = subparsers.add_parser(
        'agent',
        help='AI Agent模式',
        description='使用自主AI Agent执行安全测试任务'
    )
    
    agent_parser.add_argument(
        'goal',
        nargs='?',
        help='测试目标描述 (如: "对目标进行全面的越狱测试")'
    )
    
    agent_parser.add_argument(
        '--interactive', '-i',
        action='store_true',
        help='进入交互式Agent模式'
    )
    
    # ==================== multi-agent 子命令 ====================
    multi_agent_parser = subparsers.add_parser(
        'multi-agent',
        help='多Agent协同攻击模式',
        description='''
多Agent协同攻击模式：
  - Agent1 (DeepSeek): 生成恶意Prompt
  - Agent2 (Qwen): 判断绕过是否成功  
  - Agent3 (Gemini): 变形失败样本

示例：
  python llmbreaker.py multi-agent "越狱测试"
  python llmbreaker.py multi-agent "敏感话题" -n 20 --strategies roleplay,encoding
''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    multi_agent_parser.add_argument(
        'topic',
        nargs='?',
        help='攻击话题'
    )
    
    multi_agent_parser.add_argument(
        '-n', '--max-attempts',
        type=int,
        default=10,
        help='最大尝试次数（默认: 10）'
    )
    
    multi_agent_parser.add_argument(
        '-t', '--target',
        help='目标URL'
    )
    
    multi_agent_parser.add_argument(
        '--strategies',
        help='攻击策略列表，逗号分隔 (可选: implicit,roleplay,multi-turn,encoding,low-resource,hypothetical,academic,nested)'
    )
    
    multi_agent_parser.add_argument(
        '--interval',
        type=float,
        default=1.0,
        help='请求间隔秒数（默认: 1.0）'
    )
    
    # 解析参数
    args = parser.parse_args()
    
    # 配置日志
    setup_logging(args.log_level)
    
    # 执行命令
    if args.command == 'attack':
        success = cmd_attack(args)
    elif args.command == 'manage':
        success = cmd_manage(args)
    elif args.command == 'analyze':
        success = cmd_analyze(args)
    elif args.command == 'regression':
        success = cmd_regression(args)
    elif args.command == 'agent':
        success = cmd_agent(args)
    elif args.command == 'multi-agent':
        success = cmd_multi_agent(args)
    else:
        parser.print_help()
        return 0
    
    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
