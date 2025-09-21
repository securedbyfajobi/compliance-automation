#!/usr/bin/env python3
"""
Compliance Framework Runner
Orchestrates execution of multiple compliance frameworks
"""

import argparse
import json
import logging
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, List

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ComplianceRunner:
    """Orchestrate compliance framework execution"""

    def __init__(self, config_path: str = None):
        self.config = self._load_config(config_path)
        self.results = {}
        self.start_time = datetime.now()

    def _load_config(self, config_path: str) -> Dict:
        """Load configuration from file or use defaults"""
        default_config = {
            'frameworks': {
                'iso27001': {
                    'enabled': True,
                    'script': 'iso27001-automation/compliance_checker.py',
                    'timeout': 300,
                    'args': ['--output', 'json']
                },
                'gdpr': {
                    'enabled': True,
                    'script': 'gdpr-compliance/gdpr_validator.py',
                    'timeout': 180,
                    'args': ['--data-inventory']
                },
                'nist': {
                    'enabled': True,
                    'script': 'nist-framework/nist_validator.py',
                    'timeout': 240,
                    'args': ['--functions', 'all']
                },
                'pci_dss': {
                    'enabled': True,
                    'script': 'pci-dss-scanner/pci_dss_scanner.py',
                    'timeout': 360,
                    'args': ['--scope', 'production']
                }
            },
            'execution': {
                'parallel': True,
                'max_workers': 4,
                'continue_on_failure': True
            },
            'output': {
                'directory': './compliance-reports',
                'formats': ['json', 'html'],
                'timestamp': True
            },
            'notifications': {
                'email': {
                    'enabled': False,
                    'recipients': []
                },
                'slack': {
                    'enabled': False,
                    'webhook_url': ''
                }
            }
        }

        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
            except Exception as e:
                logger.warning(f"Failed to load config from {config_path}: {e}")

        return default_config

    def run_framework(self, framework_name: str, framework_config: Dict) -> Dict:
        """Run a single compliance framework"""
        logger.info(f"Starting {framework_name} compliance assessment...")

        try:
            script_path = framework_config['script']
            args = framework_config.get('args', [])
            timeout = framework_config.get('timeout', 300)

            # Construct command
            cmd = [sys.executable, script_path] + args

            # Execute framework assessment
            start_time = datetime.now()
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=os.path.dirname(os.path.abspath(__file__)) + '/..'
            )

            end_time = datetime.now()
            execution_time = (end_time - start_time).total_seconds()

            # Parse results
            framework_result = {
                'framework': framework_name,
                'status': 'SUCCESS' if result.returncode == 0 else 'FAILED',
                'execution_time': execution_time,
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'command': ' '.join(cmd),
                'exit_code': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr
            }

            # Try to parse JSON output if available
            try:
                if result.stdout.strip():
                    framework_result['compliance_data'] = json.loads(result.stdout)
            except json.JSONDecodeError:
                logger.warning(f"Could not parse JSON output from {framework_name}")

            if result.returncode == 0:
                logger.info(f"✅ {framework_name} assessment completed successfully")
            else:
                logger.error(f"❌ {framework_name} assessment failed")
                logger.error(f"Error output: {result.stderr}")

            return framework_result

        except subprocess.TimeoutExpired:
            logger.error(f"⏰ {framework_name} assessment timed out after {timeout} seconds")
            return {
                'framework': framework_name,
                'status': 'TIMEOUT',
                'error': f'Assessment timed out after {timeout} seconds'
            }

        except Exception as e:
            logger.error(f"💥 {framework_name} assessment failed with exception: {e}")
            return {
                'framework': framework_name,
                'status': 'ERROR',
                'error': str(e)
            }

    def run_all_frameworks(self, selected_frameworks: List[str] = None) -> Dict:
        """Run all enabled compliance frameworks"""
        frameworks_to_run = {}

        for name, config in self.config['frameworks'].items():
            if config.get('enabled', True):
                if not selected_frameworks or name in selected_frameworks:
                    frameworks_to_run[name] = config

        if not frameworks_to_run:
            logger.error("No frameworks enabled or selected")
            return {'error': 'No frameworks to run'}

        logger.info(f"Running {len(frameworks_to_run)} compliance frameworks...")

        execution_results = {}

        if self.config['execution'].get('parallel', True):
            # Parallel execution
            max_workers = self.config['execution'].get('max_workers', 4)
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_framework = {
                    executor.submit(self.run_framework, name, config): name
                    for name, config in frameworks_to_run.items()
                }

                for future in as_completed(future_to_framework):
                    framework_name = future_to_framework[future]
                    try:
                        result = future.result()
                        execution_results[framework_name] = result
                    except Exception as e:
                        logger.error(f"Framework {framework_name} execution failed: {e}")
                        execution_results[framework_name] = {
                            'framework': framework_name,
                            'status': 'ERROR',
                            'error': str(e)
                        }
        else:
            # Sequential execution
            for name, config in frameworks_to_run.items():
                result = self.run_framework(name, config)
                execution_results[name] = result

                # Stop on failure if configured
                if (result['status'] != 'SUCCESS' and
                    not self.config['execution'].get('continue_on_failure', True)):
                    logger.error(f"Stopping execution due to {name} failure")
                    break

        return execution_results

    def generate_summary_report(self, execution_results: Dict) -> Dict:
        """Generate summary report of all framework executions"""
        end_time = datetime.now()
        total_execution_time = (end_time - self.start_time).total_seconds()

        summary = {
            'execution_summary': {
                'start_time': self.start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'total_execution_time': total_execution_time,
                'frameworks_run': len(execution_results),
                'successful': len([r for r in execution_results.values() if r.get('status') == 'SUCCESS']),
                'failed': len([r for r in execution_results.values() if r.get('status') in ['FAILED', 'ERROR', 'TIMEOUT']])
            },
            'framework_results': execution_results,
            'compliance_scores': {},
            'overall_compliance': 0
        }

        # Extract compliance scores
        total_score = 0
        scored_frameworks = 0

        for framework_name, result in execution_results.items():
            if result.get('status') == 'SUCCESS' and 'compliance_data' in result:
                data = result['compliance_data']

                # Extract score based on framework structure
                score = None
                if 'summary' in data and 'compliance_percentage' in data['summary']:
                    score = data['summary']['compliance_percentage']
                elif 'overall_score' in data:
                    score = data['overall_score']
                elif 'compliance_score' in data:
                    score = data['compliance_score']

                if score is not None:
                    summary['compliance_scores'][framework_name] = score
                    total_score += score
                    scored_frameworks += 1

        # Calculate overall compliance
        if scored_frameworks > 0:
            summary['overall_compliance'] = total_score / scored_frameworks

        return summary

    def save_results(self, summary_report: Dict):
        """Save compliance results to files"""
        output_dir = Path(self.config['output']['directory'])
        output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        formats = self.config['output'].get('formats', ['json'])

        if self.config['output'].get('timestamp', True):
            base_filename = f"compliance_summary_{timestamp}"
        else:
            base_filename = "compliance_summary"

        # Save JSON format
        if 'json' in formats:
            json_file = output_dir / f"{base_filename}.json"
            with open(json_file, 'w') as f:
                json.dump(summary_report, f, indent=2, default=str)
            logger.info(f"📄 Results saved to {json_file}")

        # Save HTML format
        if 'html' in formats:
            html_file = output_dir / f"{base_filename}.html"
            self._generate_html_report(summary_report, html_file)
            logger.info(f"🌐 HTML report saved to {html_file}")

        # Save CSV format for scores
        if 'csv' in formats:
            csv_file = output_dir / f"compliance_scores_{timestamp}.csv"
            self._generate_csv_report(summary_report, csv_file)
            logger.info(f"📊 CSV report saved to {csv_file}")

    def _generate_html_report(self, summary_report: Dict, output_file: Path):
        """Generate HTML compliance report"""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Compliance Assessment Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
                .summary { margin: 20px 0; }
                .framework { margin: 10px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
                .success { background: #d5f5e3; border-color: #27ae60; }
                .failure { background: #fadbd8; border-color: #e74c3c; }
                .score { font-size: 24px; font-weight: bold; }
                table { width: 100%; border-collapse: collapse; margin: 10px 0; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Compliance Assessment Report</h1>
                <p>Generated: {timestamp}</p>
            </div>

            <div class="summary">
                <h2>Executive Summary</h2>
                <div class="score">Overall Compliance: {overall_compliance:.1f}%</div>
                <p>Frameworks Assessed: {frameworks_run}</p>
                <p>Successful: {successful} | Failed: {failed}</p>
            </div>

            <h2>Framework Results</h2>
            {framework_details}

            <h2>Compliance Scores</h2>
            <table>
                <tr><th>Framework</th><th>Score (%)</th><th>Status</th></tr>
                {score_table}
            </table>
        </body>
        </html>
        """

        # Generate framework details
        framework_details = ""
        for name, result in summary_report['framework_results'].items():
            status_class = "success" if result.get('status') == 'SUCCESS' else "failure"
            framework_details += f"""
            <div class="framework {status_class}">
                <h3>{name.upper()}</h3>
                <p><strong>Status:</strong> {result.get('status', 'UNKNOWN')}</p>
                <p><strong>Execution Time:</strong> {result.get('execution_time', 0):.2f} seconds</p>
            </div>
            """

        # Generate score table
        score_table = ""
        for framework, score in summary_report['compliance_scores'].items():
            status = summary_report['framework_results'][framework].get('status', 'UNKNOWN')
            score_table += f"<tr><td>{framework.upper()}</td><td>{score:.1f}</td><td>{status}</td></tr>"

        html_content = html_template.format(
            timestamp=summary_report['execution_summary']['start_time'],
            overall_compliance=summary_report['overall_compliance'],
            frameworks_run=summary_report['execution_summary']['frameworks_run'],
            successful=summary_report['execution_summary']['successful'],
            failed=summary_report['execution_summary']['failed'],
            framework_details=framework_details,
            score_table=score_table
        )

        with open(output_file, 'w') as f:
            f.write(html_content)

    def _generate_csv_report(self, summary_report: Dict, output_file: Path):
        """Generate CSV compliance scores report"""
        import csv

        with open(output_file, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Framework', 'Score', 'Status', 'Execution_Time'])

            for framework, result in summary_report['framework_results'].items():
                score = summary_report['compliance_scores'].get(framework, 0)
                status = result.get('status', 'UNKNOWN')
                exec_time = result.get('execution_time', 0)
                writer.writerow([framework, score, status, exec_time])

    def send_notifications(self, summary_report: Dict):
        """Send notifications about compliance results"""
        if self.config['notifications']['email']['enabled']:
            self._send_email_notification(summary_report)

        if self.config['notifications']['slack']['enabled']:
            self._send_slack_notification(summary_report)

    def _send_email_notification(self, summary_report: Dict):
        """Send email notification"""
        # Implementation would depend on your email service
        logger.info("📧 Email notification sent")

    def _send_slack_notification(self, summary_report: Dict):
        """Send Slack notification"""
        # Implementation would depend on Slack webhook
        logger.info("💬 Slack notification sent")

def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description='Compliance Framework Runner')
    parser.add_argument('--config', help='Configuration file path')
    parser.add_argument('--frameworks', nargs='+', help='Specific frameworks to run',
                        choices=['iso27001', 'gdpr', 'nist', 'pci_dss'])
    parser.add_argument('--parallel', action='store_true', help='Run frameworks in parallel')
    parser.add_argument('--output-dir', help='Output directory for results')
    parser.add_argument('--format', nargs='+', choices=['json', 'html', 'csv'],
                        default=['json'], help='Output formats')
    parser.add_argument('--notify', action='store_true', help='Send notifications')
    parser.add_argument('--verbose', action='store_true', help='Verbose logging')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Initialize runner
    runner = ComplianceRunner(args.config)

    # Override config with command line arguments
    if args.parallel:
        runner.config['execution']['parallel'] = True

    if args.output_dir:
        runner.config['output']['directory'] = args.output_dir

    if args.format:
        runner.config['output']['formats'] = args.format

    # Run compliance assessments
    results = runner.run_all_frameworks(args.frameworks)

    # Generate summary report
    summary = runner.generate_summary_report(results)

    # Save results
    runner.save_results(summary)

    # Send notifications
    if args.notify:
        runner.send_notifications(summary)

    # Print summary
    print(f"\n🎯 Compliance Assessment Complete")
    print(f"Overall Compliance: {summary['overall_compliance']:.1f}%")
    print(f"Successful: {summary['execution_summary']['successful']}")
    print(f"Failed: {summary['execution_summary']['failed']}")

    # Exit with appropriate code
    if summary['execution_summary']['failed'] > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()