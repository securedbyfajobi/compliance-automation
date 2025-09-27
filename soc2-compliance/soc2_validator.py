#!/usr/bin/env python3
"""
SOC 2 Type II Compliance Validator
Automated validation of SOC 2 trust service criteria
Comprehensive implementation with AWS integration
"""

import argparse
import boto3
import json
import logging
import os
import re
import yaml
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SOC2Validator:
    """Comprehensive SOC 2 Type II compliance validator with AWS integration"""

    def __init__(self, region: str = 'eu-west-2', config_file: Optional[str] = None):
        self.region = region
        self.config = self._load_config(config_file)

        # AWS Clients for comprehensive SOC 2 assessment
        self.ec2 = boto3.client('ec2', region_name=region)
        self.s3 = boto3.client('s3')
        self.iam = boto3.client('iam')
        self.cloudtrail = boto3.client('cloudtrail', region_name=region)
        self.cloudwatch = boto3.client('cloudwatch', region_name=region)
        self.config_client = boto3.client('config', region_name=region)
        self.guardduty = boto3.client('guardduty', region_name=region)
        self.kms = boto3.client('kms', region_name=region)
        self.rds = boto3.client('rds', region_name=region)
        self.backup = boto3.client('backup', region_name=region)

        self.validation_results = {
            'timestamp': datetime.now().isoformat(),
            'framework': 'SOC 2 Type II',
            'version': '2017',
            'region': region,
            'trust_service_criteria': {
                'security': {'controls': {}, 'score': 0, 'aws_checks': {}},
                'availability': {'controls': {}, 'score': 0, 'aws_checks': {}},
                'processing_integrity': {'controls': {}, 'score': 0, 'aws_checks': {}},
                'confidentiality': {'controls': {}, 'score': 0, 'aws_checks': {}},
                'privacy': {'controls': {}, 'score': 0, 'aws_checks': {}}
            },
            'overall_score': 0,
            'aws_summary': {
                'total_checks': 0,
                'implemented': 0,
                'not_implemented': 0,
                'partial': 0,
                'compliance_score': 0.0
            }
        }

    def _load_config(self, config_file: Optional[str]) -> Dict:
        """Load configuration from file or use defaults"""
        default_config = {
            'assessment_period_months': 12,
            'evidence_retention_years': 3,
            'monitoring_frequency_hours': 24,
            'backup_retention_days': 90,
            'log_retention_days': 365
        }

        if config_file and os.path.exists(config_file):
            with open(config_file, 'r') as f:
                user_config = yaml.safe_load(f)
                default_config.update(user_config)

        return default_config

    def check_security_criteria(self, directory: str = ".") -> Dict:
        """CC1-CC9: Common Criteria - Security"""
        logger.info("Checking SOC 2 Security criteria...")

        # CC1 - Control Environment
        control_env_patterns = [
            r'control.*environment',
            r'governance.*framework',
            r'security.*policy',
            r'risk.*management.*framework',
            r'management.*oversight'
        ]

        control_environment = self._check_patterns(directory, control_env_patterns)
        self.validation_results['trust_service_criteria']['security']['controls']['CC1'] = {
            'status': 'Implemented' if control_environment else 'Not Implemented',
            'description': 'Control Environment',
            'evidence': 'Governance and risk management framework documentation'
        }

        # CC2 - Communication and Information
        communication_patterns = [
            r'security.*communication',
            r'policy.*communication',
            r'security.*awareness.*training',
            r'incident.*notification',
            r'security.*procedures'
        ]

        communication = self._check_patterns(directory, communication_patterns)
        self.validation_results['trust_service_criteria']['security']['controls']['CC2'] = {
            'status': 'Implemented' if communication else 'Not Implemented',
            'description': 'Communication and Information',
            'evidence': 'Security communication and training programs'
        }

        # CC3 - Risk Assessment
        risk_assessment_patterns = [
            r'risk.*assessment.*process',
            r'threat.*analysis',
            r'vulnerability.*assessment',
            r'risk.*register',
            r'risk.*mitigation'
        ]

        risk_assessment = self._check_patterns(directory, risk_assessment_patterns)
        self.validation_results['trust_service_criteria']['security']['controls']['CC3'] = {
            'status': 'Implemented' if risk_assessment else 'Not Implemented',
            'description': 'Risk Assessment',
            'evidence': 'Formal risk assessment and threat analysis documentation'
        }

        # CC4 - Monitoring Activities
        monitoring_patterns = [
            r'continuous.*monitoring',
            r'security.*monitoring',
            r'control.*monitoring',
            r'performance.*monitoring',
            r'compliance.*monitoring'
        ]

        monitoring = self._check_patterns(directory, monitoring_patterns)
        self.validation_results['trust_service_criteria']['security']['controls']['CC4'] = {
            'status': 'Implemented' if monitoring else 'Not Implemented',
            'description': 'Monitoring Activities',
            'evidence': 'Continuous monitoring and oversight procedures'
        }

        # CC5 - Control Activities
        control_activities_patterns = [
            r'control.*activities',
            r'security.*controls',
            r'access.*controls',
            r'change.*control',
            r'segregation.*of.*duties'
        ]

        control_activities = self._check_patterns(directory, control_activities_patterns)
        self.validation_results['trust_service_criteria']['security']['controls']['CC5'] = {
            'status': 'Implemented' if control_activities else 'Not Implemented',
            'description': 'Control Activities',
            'evidence': 'Implemented security and operational controls'
        }

        # CC6 - Logical and Physical Access Controls
        access_control_patterns = [
            r'access.*control.*policy',
            r'physical.*security',
            r'logical.*access.*control',
            r'authentication.*system',
            r'authorization.*matrix'
        ]

        access_controls = self._check_patterns(directory, access_control_patterns)
        self.validation_results['trust_service_criteria']['security']['controls']['CC6'] = {
            'status': 'Implemented' if access_controls else 'Not Implemented',
            'description': 'Logical and Physical Access Controls',
            'evidence': 'Access control policies and physical security measures'
        }

        # CC7 - System Operations
        system_ops_patterns = [
            r'system.*operations',
            r'capacity.*management',
            r'system.*monitoring',
            r'performance.*management',
            r'operational.*procedures'
        ]

        system_operations = self._check_patterns(directory, system_ops_patterns)
        self.validation_results['trust_service_criteria']['security']['controls']['CC7'] = {
            'status': 'Implemented' if system_operations else 'Not Implemented',
            'description': 'System Operations',
            'evidence': 'System operations and capacity management procedures'
        }

        # CC8 - Change Management
        change_mgmt_patterns = [
            r'change.*management.*process',
            r'configuration.*management',
            r'deployment.*procedures',
            r'version.*control',
            r'emergency.*changes'
        ]

        change_management = self._check_patterns(directory, change_mgmt_patterns)
        self.validation_results['trust_service_criteria']['security']['controls']['CC8'] = {
            'status': 'Implemented' if change_management else 'Not Implemented',
            'description': 'Change Management',
            'evidence': 'Formal change management and configuration control'
        }

        # CC9 - Risk Mitigation
        risk_mitigation_patterns = [
            r'risk.*mitigation.*strategy',
            r'incident.*response.*plan',
            r'business.*continuity.*plan',
            r'disaster.*recovery.*plan',
            r'risk.*treatment'
        ]

        risk_mitigation = self._check_patterns(directory, risk_mitigation_patterns)
        self.validation_results['trust_service_criteria']['security']['controls']['CC9'] = {
            'status': 'Implemented' if risk_mitigation else 'Not Implemented',
            'description': 'Risk Mitigation',
            'evidence': 'Risk mitigation and incident response procedures'
        }

        # Calculate Security score
        implemented_controls = sum(
            1 for control in self.validation_results['trust_service_criteria']['security']['controls'].values()
            if control['status'] == 'Implemented'
        )
        total_controls = len(self.validation_results['trust_service_criteria']['security']['controls'])
        self.validation_results['trust_service_criteria']['security']['score'] = (implemented_controls / total_controls) * 100

        # AWS-specific security checks
        aws_security_checks = self._run_aws_security_checks()
        self.validation_results['trust_service_criteria']['security']['aws_checks'] = aws_security_checks

        return self.validation_results['trust_service_criteria']['security']

    def _run_aws_security_checks(self) -> Dict:
        """Run AWS-specific checks for Security criteria"""
        checks = {}

        # Access Control via IAM
        try:
            # Check for MFA enforcement
            users = self.iam.list_users()['Users']
            mfa_devices = self.iam.list_virtual_mfa_devices()['VirtualMFADevices']
            mfa_coverage = (len(mfa_devices) / len(users)) * 100 if users else 0

            # Check for password policy
            try:
                password_policy = self.iam.get_account_password_policy()
                password_policy_exists = True
            except:
                password_policy_exists = False

            # Check for root account MFA
            account_summary = self.iam.get_account_summary()
            root_mfa = account_summary.get('AccountMFAEnabled', 0) > 0

            access_score = (mfa_coverage >= 90) * 40 + password_policy_exists * 30 + root_mfa * 30

            checks['access_control'] = {
                'status': 'Implemented' if access_score >= 80 else 'Partial' if access_score >= 50 else 'Not Implemented',
                'description': f'IAM access controls: MFA {mfa_coverage:.1f}%, Password Policy: {password_policy_exists}, Root MFA: {root_mfa}',
                'compliant': access_score >= 80
            }
        except Exception as e:
            checks['access_control'] = {
                'status': 'Error',
                'description': f'Error checking IAM: {str(e)}',
                'compliant': False
            }

        # Encryption Controls
        try:
            # Check S3 encryption
            buckets = self.s3.list_buckets()['Buckets']
            encrypted_buckets = 0

            for bucket in buckets:
                try:
                    self.s3.get_bucket_encryption(Bucket=bucket['Name'])
                    encrypted_buckets += 1
                except:
                    pass

            # Check RDS encryption
            rds_instances = self.rds.describe_db_instances()['DBInstances']
            encrypted_rds = sum(1 for db in rds_instances if db.get('StorageEncrypted', False))

            # Check KMS key management
            keys = self.kms.list_keys()['Keys']
            customer_managed_keys = len([k for k in keys if not k['KeyId'].startswith('alias/aws/')])

            encryption_rate = (
                (encrypted_buckets / len(buckets) if buckets else 1) * 0.4 +
                (encrypted_rds / len(rds_instances) if rds_instances else 1) * 0.4 +
                (min(customer_managed_keys / 5, 1)) * 0.2
            ) * 100

            checks['encryption'] = {
                'status': 'Implemented' if encryption_rate >= 95 else 'Partial' if encryption_rate >= 70 else 'Not Implemented',
                'description': f'Encryption coverage: S3 {encrypted_buckets}/{len(buckets)}, RDS {encrypted_rds}/{len(rds_instances)}, CMKs {customer_managed_keys}',
                'compliant': encryption_rate >= 95
            }
        except Exception as e:
            checks['encryption'] = {
                'status': 'Error',
                'description': f'Error checking encryption: {str(e)}',
                'compliant': False
            }

        return checks

    def check_availability_criteria(self, directory: str = ".") -> Dict:
        """A1: Availability criteria"""
        logger.info("Checking SOC 2 Availability criteria...")

        # Performance Monitoring
        performance_patterns = [
            r'performance.*monitoring',
            r'availability.*monitoring',
            r'uptime.*monitoring',
            r'sla.*monitoring',
            r'capacity.*planning'
        ]

        performance_monitoring = self._check_patterns(directory, performance_patterns)
        self.validation_results['trust_service_criteria']['availability']['controls']['A1.1'] = {
            'status': 'Implemented' if performance_monitoring else 'Not Implemented',
            'description': 'Performance and Availability Monitoring',
            'evidence': 'System performance and availability monitoring procedures'
        }

        # Backup and Recovery
        backup_patterns = [
            r'backup.*procedures',
            r'data.*backup',
            r'recovery.*procedures',
            r'disaster.*recovery',
            r'business.*continuity'
        ]

        backup_recovery = self._check_patterns(directory, backup_patterns)
        self.validation_results['trust_service_criteria']['availability']['controls']['A1.2'] = {
            'status': 'Implemented' if backup_recovery else 'Not Implemented',
            'description': 'Backup and Recovery Procedures',
            'evidence': 'Data backup and disaster recovery documentation'
        }

        # Environmental Protections
        environmental_patterns = [
            r'environmental.*controls',
            r'data.*center.*security',
            r'power.*management',
            r'cooling.*systems',
            r'facility.*security'
        ]

        environmental_protections = self._check_patterns(directory, environmental_patterns)
        self.validation_results['trust_service_criteria']['availability']['controls']['A1.3'] = {
            'status': 'Implemented' if environmental_protections else 'Not Implemented',
            'description': 'Environmental Protections',
            'evidence': 'Data center and facility security controls'
        }

        # Calculate Availability score
        implemented_controls = sum(
            1 for control in self.validation_results['trust_service_criteria']['availability']['controls'].values()
            if control['status'] == 'Implemented'
        )
        total_controls = len(self.validation_results['trust_service_criteria']['availability']['controls'])
        self.validation_results['trust_service_criteria']['availability']['score'] = (implemented_controls / total_controls) * 100

        # AWS-specific availability checks
        aws_availability_checks = self._run_aws_availability_checks()
        self.validation_results['trust_service_criteria']['availability']['aws_checks'] = aws_availability_checks

        return self.validation_results['trust_service_criteria']['availability']

    def _run_aws_availability_checks(self) -> Dict:
        """Run AWS-specific checks for Availability criteria"""
        checks = {}

        # Backup and Recovery
        try:
            # Check AWS Backup
            backup_plans = self.backup.list_backup_plans()['BackupPlansList']

            # Check RDS automated backups
            rds_instances = self.rds.describe_db_instances()['DBInstances']
            rds_with_backups = sum(1 for db in rds_instances if db.get('BackupRetentionPeriod', 0) > 0)

            # Check EBS snapshots (sample check)
            snapshots = self.ec2.describe_snapshots(OwnerIds=['self'], MaxResults=10)['Snapshots']
            recent_snapshots = [
                s for s in snapshots
                if (datetime.now() - s['StartTime'].replace(tzinfo=None)).days <= 7
            ]

            backup_score = (
                (len(backup_plans) > 0) * 40 +
                (rds_with_backups / len(rds_instances) if rds_instances else 1) * 40 +
                (len(recent_snapshots) > 0) * 20
            )

            checks['backup_recovery'] = {
                'status': 'Implemented' if backup_score >= 80 else 'Partial' if backup_score >= 50 else 'Not Implemented',
                'description': f'Backup coverage: {len(backup_plans)} backup plans, {rds_with_backups}/{len(rds_instances)} RDS backups, {len(recent_snapshots)} recent snapshots',
                'compliant': backup_score >= 80
            }
        except Exception as e:
            checks['backup_recovery'] = {
                'status': 'Error',
                'description': f'Error checking backup systems: {str(e)}',
                'compliant': False
            }

        # Monitoring and Alerting
        try:
            alarms = self.cloudwatch.describe_alarms()['MetricAlarms']
            enabled_alarms = [alarm for alarm in alarms if alarm['ActionsEnabled']]

            # Check for critical system alarms
            critical_alarms = [
                alarm for alarm in enabled_alarms
                if any(keyword in alarm['AlarmName'].lower()
                      for keyword in ['cpu', 'memory', 'disk', 'network', 'availability'])
            ]

            monitoring_score = min((len(critical_alarms) / 5), 1) * 100

            checks['monitoring'] = {
                'status': 'Implemented' if monitoring_score >= 80 else 'Partial' if monitoring_score >= 50 else 'Not Implemented',
                'description': f'CloudWatch monitoring: {len(enabled_alarms)} total alarms, {len(critical_alarms)} critical alarms',
                'compliant': monitoring_score >= 80
            }
        except Exception as e:
            checks['monitoring'] = {
                'status': 'Error',
                'description': f'Error checking monitoring: {str(e)}',
                'compliant': False
            }

        return checks

    def check_processing_integrity_criteria(self, directory: str = ".") -> Dict:
        """PI1: Processing Integrity criteria"""
        logger.info("Checking SOC 2 Processing Integrity criteria...")

        # Data Processing Controls
        processing_patterns = [
            r'data.*processing.*controls',
            r'input.*validation',
            r'data.*integrity.*checks',
            r'processing.*procedures',
            r'data.*quality.*controls'
        ]

        processing_controls = self._check_patterns(directory, processing_patterns)
        self.validation_results['trust_service_criteria']['processing_integrity']['controls']['PI1.1'] = {
            'status': 'Implemented' if processing_controls else 'Not Implemented',
            'description': 'Data Processing Controls',
            'evidence': 'Data processing and integrity validation procedures'
        }

        # Error Handling
        error_handling_patterns = [
            r'error.*handling.*procedures',
            r'exception.*handling',
            r'error.*logging',
            r'data.*validation.*errors',
            r'processing.*errors'
        ]

        error_handling = self._check_patterns(directory, error_handling_patterns)
        self.validation_results['trust_service_criteria']['processing_integrity']['controls']['PI1.2'] = {
            'status': 'Implemented' if error_handling else 'Not Implemented',
            'description': 'Error Handling Procedures',
            'evidence': 'Error handling and exception management documentation'
        }

        # Calculate Processing Integrity score
        implemented_controls = sum(
            1 for control in self.validation_results['trust_service_criteria']['processing_integrity']['controls'].values()
            if control['status'] == 'Implemented'
        )
        total_controls = len(self.validation_results['trust_service_criteria']['processing_integrity']['controls'])
        self.validation_results['trust_service_criteria']['processing_integrity']['score'] = (implemented_controls / total_controls) * 100

        return self.validation_results['trust_service_criteria']['processing_integrity']

    def _check_patterns(self, directory: str, patterns: List[str]) -> bool:
        """Check if any of the patterns are found in the directory"""
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith(('.py', '.js', '.java', '.md', '.yml', '.yaml', '.json', '.conf', '.txt')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read().lower()
                            for pattern in patterns:
                                if re.search(pattern, content):
                                    return True
                    except (UnicodeDecodeError, PermissionError):
                        continue
        return False

    def _calculate_aws_summary(self) -> None:
        """Calculate overall AWS compliance summary"""
        total_checks = 0
        implemented = 0
        not_implemented = 0
        partial = 0

        for criteria_name, criteria_data in self.validation_results['trust_service_criteria'].items():
            aws_checks = criteria_data.get('aws_checks', {})
            for check_name, check_data in aws_checks.items():
                total_checks += 1
                status = check_data['status']

                if status == 'Implemented':
                    implemented += 1
                elif status == 'Partial':
                    partial += 1
                else:
                    not_implemented += 1

        self.validation_results['aws_summary'] = {
            'total_checks': total_checks,
            'implemented': implemented,
            'not_implemented': not_implemented,
            'partial': partial,
            'compliance_score': ((implemented + partial) / total_checks * 100) if total_checks > 0 else 0
        }

    def generate_compliance_report(self) -> Dict:
        """Generate comprehensive SOC 2 compliance report"""
        logger.info("Generating SOC 2 compliance report...")

        # Calculate overall score
        total_score = 0
        criteria_count = 0

        for criteria_name, criteria_data in self.validation_results['trust_service_criteria'].items():
            if criteria_data.get('controls'):
                total_score += criteria_data['score']
                criteria_count += 1

        if criteria_count > 0:
            self.validation_results['overall_score'] = total_score / criteria_count

        # Calculate AWS summary
        self._calculate_aws_summary()

        # Generate recommendations
        recommendations = []

        for criteria_name, criteria_data in self.validation_results['trust_service_criteria'].items():
            # Traditional control recommendations
            for control_id, control_data in criteria_data.get('controls', {}).items():
                if control_data['status'] == 'Not Implemented':
                    recommendations.append({
                        'type': 'Control Implementation',
                        'criteria': criteria_name.title(),
                        'control': control_id,
                        'issue': control_data['description'],
                        'remediation': f'Implement {control_data["description"]} controls and document evidence'
                    })

            # AWS-specific recommendations
            for check_name, check_data in criteria_data.get('aws_checks', {}).items():
                if not check_data['compliant']:
                    recommendations.append({
                        'type': 'AWS Configuration',
                        'criteria': criteria_name.title(),
                        'control': check_name,
                        'issue': check_data['description'],
                        'remediation': f'Address {check_name} AWS configuration to meet SOC 2 requirements'
                    })

        self.validation_results['recommendations'] = recommendations

        return self.validation_results

    def run_full_assessment(self, directory: str = ".") -> Dict:
        """Run complete SOC 2 assessment"""
        logger.info("Starting SOC 2 Type II compliance assessment...")

        self.check_security_criteria(directory)
        self.check_availability_criteria(directory)
        self.check_processing_integrity_criteria(directory)

        return self.generate_compliance_report()

def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description='SOC 2 Type II Compliance Assessment')
    parser.add_argument('--region', default='eu-west-2', help='AWS region to assess')
    parser.add_argument('--config', help='Configuration file path')
    parser.add_argument('--output', help='Output file path')
    parser.add_argument('--format', choices=['json', 'yaml'], default='json', help='Output format')
    parser.add_argument('--directory', default='.', help='Directory to scan for compliance artifacts')
    parser.add_argument('--criteria', nargs='+',
                       choices=['security', 'availability', 'processing_integrity', 'confidentiality', 'privacy'],
                       help='Specific trust service criteria to assess')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    validator = SOC2Validator(region=args.region, config_file=args.config)
    results = validator.run_full_assessment(directory=args.directory)

    # Output report
    if args.format == 'yaml':
        output = yaml.dump(results, default_flow_style=False, sort_keys=False)
        print(output)
    else:
        output = json.dumps(results, indent=2)
        print(output)

    # Save to file
    if args.output:
        output_file = args.output
    else:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = f"soc2_compliance_report_{timestamp}.{args.format}"

    with open(output_file, 'w') as f:
        if args.format == 'yaml':
            yaml.dump(results, f, default_flow_style=False, sort_keys=False)
        else:
            json.dump(results, f, indent=2)

    # Summary output
    overall_score = results.get('overall_score', 0)
    aws_summary = results.get('aws_summary', {})

    logger.info(f"SOC 2 assessment complete: {overall_score:.1f}% traditional controls")
    logger.info(f"AWS compliance: {aws_summary.get('compliance_score', 0):.1f}% ({aws_summary.get('implemented', 0)} implemented, {aws_summary.get('partial', 0)} partial)")
    logger.info(f"Report saved to: {output_file}")

    # Return exit code based on compliance
    combined_score = (overall_score + aws_summary.get('compliance_score', 0)) / 2
    if combined_score < 70:
        return 1
    return 0

if __name__ == "__main__":
    exit(main())