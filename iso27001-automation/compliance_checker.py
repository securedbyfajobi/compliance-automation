#!/usr/bin/env python3
"""
ISO 27001 Compliance Checker
Automated validation of ISO 27001:2013 security controls
Comprehensive implementation covering all Annex A controls
"""

import argparse
import boto3
import json
import yaml
import logging
import os
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from enhanced_controls import EnhancedISO27001Controls

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ISO27001Checker(EnhancedISO27001Controls):
    """Comprehensive ISO 27001:2013 compliance validation covering all Annex A controls"""

    def __init__(self, region: str = 'eu-west-2', config_file: Optional[str] = None):
        self.region = region
        self.config = self._load_config(config_file)

        # AWS Clients
        self.ec2 = boto3.client('ec2', region_name=region)
        self.s3 = boto3.client('s3')
        self.iam = boto3.client('iam')
        self.cloudtrail = boto3.client('cloudtrail', region_name=region)
        self.cloudwatch = boto3.client('cloudwatch', region_name=region)
        self.config_client = boto3.client('config', region_name=region)
        self.guardduty = boto3.client('guardduty', region_name=region)
        self.kms = boto3.client('kms', region_name=region)
        self.rds = boto3.client('rds', region_name=region)
        self.lambda_client = boto3.client('lambda', region_name=region)
        self.securityhub = boto3.client('securityhub', region_name=region)
        self.inspector = boto3.client('inspector2', region_name=region)
        self.macie = boto3.client('macie2', region_name=region)
        self.organizations = boto3.client('organizations')
        self.ssm = boto3.client('ssm', region_name=region)

        # Initialize parent class
        super().__init__(region, config_file)

        # Results storage
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'framework': 'ISO 27001:2013',
            'version': '2013',
            'region': region,
            'controls': {},
            'summary': {
                'total_controls': 0,
                'implemented': 0,
                'not_implemented': 0,
                'partial': 0,
                'not_applicable': 0,
                'compliance_score': 0.0
            }
        }

    def _load_config(self, config_file: Optional[str]) -> Dict:
        """Load configuration from file or use defaults"""
        default_config = {
            'scope': {
                'include_regions': ['eu-west-2', 'us-east-1'],
                'exclude_accounts': [],
                'include_services': ['ec2', 's3', 'iam', 'cloudtrail', 'kms', 'rds']
            },
            'thresholds': {
                'password_max_age': 90,
                'key_rotation_days': 365,
                'log_retention_days': 365,
                'backup_retention_days': 30
            },
            'controls': {
                'skip_controls': [],
                'custom_controls': {}
            }
        }

        if config_file and os.path.exists(config_file):
            with open(config_file, 'r') as f:
                user_config = yaml.safe_load(f)
                default_config.update(user_config)

        return default_config

    def check_control_a12_6_2(self) -> Tuple[bool, str]:
        """A.12.6.2 Restrictions on software installation"""
        try:
            # Check IAM policies for software installation restrictions
            policies = self.iam.list_policies(Scope='Local')['Policies']

            for policy in policies:
                if 'software-restriction' in policy['PolicyName'].lower():
                    return True, "Software installation restrictions found in IAM policies"

            return False, "No software installation restrictions found"
        except Exception as e:
            return False, f"Error checking control A.12.6.2: {str(e)}"

    def check_control_a13_1_1(self) -> Tuple[bool, str]:
        """A.13.1.1 Network controls"""
        try:
            # Check security groups for default deny rules
            security_groups = self.ec2.describe_security_groups()['SecurityGroups']

            compliant_sgs = 0
            for sg in security_groups:
                if sg['GroupName'] == 'default':
                    # Check if default SG has restrictive rules
                    if not sg['IpPermissions']:  # No inbound rules
                        compliant_sgs += 1

            compliance_rate = (compliant_sgs / len(security_groups)) * 100

            if compliance_rate >= 80:
                return True, f"Network controls compliant: {compliance_rate:.1f}%"
            else:
                return False, f"Network controls non-compliant: {compliance_rate:.1f}%"

        except Exception as e:
            return False, f"Error checking control A.13.1.1: {str(e)}"

    def check_control_a12_4_1(self) -> Tuple[bool, str]:
        """A.12.4.1 Event logging"""
        try:
            # Check CloudTrail configuration
            trails = self.cloudtrail.describe_trails()['trailList']

            active_trails = []
            for trail in trails:
                status = self.cloudtrail.get_trail_status(Name=trail['TrailARN'])
                if status['IsLogging']:
                    active_trails.append(trail)

            if active_trails:
                return True, f"Event logging active: {len(active_trails)} CloudTrail(s) enabled"
            else:
                return False, "No active CloudTrail logging found"

        except Exception as e:
            return False, f"Error checking control A.12.4.1: {str(e)}"

    def check_control_a10_1_1(self) -> Tuple[bool, str]:
        """A.10.1.1 Use of cryptographic controls"""
        try:
            # Check S3 bucket encryption
            buckets = self.s3.list_buckets()['Buckets']
            encrypted_buckets = 0

            for bucket in buckets:
                try:
                    self.s3.get_bucket_encryption(Bucket=bucket['Name'])
                    encrypted_buckets += 1
                except self.s3.exceptions.ClientError:
                    pass  # No encryption configured

            encryption_rate = (encrypted_buckets / len(buckets)) * 100 if buckets else 0

            if encryption_rate >= 95:
                return True, f"Cryptographic controls compliant: {encryption_rate:.1f}%"
            else:
                return False, f"Cryptographic controls non-compliant: {encryption_rate:.1f}%"

        except Exception as e:
            return False, f"Error checking control A.10.1.1: {str(e)}"

    def run_comprehensive_assessment(self) -> Dict:
        """Run comprehensive ISO 27001 assessment using all enhanced controls"""

        # Get all control methods from enhanced controls
        control_methods = {}
        for attr_name in dir(self):
            if attr_name.startswith('check_a') and callable(getattr(self, attr_name)):
                control_id = attr_name.replace('check_', '').replace('_', '.').upper()
                control_methods[control_id] = getattr(self, attr_name)

        logger.info(f"Running assessment for {len(control_methods)} ISO 27001 controls")

        results = {}
        summary = {
            'total_controls': len(control_methods),
            'implemented': 0,
            'not_implemented': 0,
            'partial': 0,
            'not_applicable': 0,
            'compliance_score': 0.0
        }

        # Run controls in parallel for better performance
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_control = {
                executor.submit(method): control_id
                for control_id, method in control_methods.items()
            }

            for future in as_completed(future_to_control):
                control_id = future_to_control[future]
                try:
                    status, compliant, description = future.result()

                    results[control_id] = {
                        'status': status,
                        'compliant': compliant,
                        'description': description,
                        'timestamp': datetime.now().isoformat()
                    }

                    summary[status.lower().replace(' ', '_')] += 1

                except Exception as e:
                    logger.error(f"Error checking control {control_id}: {str(e)}")
                    results[control_id] = {
                        'status': 'Error',
                        'compliant': False,
                        'description': f"Assessment failed: {str(e)}",
                        'timestamp': datetime.now().isoformat()
                    }
                    summary['not_implemented'] += 1

        # Calculate compliance score
        implemented_controls = summary['implemented'] + summary['partial']
        summary['compliance_score'] = (implemented_controls / summary['total_controls']) * 100

        return {
            'timestamp': datetime.now().isoformat(),
            'framework': 'ISO 27001:2013',
            'version': '2013',
            'region': self.region,
            'controls': results,
            'summary': summary,
            'recommendations': self._generate_recommendations(results)
        }

    def _generate_recommendations(self, results: Dict) -> List[str]:
        """Generate actionable recommendations based on assessment results"""
        recommendations = []

        non_compliant = [
            control_id for control_id, result in results.items()
            if not result['compliant']
        ]

        if non_compliant:
            recommendations.append(f"Address {len(non_compliant)} non-compliant controls immediately")

        # Category-specific recommendations
        access_controls = [c for c in non_compliant if c.startswith('A.9')]
        if access_controls:
            recommendations.append("Strengthen access control policies and review user permissions")

        crypto_controls = [c for c in non_compliant if c.startswith('A.10')]
        if crypto_controls:
            recommendations.append("Implement comprehensive encryption across all data stores")

        network_controls = [c for c in non_compliant if c.startswith('A.13')]
        if network_controls:
            recommendations.append("Review and harden network security configurations")

        incident_controls = [c for c in non_compliant if c.startswith('A.16')]
        if incident_controls:
            recommendations.append("Establish formal incident response procedures and testing")

        return recommendations

    def run_specific_controls(self, control_ids: List[str]) -> Dict:
        """Run assessment for specific controls only"""

        results = {}
        summary = {
            'total_controls': len(control_ids),
            'implemented': 0,
            'not_implemented': 0,
            'partial': 0,
            'not_applicable': 0,
            'compliance_score': 0.0
        }

        for control_id in control_ids:
            method_name = f"check_{control_id.lower().replace('.', '_')}"

            if hasattr(self, method_name):
                try:
                    method = getattr(self, method_name)
                    status, compliant, description = method()

                    results[control_id] = {
                        'status': status,
                        'compliant': compliant,
                        'description': description,
                        'timestamp': datetime.now().isoformat()
                    }

                    summary[status.lower().replace(' ', '_')] += 1

                except Exception as e:
                    logger.error(f"Error checking control {control_id}: {str(e)}")
                    results[control_id] = {
                        'status': 'Error',
                        'compliant': False,
                        'description': f"Assessment failed: {str(e)}",
                        'timestamp': datetime.now().isoformat()
                    }
                    summary['not_implemented'] += 1
            else:
                logger.warning(f"Control {control_id} not implemented")
                results[control_id] = {
                    'status': 'Not Applicable',
                    'compliant': False,
                    'description': 'Control not implemented in checker',
                    'timestamp': datetime.now().isoformat()
                }
                summary['not_applicable'] += 1

        # Calculate compliance score
        implemented_controls = summary['implemented'] + summary['partial']
        summary['compliance_score'] = (implemented_controls / summary['total_controls']) * 100 if summary['total_controls'] > 0 else 0

        return {
            'timestamp': datetime.now().isoformat(),
            'framework': 'ISO 27001:2013',
            'version': '2013',
            'region': self.region,
            'controls': results,
            'summary': summary,
            'recommendations': self._generate_recommendations(results)
        }

    def generate_compliance_report(self) -> Dict:
        """Legacy method for backward compatibility"""
        return self.run_comprehensive_assessment()

def main():
    parser = argparse.ArgumentParser(description='ISO 27001:2013 Compliance Assessment')
    parser.add_argument('--region', default='eu-west-2', help='AWS region to assess')
    parser.add_argument('--config', help='Configuration file path')
    parser.add_argument('--output', help='Output file path')
    parser.add_argument('--format', choices=['json', 'yaml'], default='json', help='Output format')
    parser.add_argument('--controls', nargs='+', help='Specific controls to check (e.g., A.5.1.1 A.9.1.1)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    checker = ISO27001Checker(region=args.region, config_file=args.config)

    if args.controls:
        # Run specific controls only
        logger.info(f"Running assessment for specific controls: {args.controls}")
        report = checker.run_specific_controls(args.controls)
    else:
        # Run comprehensive assessment
        logger.info("Running comprehensive ISO 27001 assessment")
        report = checker.run_comprehensive_assessment()

    # Output report
    if args.format == 'yaml':
        output = yaml.dump(report, default_flow_style=False, sort_keys=False)
        print(output)
    else:
        output = json.dumps(report, indent=2)
        print(output)

    # Save to file
    if args.output:
        output_file = args.output
    else:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = f"iso27001_report_{timestamp}.{args.format}"

    with open(output_file, 'w') as f:
        if args.format == 'yaml':
            yaml.dump(report, f, default_flow_style=False, sort_keys=False)
        else:
            json.dump(report, f, indent=2)

    # Summary output
    summary = report['summary']
    logger.info(f"Assessment complete: {summary['compliance_score']:.1f}% compliant")
    logger.info(f"Controls: {summary['implemented']} implemented, {summary['partial']} partial, {summary['not_implemented']} not implemented")
    logger.info(f"Report saved to: {output_file}")

    # Return exit code based on compliance
    if summary['compliance_score'] < 80:
        return 1
    return 0

if __name__ == "__main__":
    main()