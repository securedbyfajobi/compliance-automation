#!/usr/bin/env python3
"""
ISO 27001 Compliance Checker
Automated validation of ISO 27001:2013 security controls
"""

import boto3
import json
import yaml
import logging
from datetime import datetime
from typing import Dict, List, Tuple

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ISO27001Checker:
    """ISO 27001 compliance validation"""

    def __init__(self):
        self.ec2 = boto3.client('ec2')
        self.s3 = boto3.client('s3')
        self.iam = boto3.client('iam')
        self.cloudtrail = boto3.client('cloudtrail')

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

    def generate_compliance_report(self) -> Dict:
        """Generate comprehensive compliance report"""
        controls = {
            'A.12.6.2': self.check_control_a12_6_2,
            'A.13.1.1': self.check_control_a13_1_1,
            'A.12.4.1': self.check_control_a12_4_1,
            'A.10.1.1': self.check_control_a10_1_1,
        }

        report = {
            'timestamp': datetime.now().isoformat(),
            'framework': 'ISO 27001:2013',
            'controls': {},
            'summary': {
                'total_controls': len(controls),
                'compliant': 0,
                'non_compliant': 0,
                'compliance_percentage': 0
            }
        }

        for control_id, check_function in controls.items():
            compliant, message = check_function()

            report['controls'][control_id] = {
                'compliant': compliant,
                'description': message,
                'checked_at': datetime.now().isoformat()
            }

            if compliant:
                report['summary']['compliant'] += 1
            else:
                report['summary']['non_compliant'] += 1

        report['summary']['compliance_percentage'] = (
            report['summary']['compliant'] / report['summary']['total_controls']
        ) * 100

        return report

def main():
    checker = ISO27001Checker()
    report = checker.generate_compliance_report()

    # Output report
    print(json.dumps(report, indent=2))

    # Save to file
    with open(f"iso27001_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json", 'w') as f:
        json.dump(report, f, indent=2)

    logger.info(f"Compliance check complete: {report['summary']['compliance_percentage']:.1f}% compliant")

if __name__ == "__main__":
    main()