#!/usr/bin/env python3
"""
GDPR Compliance Validator
Automated validation of GDPR data protection requirements
"""

import json
import logging
import os
import re
from datetime import datetime
from typing import Dict, List, Tuple

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class GDPRValidator:
    """Validate GDPR compliance requirements"""

    def __init__(self):
        self.compliance_results = {
            'timestamp': datetime.now().isoformat(),
            'framework': 'GDPR',
            'version': '2018',
            'articles': {},
            'privacy_rights': {},
            'data_protection': {},
            'summary': {
                'total_checks': 0,
                'passed': 0,
                'failed': 0,
                'compliance_percentage': 0
            }
        }

    def check_data_inventory(self, data_directory: str = ".") -> Dict:
        """Check for comprehensive data inventory (Article 30)"""
        logger.info("Checking data inventory compliance...")

        inventory_files = [
            'data-inventory.json',
            'personal-data-registry.json',
            'data-mapping.json',
            'processing-activities.json'
        ]

        found_inventory = False
        for inventory_file in inventory_files:
            if os.path.exists(os.path.join(data_directory, inventory_file)):
                found_inventory = True
                break

        if found_inventory:
            self.compliance_results['articles']['Article_30'] = {
                'status': 'PASS',
                'description': 'Data inventory documentation found',
                'requirement': 'Records of processing activities'
            }
            self.compliance_results['summary']['passed'] += 1
        else:
            self.compliance_results['articles']['Article_30'] = {
                'status': 'FAIL',
                'description': 'No data inventory found',
                'requirement': 'Records of processing activities',
                'remediation': 'Create comprehensive data inventory'
            }
            self.compliance_results['summary']['failed'] += 1

        self.compliance_results['summary']['total_checks'] += 1
        return self.compliance_results['articles']['Article_30']

    def check_lawful_basis(self, code_directory: str = ".") -> Dict:
        """Check for lawful basis documentation (Article 6)"""
        logger.info("Checking lawful basis compliance...")

        # Search for lawful basis implementations
        lawful_basis_patterns = [
            r'consent.*processing',
            r'legitimate.*interest',
            r'legal.*obligation',
            r'vital.*interests',
            r'public.*task',
            r'contractual.*necessity'
        ]

        lawful_basis_found = False
        for root, dirs, files in os.walk(code_directory):
            for file in files:
                if file.endswith(('.py', '.js', '.java', '.md')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read().lower()
                            for pattern in lawful_basis_patterns:
                                if re.search(pattern, content):
                                    lawful_basis_found = True
                                    break
                    except (UnicodeDecodeError, PermissionError):
                        continue

                    if lawful_basis_found:
                        break
            if lawful_basis_found:
                break

        if lawful_basis_found:
            self.compliance_results['articles']['Article_6'] = {
                'status': 'PASS',
                'description': 'Lawful basis implementation found',
                'requirement': 'Lawful basis for processing'
            }
            self.compliance_results['summary']['passed'] += 1
        else:
            self.compliance_results['articles']['Article_6'] = {
                'status': 'FAIL',
                'description': 'No lawful basis implementation found',
                'requirement': 'Lawful basis for processing',
                'remediation': 'Implement and document lawful basis'
            }
            self.compliance_results['summary']['failed'] += 1

        self.compliance_results['summary']['total_checks'] += 1
        return self.compliance_results['articles']['Article_6']

    def check_consent_mechanisms(self, code_directory: str = ".") -> Dict:
        """Check for proper consent mechanisms (Article 7)"""
        logger.info("Checking consent mechanisms...")

        consent_patterns = [
            r'consent.*management',
            r'cookie.*consent',
            r'withdraw.*consent',
            r'consent.*record',
            r'opt.*in',
            r'consent.*form'
        ]

        consent_implementation = False
        consent_files = []

        for root, dirs, files in os.walk(code_directory):
            for file in files:
                if file.endswith(('.py', '.js', '.java', '.html', '.vue', '.tsx')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read().lower()
                            for pattern in consent_patterns:
                                if re.search(pattern, content):
                                    consent_implementation = True
                                    consent_files.append(file_path)
                                    break
                    except (UnicodeDecodeError, PermissionError):
                        continue

        if consent_implementation:
            self.compliance_results['articles']['Article_7'] = {
                'status': 'PASS',
                'description': f'Consent mechanisms found in {len(consent_files)} files',
                'requirement': 'Conditions for consent',
                'files': consent_files[:5]  # Limit to first 5 files
            }
            self.compliance_results['summary']['passed'] += 1
        else:
            self.compliance_results['articles']['Article_7'] = {
                'status': 'FAIL',
                'description': 'No consent mechanisms found',
                'requirement': 'Conditions for consent',
                'remediation': 'Implement consent management system'
            }
            self.compliance_results['summary']['failed'] += 1

        self.compliance_results['summary']['total_checks'] += 1
        return self.compliance_results['articles']['Article_7']

    def check_data_subject_rights(self, code_directory: str = ".") -> Dict:
        """Check implementation of data subject rights (Articles 15-22)"""
        logger.info("Checking data subject rights implementation...")

        rights_patterns = {
            'access': [r'data.*access', r'subject.*access.*request', r'sar.*endpoint'],
            'rectification': [r'data.*rectification', r'update.*personal.*data', r'correct.*data'],
            'erasure': [r'right.*erasure', r'delete.*personal.*data', r'forget.*me'],
            'portability': [r'data.*portability', r'export.*data', r'download.*data'],
            'objection': [r'object.*processing', r'opt.*out', r'unsubscribe'],
            'restriction': [r'restrict.*processing', r'limit.*processing']
        }

        implemented_rights = {}

        for right, patterns in rights_patterns.items():
            for root, dirs, files in os.walk(code_directory):
                for file in files:
                    if file.endswith(('.py', '.js', '.java', '.php')):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8') as f:
                                content = f.read().lower()
                                for pattern in patterns:
                                    if re.search(pattern, content):
                                        implemented_rights[right] = True
                                        break
                        except (UnicodeDecodeError, PermissionError):
                            continue
                        if right in implemented_rights:
                            break
                if right in implemented_rights:
                    break

        rights_count = len(implemented_rights)
        total_rights = len(rights_patterns)

        if rights_count >= 4:  # At least 4 out of 6 rights implemented
            self.compliance_results['privacy_rights']['data_subject_rights'] = {
                'status': 'PASS',
                'description': f'{rights_count}/{total_rights} data subject rights implemented',
                'implemented_rights': list(implemented_rights.keys())
            }
            self.compliance_results['summary']['passed'] += 1
        else:
            self.compliance_results['privacy_rights']['data_subject_rights'] = {
                'status': 'FAIL',
                'description': f'Only {rights_count}/{total_rights} data subject rights implemented',
                'implemented_rights': list(implemented_rights.keys()),
                'missing_rights': [right for right in rights_patterns.keys() if right not in implemented_rights],
                'remediation': 'Implement missing data subject rights'
            }
            self.compliance_results['summary']['failed'] += 1

        self.compliance_results['summary']['total_checks'] += 1
        return self.compliance_results['privacy_rights']['data_subject_rights']

    def check_privacy_by_design(self, code_directory: str = ".") -> Dict:
        """Check for privacy by design implementation (Article 25)"""
        logger.info("Checking privacy by design implementation...")

        privacy_patterns = [
            r'encryption.*personal.*data',
            r'pseudonymization',
            r'anonymization',
            r'data.*minimization',
            r'privacy.*impact.*assessment',
            r'purpose.*limitation',
            r'storage.*limitation'
        ]

        privacy_features = []

        for root, dirs, files in os.walk(code_directory):
            for file in files:
                if file.endswith(('.py', '.js', '.java', '.config', '.yml', '.yaml')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read().lower()
                            for pattern in privacy_patterns:
                                if re.search(pattern, content):
                                    privacy_features.append(pattern)
                    except (UnicodeDecodeError, PermissionError):
                        continue

        if len(privacy_features) >= 3:
            self.compliance_results['data_protection']['privacy_by_design'] = {
                'status': 'PASS',
                'description': f'{len(privacy_features)} privacy features implemented',
                'features': privacy_features
            }
            self.compliance_results['summary']['passed'] += 1
        else:
            self.compliance_results['data_protection']['privacy_by_design'] = {
                'status': 'FAIL',
                'description': f'Only {len(privacy_features)} privacy features found',
                'features': privacy_features,
                'remediation': 'Implement additional privacy by design measures'
            }
            self.compliance_results['summary']['failed'] += 1

        self.compliance_results['summary']['total_checks'] += 1
        return self.compliance_results['data_protection']['privacy_by_design']

    def check_breach_notification(self, code_directory: str = ".") -> Dict:
        """Check for breach notification procedures (Articles 33-34)"""
        logger.info("Checking breach notification procedures...")

        breach_patterns = [
            r'breach.*notification',
            r'incident.*response',
            r'data.*breach.*procedure',
            r'72.*hour.*notification',
            r'supervisory.*authority',
            r'breach.*log'
        ]

        breach_procedures = False

        for root, dirs, files in os.walk(code_directory):
            for file in files:
                if file.endswith(('.py', '.js', '.md', '.yml', '.yaml', '.json')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read().lower()
                            for pattern in breach_patterns:
                                if re.search(pattern, content):
                                    breach_procedures = True
                                    break
                    except (UnicodeDecodeError, PermissionError):
                        continue
                    if breach_procedures:
                        break
            if breach_procedures:
                break

        if breach_procedures:
            self.compliance_results['data_protection']['breach_notification'] = {
                'status': 'PASS',
                'description': 'Breach notification procedures found',
                'requirement': 'Personal data breach notification'
            }
            self.compliance_results['summary']['passed'] += 1
        else:
            self.compliance_results['data_protection']['breach_notification'] = {
                'status': 'FAIL',
                'description': 'No breach notification procedures found',
                'requirement': 'Personal data breach notification',
                'remediation': 'Implement breach notification procedures'
            }
            self.compliance_results['summary']['failed'] += 1

        self.compliance_results['summary']['total_checks'] += 1
        return self.compliance_results['data_protection']['breach_notification']

    def check_dpo_designation(self, code_directory: str = ".") -> Dict:
        """Check for Data Protection Officer designation (Articles 37-39)"""
        logger.info("Checking DPO designation...")

        dpo_patterns = [
            r'data.*protection.*officer',
            r'dpo.*contact',
            r'privacy.*officer',
            r'dpo@',
            r'data.*controller',
            r'data.*processor'
        ]

        dpo_found = False

        for root, dirs, files in os.walk(code_directory):
            for file in files:
                if file.endswith(('.md', '.html', '.txt', '.json')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read().lower()
                            for pattern in dpo_patterns:
                                if re.search(pattern, content):
                                    dpo_found = True
                                    break
                    except (UnicodeDecodeError, PermissionError):
                        continue
                    if dpo_found:
                        break
            if dpo_found:
                break

        if dpo_found:
            self.compliance_results['data_protection']['dpo_designation'] = {
                'status': 'PASS',
                'description': 'DPO designation or contact information found',
                'requirement': 'Data Protection Officer'
            }
            self.compliance_results['summary']['passed'] += 1
        else:
            self.compliance_results['data_protection']['dpo_designation'] = {
                'status': 'WARNING',
                'description': 'No DPO information found',
                'requirement': 'Data Protection Officer (if required)',
                'remediation': 'Designate DPO if processing meets criteria'
            }
            # Don't count as failed as DPO may not be required

        self.compliance_results['summary']['total_checks'] += 1
        return self.compliance_results['data_protection']['dpo_designation']

    def generate_compliance_report(self) -> Dict:
        """Generate comprehensive GDPR compliance report"""
        logger.info("Generating GDPR compliance report...")

        # Calculate compliance percentage
        if self.compliance_results['summary']['total_checks'] > 0:
            self.compliance_results['summary']['compliance_percentage'] = (
                (self.compliance_results['summary']['passed'] /
                 self.compliance_results['summary']['total_checks']) * 100
            )

        # Generate recommendations
        recommendations = []

        for section in ['articles', 'privacy_rights', 'data_protection']:
            for check, result in self.compliance_results.get(section, {}).items():
                if result.get('status') == 'FAIL':
                    recommendations.append({
                        'check': check,
                        'issue': result.get('description'),
                        'remediation': result.get('remediation', 'Review and implement requirements')
                    })

        self.compliance_results['recommendations'] = recommendations

        return self.compliance_results

    def run_full_assessment(self, directory: str = ".") -> Dict:
        """Run complete GDPR compliance assessment"""
        logger.info("Starting GDPR compliance assessment...")

        self.check_data_inventory(directory)
        self.check_lawful_basis(directory)
        self.check_consent_mechanisms(directory)
        self.check_data_subject_rights(directory)
        self.check_privacy_by_design(directory)
        self.check_breach_notification(directory)
        self.check_dpo_designation(directory)

        return self.generate_compliance_report()

def main():
    """Main execution function"""
    validator = GDPRValidator()
    results = validator.run_full_assessment()

    print(json.dumps(results, indent=2))

    # Save results
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"gdpr_compliance_report_{timestamp}.json"

    with open(filename, 'w') as f:
        json.dump(results, f, indent=2)

    logger.info(f"GDPR compliance assessment complete. Report saved to {filename}")
    logger.info(f"Compliance score: {results['summary']['compliance_percentage']:.1f}%")

if __name__ == "__main__":
    main()