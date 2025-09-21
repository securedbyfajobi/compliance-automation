#!/usr/bin/env python3
"""
PCI DSS Compliance Scanner
Automated validation of PCI DSS v4.0 requirements
"""

import json
import logging
import os
import re
import socket
import ssl
from datetime import datetime
from typing import Dict, List, Tuple

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PCIDSSScanner:
    """PCI DSS compliance scanner for payment card data protection"""

    def __init__(self):
        self.scan_results = {
            'timestamp': datetime.now().isoformat(),
            'framework': 'PCI DSS',
            'version': '4.0',
            'requirements': {},
            'network_security': {},
            'data_protection': {},
            'access_control': {},
            'summary': {
                'total_requirements': 0,
                'passed': 0,
                'failed': 0,
                'compliance_percentage': 0
            }
        }

    def check_requirement_1_firewall(self, directory: str = ".") -> Dict:
        """Requirement 1: Install and maintain network security controls"""
        logger.info("Checking PCI DSS Requirement 1 - Firewall configuration...")

        firewall_patterns = [
            r'firewall.*configuration',
            r'network.*security.*group',
            r'iptables',
            r'ufw.*enable',
            r'security.*group.*rules',
            r'network.*acl'
        ]

        firewall_config = self._check_patterns(directory, firewall_patterns)

        # Check for DMZ configuration
        dmz_patterns = [
            r'dmz.*configuration',
            r'perimeter.*network',
            r'network.*segmentation',
            r'cardholder.*data.*environment'
        ]

        dmz_config = self._check_patterns(directory, dmz_patterns)

        if firewall_config and dmz_config:
            self.scan_results['requirements']['REQ_1'] = {
                'status': 'PASS',
                'description': 'Network security controls implemented',
                'details': 'Firewall and DMZ configuration found'
            }
            self.scan_results['summary']['passed'] += 1
        else:
            self.scan_results['requirements']['REQ_1'] = {
                'status': 'FAIL',
                'description': 'Network security controls incomplete',
                'details': f'Firewall: {firewall_config}, DMZ: {dmz_config}',
                'remediation': 'Implement comprehensive firewall and network segmentation'
            }
            self.scan_results['summary']['failed'] += 1

        self.scan_results['summary']['total_requirements'] += 1
        return self.scan_results['requirements']['REQ_1']

    def check_requirement_2_default_passwords(self, directory: str = ".") -> Dict:
        """Requirement 2: Apply secure configurations to all system components"""
        logger.info("Checking PCI DSS Requirement 2 - Default passwords and configurations...")

        # Check for default password removal
        default_pwd_patterns = [
            r'default.*password.*change',
            r'admin.*password.*policy',
            r'system.*hardening',
            r'secure.*configuration',
            r'baseline.*configuration'
        ]

        secure_config = self._check_patterns(directory, default_pwd_patterns)

        # Check for unnecessary services removal
        service_patterns = [
            r'unnecessary.*services.*disabled',
            r'service.*hardening',
            r'minimal.*installation',
            r'service.*inventory'
        ]

        service_hardening = self._check_patterns(directory, service_patterns)

        if secure_config and service_hardening:
            self.scan_results['requirements']['REQ_2'] = {
                'status': 'PASS',
                'description': 'Secure configurations applied',
                'details': 'Configuration hardening and service management found'
            }
            self.scan_results['summary']['passed'] += 1
        else:
            self.scan_results['requirements']['REQ_2'] = {
                'status': 'FAIL',
                'description': 'Secure configurations incomplete',
                'details': f'Config: {secure_config}, Services: {service_hardening}',
                'remediation': 'Implement secure configuration standards and service hardening'
            }
            self.scan_results['summary']['failed'] += 1

        self.scan_results['summary']['total_requirements'] += 1
        return self.scan_results['requirements']['REQ_2']

    def check_requirement_3_cardholder_data(self, directory: str = ".") -> Dict:
        """Requirement 3: Protect stored cardholder data"""
        logger.info("Checking PCI DSS Requirement 3 - Cardholder data protection...")

        # Check for data encryption
        encryption_patterns = [
            r'cardholder.*data.*encryption',
            r'payment.*data.*encryption',
            r'credit.*card.*encryption',
            r'aes.*256.*encryption',
            r'field.*level.*encryption',
            r'tokenization'
        ]

        data_encryption = self._check_patterns(directory, encryption_patterns)

        # Check for PAN masking
        masking_patterns = [
            r'pan.*masking',
            r'card.*number.*masking',
            r'primary.*account.*number.*mask',
            r'payment.*card.*mask'
        ]

        pan_masking = self._check_patterns(directory, masking_patterns)

        # Check for key management
        key_mgmt_patterns = [
            r'key.*management',
            r'encryption.*key.*rotation',
            r'key.*escrow',
            r'hsm.*hardware.*security.*module'
        ]

        key_management = self._check_patterns(directory, key_mgmt_patterns)

        protection_score = sum([data_encryption, pan_masking, key_management])

        if protection_score >= 2:
            self.scan_results['requirements']['REQ_3'] = {
                'status': 'PASS',
                'description': 'Cardholder data protection implemented',
                'details': f'Encryption: {data_encryption}, Masking: {pan_masking}, Key Mgmt: {key_management}'
            }
            self.scan_results['summary']['passed'] += 1
        else:
            self.scan_results['requirements']['REQ_3'] = {
                'status': 'FAIL',
                'description': 'Insufficient cardholder data protection',
                'details': f'Score: {protection_score}/3',
                'remediation': 'Implement comprehensive data encryption, masking, and key management'
            }
            self.scan_results['summary']['failed'] += 1

        self.scan_results['summary']['total_requirements'] += 1
        return self.scan_results['requirements']['REQ_3']

    def check_requirement_4_data_transmission(self, directory: str = ".") -> Dict:
        """Requirement 4: Protect cardholder data with strong cryptography during transmission"""
        logger.info("Checking PCI DSS Requirement 4 - Data transmission security...")

        # Check for strong cryptography
        crypto_patterns = [
            r'tls.*1\.[23]',
            r'ssl.*tls.*encryption',
            r'transport.*layer.*security',
            r'https.*only',
            r'secure.*transmission'
        ]

        strong_crypto = self._check_patterns(directory, crypto_patterns)

        # Check for wireless security
        wireless_patterns = [
            r'wpa.*2.*enterprise',
            r'wireless.*security',
            r'wifi.*encryption',
            r'802\.1x.*authentication'
        ]

        wireless_security = self._check_patterns(directory, wireless_patterns)

        if strong_crypto:
            self.scan_results['requirements']['REQ_4'] = {
                'status': 'PASS',
                'description': 'Strong cryptography for data transmission',
                'details': f'Crypto: {strong_crypto}, Wireless: {wireless_security}'
            }
            self.scan_results['summary']['passed'] += 1
        else:
            self.scan_results['requirements']['REQ_4'] = {
                'status': 'FAIL',
                'description': 'Weak or missing transmission encryption',
                'remediation': 'Implement TLS 1.2+ for all cardholder data transmission'
            }
            self.scan_results['summary']['failed'] += 1

        self.scan_results['summary']['total_requirements'] += 1
        return self.scan_results['requirements']['REQ_4']

    def check_requirement_6_secure_development(self, directory: str = ".") -> Dict:
        """Requirement 6: Develop and maintain secure systems and software"""
        logger.info("Checking PCI DSS Requirement 6 - Secure development...")

        # Check for secure coding practices
        secure_coding_patterns = [
            r'secure.*coding.*guidelines',
            r'input.*validation',
            r'sql.*injection.*prevention',
            r'xss.*prevention',
            r'security.*code.*review'
        ]

        secure_coding = self._check_patterns(directory, secure_coding_patterns)

        # Check for vulnerability management
        vuln_mgmt_patterns = [
            r'vulnerability.*scanning',
            r'security.*testing',
            r'penetration.*testing',
            r'security.*assessment'
        ]

        vuln_management = self._check_patterns(directory, vuln_mgmt_patterns)

        # Check for change control
        change_control_patterns = [
            r'change.*control.*process',
            r'deployment.*procedures',
            r'rollback.*procedures',
            r'testing.*procedures'
        ]

        change_control = self._check_patterns(directory, change_control_patterns)

        development_score = sum([secure_coding, vuln_management, change_control])

        if development_score >= 2:
            self.scan_results['requirements']['REQ_6'] = {
                'status': 'PASS',
                'description': 'Secure development practices implemented',
                'details': f'Secure Coding: {secure_coding}, Vuln Mgmt: {vuln_management}, Change Control: {change_control}'
            }
            self.scan_results['summary']['passed'] += 1
        else:
            self.scan_results['requirements']['REQ_6'] = {
                'status': 'FAIL',
                'description': 'Insufficient secure development practices',
                'details': f'Score: {development_score}/3',
                'remediation': 'Implement comprehensive secure development lifecycle'
            }
            self.scan_results['summary']['failed'] += 1

        self.scan_results['summary']['total_requirements'] += 1
        return self.scan_results['requirements']['REQ_6']

    def check_requirement_7_access_control(self, directory: str = ".") -> Dict:
        """Requirement 7: Restrict access to cardholder data by business need to know"""
        logger.info("Checking PCI DSS Requirement 7 - Access control...")

        # Check for role-based access control
        rbac_patterns = [
            r'role.*based.*access.*control',
            r'rbac.*implementation',
            r'access.*control.*list',
            r'privilege.*management',
            r'least.*privilege'
        ]

        rbac_implementation = self._check_patterns(directory, rbac_patterns)

        # Check for access reviews
        access_review_patterns = [
            r'access.*review.*process',
            r'user.*access.*audit',
            r'privilege.*review',
            r'access.*certification'
        ]

        access_reviews = self._check_patterns(directory, access_review_patterns)

        if rbac_implementation and access_reviews:
            self.scan_results['requirements']['REQ_7'] = {
                'status': 'PASS',
                'description': 'Access control implemented',
                'details': 'RBAC and access review processes found'
            }
            self.scan_results['summary']['passed'] += 1
        else:
            self.scan_results['requirements']['REQ_7'] = {
                'status': 'FAIL',
                'description': 'Insufficient access control',
                'details': f'RBAC: {rbac_implementation}, Reviews: {access_reviews}',
                'remediation': 'Implement role-based access control and regular access reviews'
            }
            self.scan_results['summary']['failed'] += 1

        self.scan_results['summary']['total_requirements'] += 1
        return self.scan_results['requirements']['REQ_7']

    def check_requirement_8_authentication(self, directory: str = ".") -> Dict:
        """Requirement 8: Identify users and authenticate access to system components"""
        logger.info("Checking PCI DSS Requirement 8 - Authentication...")

        # Check for multi-factor authentication
        mfa_patterns = [
            r'multi.*factor.*authentication',
            r'two.*factor.*authentication',
            r'mfa.*implementation',
            r'2fa.*required',
            r'authentication.*factors'
        ]

        mfa_implementation = self._check_patterns(directory, mfa_patterns)

        # Check for password policies
        password_patterns = [
            r'password.*policy',
            r'password.*complexity',
            r'password.*length',
            r'password.*expiration',
            r'account.*lockout'
        ]

        password_policies = self._check_patterns(directory, password_patterns)

        # Check for unique user IDs
        user_id_patterns = [
            r'unique.*user.*id',
            r'user.*identification',
            r'individual.*accountability',
            r'user.*provisioning'
        ]

        unique_users = self._check_patterns(directory, user_id_patterns)

        auth_score = sum([mfa_implementation, password_policies, unique_users])

        if auth_score >= 2:
            self.scan_results['requirements']['REQ_8'] = {
                'status': 'PASS',
                'description': 'Strong authentication implemented',
                'details': f'MFA: {mfa_implementation}, Passwords: {password_policies}, Unique IDs: {unique_users}'
            }
            self.scan_results['summary']['passed'] += 1
        else:
            self.scan_results['requirements']['REQ_8'] = {
                'status': 'FAIL',
                'description': 'Insufficient authentication controls',
                'details': f'Score: {auth_score}/3',
                'remediation': 'Implement MFA, strong password policies, and unique user identification'
            }
            self.scan_results['summary']['failed'] += 1

        self.scan_results['summary']['total_requirements'] += 1
        return self.scan_results['requirements']['REQ_8']

    def check_requirement_10_logging(self, directory: str = ".") -> Dict:
        """Requirement 10: Log and monitor all access to network resources and cardholder data"""
        logger.info("Checking PCI DSS Requirement 10 - Logging and monitoring...")

        # Check for comprehensive logging
        logging_patterns = [
            r'audit.*logging',
            r'security.*event.*logging',
            r'access.*logging',
            r'transaction.*logging',
            r'log.*management'
        ]

        comprehensive_logging = self._check_patterns(directory, logging_patterns)

        # Check for log monitoring
        monitoring_patterns = [
            r'log.*monitoring',
            r'siem.*implementation',
            r'security.*monitoring',
            r'log.*analysis',
            r'real.*time.*monitoring'
        ]

        log_monitoring = self._check_patterns(directory, monitoring_patterns)

        # Check for log protection
        log_protection_patterns = [
            r'log.*integrity',
            r'log.*encryption',
            r'log.*backup',
            r'log.*retention'
        ]

        log_protection = self._check_patterns(directory, log_protection_patterns)

        logging_score = sum([comprehensive_logging, log_monitoring, log_protection])

        if logging_score >= 2:
            self.scan_results['requirements']['REQ_10'] = {
                'status': 'PASS',
                'description': 'Comprehensive logging and monitoring',
                'details': f'Logging: {comprehensive_logging}, Monitoring: {log_monitoring}, Protection: {log_protection}'
            }
            self.scan_results['summary']['passed'] += 1
        else:
            self.scan_results['requirements']['REQ_10'] = {
                'status': 'FAIL',
                'description': 'Insufficient logging and monitoring',
                'details': f'Score: {logging_score}/3',
                'remediation': 'Implement comprehensive logging, monitoring, and log protection'
            }
            self.scan_results['summary']['failed'] += 1

        self.scan_results['summary']['total_requirements'] += 1
        return self.scan_results['requirements']['REQ_10']

    def check_requirement_11_security_testing(self, directory: str = ".") -> Dict:
        """Requirement 11: Test security of systems and networks regularly"""
        logger.info("Checking PCI DSS Requirement 11 - Security testing...")

        # Check for vulnerability scanning
        vuln_scan_patterns = [
            r'vulnerability.*scanning',
            r'network.*security.*scan',
            r'web.*application.*scan',
            r'penetration.*testing'
        ]

        vulnerability_scanning = self._check_patterns(directory, vuln_scan_patterns)

        # Check for intrusion detection
        ids_patterns = [
            r'intrusion.*detection',
            r'intrusion.*prevention',
            r'ids.*ips.*implementation',
            r'network.*monitoring'
        ]

        intrusion_detection = self._check_patterns(directory, ids_patterns)

        if vulnerability_scanning and intrusion_detection:
            self.scan_results['requirements']['REQ_11'] = {
                'status': 'PASS',
                'description': 'Security testing implemented',
                'details': 'Vulnerability scanning and intrusion detection found'
            }
            self.scan_results['summary']['passed'] += 1
        else:
            self.scan_results['requirements']['REQ_11'] = {
                'status': 'FAIL',
                'description': 'Insufficient security testing',
                'details': f'Vuln Scan: {vulnerability_scanning}, IDS: {intrusion_detection}',
                'remediation': 'Implement regular vulnerability scanning and intrusion detection'
            }
            self.scan_results['summary']['failed'] += 1

        self.scan_results['summary']['total_requirements'] += 1
        return self.scan_results['requirements']['REQ_11']

    def check_ssl_tls_configuration(self, hosts: List[str] = None) -> Dict:
        """Check SSL/TLS configuration for PCI DSS compliance"""
        logger.info("Checking SSL/TLS configuration...")

        if not hosts:
            hosts = ['localhost']

        ssl_results = {
            'compliant_hosts': [],
            'non_compliant_hosts': [],
            'issues': []
        }

        for host in hosts:
            try:
                context = ssl.create_default_context()
                with socket.create_connection((host, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        version = ssock.version()
                        cipher = ssock.cipher()

                        # Check for PCI DSS compliant protocols
                        if version in ['TLSv1.2', 'TLSv1.3']:
                            ssl_results['compliant_hosts'].append({
                                'host': host,
                                'version': version,
                                'cipher': cipher[0] if cipher else 'Unknown'
                            })
                        else:
                            ssl_results['non_compliant_hosts'].append({
                                'host': host,
                                'version': version,
                                'issue': 'Outdated TLS version'
                            })

            except Exception as e:
                ssl_results['issues'].append({
                    'host': host,
                    'error': str(e)
                })

        self.scan_results['network_security']['ssl_tls'] = ssl_results
        return ssl_results

    def _check_patterns(self, directory: str, patterns: List[str]) -> bool:
        """Check if any of the patterns are found in the directory"""
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith(('.py', '.js', '.java', '.md', '.yml', '.yaml', '.json', '.conf', '.ini')):
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

    def generate_compliance_report(self) -> Dict:
        """Generate comprehensive PCI DSS compliance report"""
        logger.info("Generating PCI DSS compliance report...")

        # Calculate compliance percentage
        if self.scan_results['summary']['total_requirements'] > 0:
            self.scan_results['summary']['compliance_percentage'] = (
                (self.scan_results['summary']['passed'] /
                 self.scan_results['summary']['total_requirements']) * 100
            )

        # Generate recommendations
        recommendations = []

        for req_id, req_data in self.scan_results['requirements'].items():
            if req_data.get('status') == 'FAIL':
                recommendations.append({
                    'requirement': req_id,
                    'issue': req_data.get('description'),
                    'remediation': req_data.get('remediation', 'Review and implement PCI DSS requirements')
                })

        self.scan_results['recommendations'] = recommendations

        return self.scan_results

    def run_full_scan(self, directory: str = ".", hosts: List[str] = None) -> Dict:
        """Run complete PCI DSS compliance scan"""
        logger.info("Starting PCI DSS compliance scan...")

        self.check_requirement_1_firewall(directory)
        self.check_requirement_2_default_passwords(directory)
        self.check_requirement_3_cardholder_data(directory)
        self.check_requirement_4_data_transmission(directory)
        self.check_requirement_6_secure_development(directory)
        self.check_requirement_7_access_control(directory)
        self.check_requirement_8_authentication(directory)
        self.check_requirement_10_logging(directory)
        self.check_requirement_11_security_testing(directory)

        # Network security checks
        if hosts:
            self.check_ssl_tls_configuration(hosts)

        return self.generate_compliance_report()

def main():
    """Main execution function"""
    scanner = PCIDSSScanner()
    results = scanner.run_full_scan()

    print(json.dumps(results, indent=2))

    # Save results
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"pci_dss_scan_report_{timestamp}.json"

    with open(filename, 'w') as f:
        json.dump(results, f, indent=2)

    logger.info(f"PCI DSS compliance scan complete. Report saved to {filename}")
    logger.info(f"Compliance score: {results['summary']['compliance_percentage']:.1f}%")

if __name__ == "__main__":
    main()