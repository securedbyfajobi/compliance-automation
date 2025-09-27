#!/usr/bin/env python3
"""
NIST Cybersecurity Framework Validator
Automated validation of NIST CSF controls and implementation
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

class NISTFrameworkValidator:
    """Comprehensive NIST Cybersecurity Framework validator with AWS integration"""

    def __init__(self, region: str = 'eu-west-2', config_file: Optional[str] = None):
        self.region = region
        self.config = self._load_config(config_file)

        # AWS Clients for comprehensive security assessment
        self.ec2 = boto3.client('ec2', region_name=region)
        self.s3 = boto3.client('s3')
        self.iam = boto3.client('iam')
        self.cloudtrail = boto3.client('cloudtrail', region_name=region)
        self.cloudwatch = boto3.client('cloudwatch', region_name=region)
        self.config_client = boto3.client('config', region_name=region)
        self.guardduty = boto3.client('guardduty', region_name=region)
        self.securityhub = boto3.client('securityhub', region_name=region)
        self.inspector = boto3.client('inspector2', region_name=region)
        self.kms = boto3.client('kms', region_name=region)
        self.rds = boto3.client('rds', region_name=region)

        self.framework_results = {
            'timestamp': datetime.now().isoformat(),
            'framework': 'NIST Cybersecurity Framework',
            'version': '2.0',
            'region': region,
            'functions': {
                'identify': {'controls': {}, 'score': 0, 'total': 0, 'aws_checks': {}},
                'protect': {'controls': {}, 'score': 0, 'total': 0, 'aws_checks': {}},
                'detect': {'controls': {}, 'score': 0, 'total': 0, 'aws_checks': {}},
                'respond': {'controls': {}, 'score': 0, 'total': 0, 'aws_checks': {}},
                'recover': {'controls': {}, 'score': 0, 'total': 0, 'aws_checks': {}}
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
            'assessment_scope': ['infrastructure', 'applications', 'data'],
            'risk_tolerance': 'medium',
            'compliance_threshold': 80,
            'aws_regions': ['eu-west-2'],
            'excluded_services': []
        }

        if config_file and os.path.exists(config_file):
            with open(config_file, 'r') as f:
                user_config = yaml.safe_load(f)
                default_config.update(user_config)

        return default_config

    def check_identify_function(self, directory: str = ".") -> Dict:
        """Check IDENTIFY function implementation"""
        logger.info("Checking NIST Identify function...")

        # ID.AM - Asset Management
        asset_patterns = [
            r'asset.*inventory',
            r'device.*management',
            r'software.*inventory',
            r'network.*diagram',
            r'data.*classification'
        ]

        asset_management = self._check_patterns(directory, asset_patterns)
        self.framework_results['functions']['identify']['controls']['ID.AM'] = {
            'status': 'PASS' if asset_management else 'FAIL',
            'description': 'Asset management controls',
            'found': asset_management
        }

        # ID.BE - Business Environment
        business_patterns = [
            r'business.*continuity',
            r'critical.*functions',
            r'supply.*chain',
            r'organizational.*roles'
        ]

        business_environment = self._check_patterns(directory, business_patterns)
        self.framework_results['functions']['identify']['controls']['ID.BE'] = {
            'status': 'PASS' if business_environment else 'FAIL',
            'description': 'Business environment understanding',
            'found': business_environment
        }

        # ID.GV - Governance
        governance_patterns = [
            r'information.*security.*policy',
            r'risk.*management.*strategy',
            r'governance.*framework',
            r'security.*roles.*responsibilities'
        ]

        governance = self._check_patterns(directory, governance_patterns)
        self.framework_results['functions']['identify']['controls']['ID.GV'] = {
            'status': 'PASS' if governance else 'FAIL',
            'description': 'Governance programs',
            'found': governance
        }

        # ID.RA - Risk Assessment
        risk_patterns = [
            r'risk.*assessment',
            r'vulnerability.*scan',
            r'threat.*analysis',
            r'risk.*register'
        ]

        risk_assessment = self._check_patterns(directory, risk_patterns)
        self.framework_results['functions']['identify']['controls']['ID.RA'] = {
            'status': 'PASS' if risk_assessment else 'FAIL',
            'description': 'Risk assessment processes',
            'found': risk_assessment
        }

        # ID.RM - Risk Management Strategy
        risk_mgmt_patterns = [
            r'risk.*tolerance',
            r'risk.*appetite',
            r'risk.*criteria',
            r'risk.*priorities'
        ]

        risk_management = self._check_patterns(directory, risk_mgmt_patterns)
        self.framework_results['functions']['identify']['controls']['ID.RM'] = {
            'status': 'PASS' if risk_management else 'FAIL',
            'description': 'Risk management strategy',
            'found': risk_management
        }

        # ID.SC - Supply Chain Risk Management
        supply_chain_patterns = [
            r'vendor.*assessment',
            r'third.*party.*risk',
            r'supplier.*security',
            r'supply.*chain.*security'
        ]

        supply_chain = self._check_patterns(directory, supply_chain_patterns)
        self.framework_results['functions']['identify']['controls']['ID.SC'] = {
            'status': 'PASS' if supply_chain else 'FAIL',
            'description': 'Supply chain risk management',
            'found': supply_chain
        }

        # Calculate Identify function score
        passed_controls = sum(1 for control in self.framework_results['functions']['identify']['controls'].values()
                             if control['status'] == 'PASS')
        total_controls = len(self.framework_results['functions']['identify']['controls'])

        self.framework_results['functions']['identify']['score'] = (passed_controls / total_controls) * 100
        self.framework_results['functions']['identify']['total'] = total_controls

        # AWS-specific checks for IDENTIFY function
        aws_identify_checks = self._run_aws_identify_checks()
        self.framework_results['functions']['identify']['aws_checks'] = aws_identify_checks

        return self.framework_results['functions']['identify']

    def _run_aws_identify_checks(self) -> Dict:
        """Run AWS-specific checks for IDENTIFY function"""
        checks = {}

        # ID.AM - Asset Management via AWS Config
        try:
            config_rules = self.config_client.describe_config_rules()['ConfigRules']
            asset_mgmt_rules = [
                rule for rule in config_rules
                if any(keyword in rule['ConfigRuleName'].lower()
                      for keyword in ['asset', 'inventory', 'tagging'])
            ]

            checks['asset_management'] = {
                'status': 'Implemented' if asset_mgmt_rules else 'Not Implemented',
                'description': f'AWS Config rules for asset management: {len(asset_mgmt_rules)}',
                'compliant': len(asset_mgmt_rules) > 0
            }
        except Exception as e:
            checks['asset_management'] = {
                'status': 'Error',
                'description': f'Error checking AWS Config: {str(e)}',
                'compliant': False
            }

        # ID.RA - Risk Assessment via Security Hub
        try:
            security_hub_enabled = False
            findings_count = 0

            try:
                findings = self.securityhub.get_findings(MaxResults=1)
                security_hub_enabled = True
                findings_count = len(findings.get('Findings', []))
            except:
                pass

            checks['risk_assessment'] = {
                'status': 'Implemented' if security_hub_enabled else 'Not Implemented',
                'description': f'Security Hub enabled for centralized findings: {security_hub_enabled}',
                'compliant': security_hub_enabled
            }
        except Exception as e:
            checks['risk_assessment'] = {
                'status': 'Error',
                'description': f'Error checking Security Hub: {str(e)}',
                'compliant': False
            }

        return checks

    def check_protect_function(self, directory: str = ".") -> Dict:
        """Check PROTECT function implementation"""
        logger.info("Checking NIST Protect function...")

        # PR.AC - Identity Management and Access Control
        access_patterns = [
            r'identity.*management',
            r'access.*control',
            r'authentication',
            r'authorization',
            r'multi.*factor.*authentication',
            r'rbac|role.*based.*access'
        ]

        access_control = self._check_patterns(directory, access_patterns)
        self.framework_results['functions']['protect']['controls']['PR.AC'] = {
            'status': 'PASS' if access_control else 'FAIL',
            'description': 'Identity management and access control',
            'found': access_control
        }

        # PR.AT - Awareness and Training
        training_patterns = [
            r'security.*awareness',
            r'security.*training',
            r'phishing.*simulation',
            r'security.*education'
        ]

        awareness_training = self._check_patterns(directory, training_patterns)
        self.framework_results['functions']['protect']['controls']['PR.AT'] = {
            'status': 'PASS' if awareness_training else 'FAIL',
            'description': 'Awareness and training programs',
            'found': awareness_training
        }

        # PR.DS - Data Security
        data_security_patterns = [
            r'data.*encryption',
            r'data.*classification',
            r'data.*loss.*prevention',
            r'backup.*and.*recovery',
            r'data.*integrity'
        ]

        data_security = self._check_patterns(directory, data_security_patterns)
        self.framework_results['functions']['protect']['controls']['PR.DS'] = {
            'status': 'PASS' if data_security else 'FAIL',
            'description': 'Data security controls',
            'found': data_security
        }

        # PR.IP - Information Protection Processes and Procedures
        info_protection_patterns = [
            r'configuration.*management',
            r'system.*development.*lifecycle',
            r'secure.*coding',
            r'maintenance.*procedures'
        ]

        info_protection = self._check_patterns(directory, info_protection_patterns)
        self.framework_results['functions']['protect']['controls']['PR.IP'] = {
            'status': 'PASS' if info_protection else 'FAIL',
            'description': 'Information protection processes',
            'found': info_protection
        }

        # PR.MA - Maintenance
        maintenance_patterns = [
            r'preventive.*maintenance',
            r'predictive.*maintenance',
            r'maintenance.*logging',
            r'remote.*maintenance'
        ]

        maintenance = self._check_patterns(directory, maintenance_patterns)
        self.framework_results['functions']['protect']['controls']['PR.MA'] = {
            'status': 'PASS' if maintenance else 'FAIL',
            'description': 'Maintenance controls',
            'found': maintenance
        }

        # PR.PT - Protective Technology
        protective_tech_patterns = [
            r'firewall',
            r'intrusion.*prevention',
            r'antivirus',
            r'endpoint.*protection',
            r'network.*segmentation'
        ]

        protective_tech = self._check_patterns(directory, protective_tech_patterns)
        self.framework_results['functions']['protect']['controls']['PR.PT'] = {
            'status': 'PASS' if protective_tech else 'FAIL',
            'description': 'Protective technology',
            'found': protective_tech
        }

        # Calculate Protect function score
        passed_controls = sum(1 for control in self.framework_results['functions']['protect']['controls'].values()
                             if control['status'] == 'PASS')
        total_controls = len(self.framework_results['functions']['protect']['controls'])

        self.framework_results['functions']['protect']['score'] = (passed_controls / total_controls) * 100
        self.framework_results['functions']['protect']['total'] = total_controls

        # AWS-specific checks for PROTECT function
        aws_protect_checks = self._run_aws_protect_checks()
        self.framework_results['functions']['protect']['aws_checks'] = aws_protect_checks

        return self.framework_results['functions']['protect']

    def _run_aws_protect_checks(self) -> Dict:
        """Run AWS-specific checks for PROTECT function"""
        checks = {}

        # PR.AC - Access Control via IAM
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

            access_score = (mfa_coverage >= 90) * 50 + password_policy_exists * 50

            checks['access_control'] = {
                'status': 'Implemented' if access_score >= 80 else 'Partial' if access_score >= 40 else 'Not Implemented',
                'description': f'IAM access controls: MFA {mfa_coverage:.1f}%, Password Policy: {password_policy_exists}',
                'compliant': access_score >= 80
            }
        except Exception as e:
            checks['access_control'] = {
                'status': 'Error',
                'description': f'Error checking IAM access controls: {str(e)}',
                'compliant': False
            }

        # PR.DS - Data Security via S3 encryption
        try:
            buckets = self.s3.list_buckets()['Buckets']
            encrypted_buckets = 0

            for bucket in buckets:
                try:
                    self.s3.get_bucket_encryption(Bucket=bucket['Name'])
                    encrypted_buckets += 1
                except:
                    pass

            encryption_rate = (encrypted_buckets / len(buckets)) * 100 if buckets else 100

            checks['data_security'] = {
                'status': 'Implemented' if encryption_rate >= 95 else 'Partial' if encryption_rate >= 70 else 'Not Implemented',
                'description': f'S3 bucket encryption: {encryption_rate:.1f}% encrypted',
                'compliant': encryption_rate >= 95
            }
        except Exception as e:
            checks['data_security'] = {
                'status': 'Error',
                'description': f'Error checking S3 encryption: {str(e)}',
                'compliant': False
            }

        # PR.PT - Protective Technology via Security Groups
        try:
            security_groups = self.ec2.describe_security_groups()['SecurityGroups']
            restrictive_sgs = 0

            for sg in security_groups:
                if sg['GroupName'] == 'default':
                    # Check if default SG has no inbound rules
                    if not sg['IpPermissions']:
                        restrictive_sgs += 1
                else:
                    # Check for overly permissive rules
                    has_wide_open = any(
                        rule.get('IpRanges', [{}])[0].get('CidrIp') == '0.0.0.0/0'
                        for rule in sg.get('IpPermissions', [])
                        if rule.get('IpRanges')
                    )
                    if not has_wide_open:
                        restrictive_sgs += 1

            sg_compliance = (restrictive_sgs / len(security_groups)) * 100 if security_groups else 100

            checks['protective_technology'] = {
                'status': 'Implemented' if sg_compliance >= 80 else 'Partial' if sg_compliance >= 60 else 'Not Implemented',
                'description': f'Security Groups compliance: {sg_compliance:.1f}% restrictive',
                'compliant': sg_compliance >= 80
            }
        except Exception as e:
            checks['protective_technology'] = {
                'status': 'Error',
                'description': f'Error checking Security Groups: {str(e)}',
                'compliant': False
            }

        return checks

    def check_detect_function(self, directory: str = ".") -> Dict:
        """Check DETECT function implementation"""
        logger.info("Checking NIST Detect function...")

        # DE.AE - Anomalies and Events
        anomaly_patterns = [
            r'anomaly.*detection',
            r'behavioral.*analysis',
            r'baseline.*monitoring',
            r'event.*correlation'
        ]

        anomalies_events = self._check_patterns(directory, anomaly_patterns)
        self.framework_results['functions']['detect']['controls']['DE.AE'] = {
            'status': 'PASS' if anomalies_events else 'FAIL',
            'description': 'Anomalies and events detection',
            'found': anomalies_events
        }

        # DE.CM - Security Continuous Monitoring
        monitoring_patterns = [
            r'continuous.*monitoring',
            r'security.*monitoring',
            r'log.*monitoring',
            r'network.*monitoring',
            r'vulnerability.*monitoring'
        ]

        continuous_monitoring = self._check_patterns(directory, monitoring_patterns)
        self.framework_results['functions']['detect']['controls']['DE.CM'] = {
            'status': 'PASS' if continuous_monitoring else 'FAIL',
            'description': 'Security continuous monitoring',
            'found': continuous_monitoring
        }

        # DE.DP - Detection Processes
        detection_processes_patterns = [
            r'detection.*procedures',
            r'security.*operations.*center',
            r'incident.*detection',
            r'threat.*hunting'
        ]

        detection_processes = self._check_patterns(directory, detection_processes_patterns)
        self.framework_results['functions']['detect']['controls']['DE.DP'] = {
            'status': 'PASS' if detection_processes else 'FAIL',
            'description': 'Detection processes and procedures',
            'found': detection_processes
        }

        # Calculate Detect function score
        passed_controls = sum(1 for control in self.framework_results['functions']['detect']['controls'].values()
                             if control['status'] == 'PASS')
        total_controls = len(self.framework_results['functions']['detect']['controls'])

        self.framework_results['functions']['detect']['score'] = (passed_controls / total_controls) * 100
        self.framework_results['functions']['detect']['total'] = total_controls

        # AWS-specific checks for DETECT function
        aws_detect_checks = self._run_aws_detect_checks()
        self.framework_results['functions']['detect']['aws_checks'] = aws_detect_checks

        return self.framework_results['functions']['detect']

    def _run_aws_detect_checks(self) -> Dict:
        """Run AWS-specific checks for DETECT function"""
        checks = {}

        # DE.CM - Continuous Monitoring via CloudTrail
        try:
            trails = self.cloudtrail.describe_trails()['trailList']
            active_trails = []

            for trail in trails:
                status = self.cloudtrail.get_trail_status(Name=trail['TrailARN'])
                if status['IsLogging']:
                    active_trails.append(trail)

            # Check for multi-region and log file validation
            global_trails = [t for t in active_trails if t.get('IsMultiRegionTrail', False)]
            validated_trails = [t for t in active_trails if t.get('LogFileValidationEnabled', False)]

            monitoring_score = (
                (len(active_trails) > 0) * 40 +
                (len(global_trails) > 0) * 30 +
                (len(validated_trails) > 0) * 30
            )

            checks['continuous_monitoring'] = {
                'status': 'Implemented' if monitoring_score >= 80 else 'Partial' if monitoring_score >= 50 else 'Not Implemented',
                'description': f'CloudTrail monitoring: {len(active_trails)} active, {len(global_trails)} global, {len(validated_trails)} validated',
                'compliant': monitoring_score >= 80
            }
        except Exception as e:
            checks['continuous_monitoring'] = {
                'status': 'Error',
                'description': f'Error checking CloudTrail: {str(e)}',
                'compliant': False
            }

        # DE.AE - Anomaly Detection via GuardDuty
        try:
            detectors = self.guardduty.list_detectors()['DetectorIds']
            active_detectors = []

            for detector_id in detectors:
                detector = self.guardduty.get_detector(DetectorId=detector_id)
                if detector['Status'] == 'ENABLED':
                    active_detectors.append(detector_id)

            checks['anomaly_detection'] = {
                'status': 'Implemented' if active_detectors else 'Not Implemented',
                'description': f'GuardDuty anomaly detection: {len(active_detectors)} active detectors',
                'compliant': len(active_detectors) > 0
            }
        except Exception as e:
            checks['anomaly_detection'] = {
                'status': 'Error',
                'description': f'Error checking GuardDuty: {str(e)}',
                'compliant': False
            }

        return checks

    def check_respond_function(self, directory: str = ".") -> Dict:
        """Check RESPOND function implementation"""
        logger.info("Checking NIST Respond function...")

        # RS.RP - Response Planning
        response_planning_patterns = [
            r'incident.*response.*plan',
            r'response.*procedures',
            r'emergency.*response',
            r'business.*continuity.*plan'
        ]

        response_planning = self._check_patterns(directory, response_planning_patterns)
        self.framework_results['functions']['respond']['controls']['RS.RP'] = {
            'status': 'PASS' if response_planning else 'FAIL',
            'description': 'Response planning',
            'found': response_planning
        }

        # RS.CO - Communications
        communications_patterns = [
            r'incident.*communication',
            r'stakeholder.*notification',
            r'media.*relations',
            r'customer.*notification'
        ]

        communications = self._check_patterns(directory, communications_patterns)
        self.framework_results['functions']['respond']['controls']['RS.CO'] = {
            'status': 'PASS' if communications else 'FAIL',
            'description': 'Response communications',
            'found': communications
        }

        # RS.AN - Analysis
        analysis_patterns = [
            r'forensic.*analysis',
            r'root.*cause.*analysis',
            r'impact.*assessment',
            r'incident.*analysis'
        ]

        analysis = self._check_patterns(directory, analysis_patterns)
        self.framework_results['functions']['respond']['controls']['RS.AN'] = {
            'status': 'PASS' if analysis else 'FAIL',
            'description': 'Response analysis',
            'found': analysis
        }

        # RS.MI - Mitigation
        mitigation_patterns = [
            r'containment.*procedures',
            r'mitigation.*strategies',
            r'system.*isolation',
            r'threat.*mitigation'
        ]

        mitigation = self._check_patterns(directory, mitigation_patterns)
        self.framework_results['functions']['respond']['controls']['RS.MI'] = {
            'status': 'PASS' if mitigation else 'FAIL',
            'description': 'Response mitigation',
            'found': mitigation
        }

        # RS.IM - Improvements
        improvements_patterns = [
            r'lessons.*learned',
            r'process.*improvement',
            r'response.*optimization',
            r'post.*incident.*review'
        ]

        improvements = self._check_patterns(directory, improvements_patterns)
        self.framework_results['functions']['respond']['controls']['RS.IM'] = {
            'status': 'PASS' if improvements else 'FAIL',
            'description': 'Response improvements',
            'found': improvements
        }

        # Calculate Respond function score
        passed_controls = sum(1 for control in self.framework_results['functions']['respond']['controls'].values()
                             if control['status'] == 'PASS')
        total_controls = len(self.framework_results['functions']['respond']['controls'])

        self.framework_results['functions']['respond']['score'] = (passed_controls / total_controls) * 100
        self.framework_results['functions']['respond']['total'] = total_controls

        return self.framework_results['functions']['respond']

    def check_recover_function(self, directory: str = ".") -> Dict:
        """Check RECOVER function implementation"""
        logger.info("Checking NIST Recover function...")

        # RC.RP - Recovery Planning
        recovery_planning_patterns = [
            r'recovery.*plan',
            r'disaster.*recovery',
            r'business.*continuity',
            r'backup.*procedures'
        ]

        recovery_planning = self._check_patterns(directory, recovery_planning_patterns)
        self.framework_results['functions']['recover']['controls']['RC.RP'] = {
            'status': 'PASS' if recovery_planning else 'FAIL',
            'description': 'Recovery planning',
            'found': recovery_planning
        }

        # RC.IM - Improvements
        recovery_improvements_patterns = [
            r'recovery.*testing',
            r'recovery.*optimization',
            r'recovery.*lessons.*learned',
            r'recovery.*process.*improvement'
        ]

        recovery_improvements = self._check_patterns(directory, recovery_improvements_patterns)
        self.framework_results['functions']['recover']['controls']['RC.IM'] = {
            'status': 'PASS' if recovery_improvements else 'FAIL',
            'description': 'Recovery improvements',
            'found': recovery_improvements
        }

        # RC.CO - Communications
        recovery_communications_patterns = [
            r'recovery.*communication',
            r'restoration.*notification',
            r'service.*restoration.*updates'
        ]

        recovery_communications = self._check_patterns(directory, recovery_communications_patterns)
        self.framework_results['functions']['recover']['controls']['RC.CO'] = {
            'status': 'PASS' if recovery_communications else 'FAIL',
            'description': 'Recovery communications',
            'found': recovery_communications
        }

        # Calculate Recover function score
        passed_controls = sum(1 for control in self.framework_results['functions']['recover']['controls'].values()
                             if control['status'] == 'PASS')
        total_controls = len(self.framework_results['functions']['recover']['controls'])

        self.framework_results['functions']['recover']['score'] = (passed_controls / total_controls) * 100
        self.framework_results['functions']['recover']['total'] = total_controls

        return self.framework_results['functions']['recover']

    def _check_patterns(self, directory: str, patterns: List[str]) -> bool:
        """Check if any of the patterns are found in the directory"""
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith(('.py', '.js', '.java', '.md', '.yml', '.yaml', '.json', '.conf')):
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

        for function_name, function_data in self.framework_results['functions'].items():
            aws_checks = function_data.get('aws_checks', {})
            for check_name, check_data in aws_checks.items():
                total_checks += 1
                status = check_data['status']

                if status == 'Implemented':
                    implemented += 1
                elif status == 'Partial':
                    partial += 1
                else:
                    not_implemented += 1

        self.framework_results['aws_summary'] = {
            'total_checks': total_checks,
            'implemented': implemented,
            'not_implemented': not_implemented,
            'partial': partial,
            'compliance_score': ((implemented + partial) / total_checks * 100) if total_checks > 0 else 0
        }

    def generate_compliance_report(self) -> Dict:
        """Generate comprehensive NIST CSF compliance report"""
        logger.info("Generating NIST CSF compliance report...")

        # Calculate overall traditional score
        total_score = 0
        total_functions = 0

        for function_name, function_data in self.framework_results['functions'].items():
            if function_data['total'] > 0:
                total_score += function_data['score']
                total_functions += 1

        if total_functions > 0:
            self.framework_results['overall_score'] = total_score / total_functions

        # Calculate AWS summary
        self._calculate_aws_summary()

        # Generate recommendations
        recommendations = []

        for function_name, function_data in self.framework_results['functions'].items():
            # Traditional control recommendations
            for control_id, control_data in function_data['controls'].items():
                if control_data['status'] == 'FAIL':
                    recommendations.append({
                        'type': 'Traditional Control',
                        'function': function_name.upper(),
                        'control': control_id,
                        'issue': control_data['description'],
                        'remediation': f'Implement {control_data["description"]} controls'
                    })

            # AWS-specific recommendations
            for check_name, check_data in function_data.get('aws_checks', {}).items():
                if not check_data['compliant']:
                    recommendations.append({
                        'type': 'AWS Control',
                        'function': function_name.upper(),
                        'control': check_name,
                        'issue': check_data['description'],
                        'remediation': f'Address {check_name} AWS configuration issues'
                    })

        self.framework_results['recommendations'] = recommendations

        return self.framework_results

    def run_full_assessment(self, directory: str = ".") -> Dict:
        """Run complete NIST CSF assessment"""
        logger.info("Starting NIST Cybersecurity Framework assessment...")

        self.check_identify_function(directory)
        self.check_protect_function(directory)
        self.check_detect_function(directory)
        self.check_respond_function(directory)
        self.check_recover_function(directory)

        return self.generate_compliance_report()

    def run_specific_functions(self, functions: List[str], directory: str = ".") -> Dict:
        """Run assessment for specific NIST functions only"""
        logger.info(f"Running assessment for specific functions: {functions}")

        function_map = {
            'identify': self.check_identify_function,
            'protect': self.check_protect_function,
            'detect': self.check_detect_function,
            'respond': self.check_respond_function,
            'recover': self.check_recover_function
        }

        for function_name in functions:
            if function_name in function_map:
                function_map[function_name](directory)
            else:
                logger.warning(f"Unknown function: {function_name}")

        return self.generate_compliance_report()

def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description='NIST Cybersecurity Framework Assessment')
    parser.add_argument('--region', default='eu-west-2', help='AWS region to assess')
    parser.add_argument('--config', help='Configuration file path')
    parser.add_argument('--output', help='Output file path')
    parser.add_argument('--format', choices=['json', 'yaml'], default='json', help='Output format')
    parser.add_argument('--directory', default='.', help='Directory to scan for compliance artifacts')
    parser.add_argument('--functions', nargs='+',
                       choices=['identify', 'protect', 'detect', 'respond', 'recover'],
                       help='Specific functions to assess')
    parser.add_argument('--aws-only', action='store_true', help='Run only AWS-specific checks')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    validator = NISTFrameworkValidator(region=args.region, config_file=args.config)

    if args.functions:
        # Run specific functions only
        logger.info(f"Running assessment for specific functions: {args.functions}")
        results = validator.run_specific_functions(args.functions, args.directory)
    else:
        # Run comprehensive assessment
        logger.info("Running comprehensive NIST CSF assessment")
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
        output_file = f"nist_csf_report_{timestamp}.{args.format}"

    with open(output_file, 'w') as f:
        if args.format == 'yaml':
            yaml.dump(results, f, default_flow_style=False, sort_keys=False)
        else:
            json.dump(results, f, indent=2)

    # Summary output
    overall_score = results.get('overall_score', 0)
    aws_summary = results.get('aws_summary', {})

    logger.info(f"NIST CSF assessment complete: {overall_score:.1f}% traditional controls")
    logger.info(f"AWS compliance: {aws_summary.get('compliance_score', 0):.1f}% ({aws_summary.get('implemented', 0)} implemented, {aws_summary.get('partial', 0)} partial)")
    logger.info(f"Report saved to: {output_file}")

    # Return exit code based on compliance
    combined_score = (overall_score + aws_summary.get('compliance_score', 0)) / 2
    if combined_score < 70:
        return 1
    return 0

if __name__ == "__main__":
    exit(main())