#!/usr/bin/env python3
"""
NIST Cybersecurity Framework Validator
Automated validation of NIST CSF controls and implementation
"""

import json
import logging
import os
import re
from datetime import datetime
from typing import Dict, List

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class NISTFrameworkValidator:
    """Validate NIST Cybersecurity Framework implementation"""

    def __init__(self):
        self.framework_results = {
            'timestamp': datetime.now().isoformat(),
            'framework': 'NIST Cybersecurity Framework',
            'version': '1.1',
            'functions': {
                'identify': {'controls': {}, 'score': 0, 'total': 0},
                'protect': {'controls': {}, 'score': 0, 'total': 0},
                'detect': {'controls': {}, 'score': 0, 'total': 0},
                'respond': {'controls': {}, 'score': 0, 'total': 0},
                'recover': {'controls': {}, 'score': 0, 'total': 0}
            },
            'overall_score': 0
        }

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

        return self.framework_results['functions']['identify']

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

        return self.framework_results['functions']['protect']

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

        return self.framework_results['functions']['detect']

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

    def generate_compliance_report(self) -> Dict:
        """Generate comprehensive NIST CSF compliance report"""
        logger.info("Generating NIST CSF compliance report...")

        # Calculate overall score
        total_score = 0
        total_functions = 0

        for function_name, function_data in self.framework_results['functions'].items():
            if function_data['total'] > 0:
                total_score += function_data['score']
                total_functions += 1

        if total_functions > 0:
            self.framework_results['overall_score'] = total_score / total_functions

        # Generate recommendations
        recommendations = []

        for function_name, function_data in self.framework_results['functions'].items():
            for control_id, control_data in function_data['controls'].items():
                if control_data['status'] == 'FAIL':
                    recommendations.append({
                        'function': function_name.upper(),
                        'control': control_id,
                        'issue': control_data['description'],
                        'remediation': f'Implement {control_data["description"]} controls'
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

def main():
    """Main execution function"""
    validator = NISTFrameworkValidator()
    results = validator.run_full_assessment()

    print(json.dumps(results, indent=2))

    # Save results
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"nist_csf_report_{timestamp}.json"

    with open(filename, 'w') as f:
        json.dump(results, f, indent=2)

    logger.info(f"NIST CSF assessment complete. Report saved to {filename}")
    logger.info(f"Overall score: {results['overall_score']:.1f}%")

if __name__ == "__main__":
    main()