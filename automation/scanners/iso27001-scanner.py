#!/usr/bin/env python3
"""
ISO 27001 Compliance Scanner
Automated assessment tool for ISO 27001 information security controls
"""

import os
import sys
import json
import yaml
import argparse
import logging
import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum

# Import compliance framework modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class ComplianceStatus(Enum):
    """Compliance status enumeration"""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NOT_APPLICABLE = "not_applicable"
    PENDING_REVIEW = "pending_review"

class RiskLevel(Enum):
    """Risk level enumeration"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class ControlAssessment:
    """Individual control assessment result"""
    control_id: str
    control_name: str
    category: str
    description: str
    status: ComplianceStatus
    risk_level: RiskLevel
    evidence: List[str]
    findings: List[str]
    recommendations: List[str]
    assessment_date: str
    assessor: str
    score: float
    next_review_date: str

@dataclass
class ComplianceReport:
    """Complete compliance assessment report"""
    framework: str
    version: str
    assessment_id: str
    scope: str
    assessment_date: str
    assessor: str
    organization: str
    controls: List[ControlAssessment]
    overall_score: float
    summary: Dict[str, int]
    recommendations: List[str]

class ISO27001Scanner:
    """ISO 27001 Compliance Scanner"""

    def __init__(self, config_path: Optional[str] = None):
        self.logger = self._setup_logging()
        self.config = self._load_config(config_path)
        self.controls_db = self._load_controls_database()
        self.evidence_path = Path(self.config.get('evidence_path', './evidence'))
        self.evidence_path.mkdir(exist_ok=True)

    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        return logging.getLogger(__name__)

    def _load_config(self, config_path: Optional[str]) -> Dict:
        """Load scanner configuration"""
        default_config = {
            'organization': 'Example Organization',
            'scope': 'Information Security Management System',
            'assessor': 'Automated Scanner',
            'evidence_path': './evidence',
            'report_path': './reports',
            'thresholds': {
                'compliant_score': 90.0,
                'partially_compliant_score': 70.0
            }
        }

        if config_path and os.path.exists(config_path):
            with open(config_path, 'r') as f:
                user_config = yaml.safe_load(f)
                default_config.update(user_config)

        return default_config

    def _load_controls_database(self) -> Dict:
        """Load ISO 27001 controls database"""
        controls_db = {
            "A.5.1.1": {
                "name": "Information Security Policy",
                "category": "Information Security Policies",
                "description": "A set of policies for information security shall be defined, approved by management, published and communicated to employees and relevant external parties.",
                "implementation_guidance": [
                    "Develop comprehensive information security policy",
                    "Obtain management approval and endorsement",
                    "Communicate policy to all personnel",
                    "Regular policy review and updates"
                ],
                "assessment_criteria": [
                    "Policy document exists and is current",
                    "Management approval documented",
                    "Evidence of policy communication",
                    "Regular review process established"
                ]
            },
            "A.6.1.1": {
                "name": "Information Security Roles and Responsibilities",
                "category": "Organization of Information Security",
                "description": "All information security responsibilities shall be defined and allocated.",
                "implementation_guidance": [
                    "Define information security roles",
                    "Assign responsibilities to personnel",
                    "Document role definitions",
                    "Communicate responsibilities"
                ],
                "assessment_criteria": [
                    "Security roles defined and documented",
                    "Responsibilities clearly assigned",
                    "Role descriptions current and accurate",
                    "Personnel awareness of responsibilities"
                ]
            },
            "A.7.1.1": {
                "name": "Screening",
                "category": "Human Resource Security",
                "description": "Background verification checks on all candidates for employment shall be carried out in accordance with relevant laws, regulations and ethics and shall be proportional to the business requirements, the classification of the information to be accessed and the perceived risks.",
                "implementation_guidance": [
                    "Establish background check procedures",
                    "Define verification requirements",
                    "Implement screening process",
                    "Document verification results"
                ],
                "assessment_criteria": [
                    "Background check policy exists",
                    "Verification procedures implemented",
                    "Documentation of checks maintained",
                    "Process complies with legal requirements"
                ]
            },
            "A.8.1.1": {
                "name": "Inventory of Assets",
                "category": "Asset Management",
                "description": "Assets associated with information and information processing facilities shall be identified and an inventory of these assets shall be drawn up and maintained.",
                "implementation_guidance": [
                    "Identify all information assets",
                    "Create and maintain asset inventory",
                    "Assign asset owners",
                    "Regular inventory updates"
                ],
                "assessment_criteria": [
                    "Complete asset inventory exists",
                    "Asset ownership assigned",
                    "Inventory regularly updated",
                    "Asset classification implemented"
                ]
            },
            "A.9.1.1": {
                "name": "Access Control Policy",
                "category": "Access Control",
                "description": "An access control policy shall be established, documented and reviewed based on business and information security requirements.",
                "implementation_guidance": [
                    "Develop access control policy",
                    "Define access control procedures",
                    "Regular policy review",
                    "Align with business requirements"
                ],
                "assessment_criteria": [
                    "Access control policy documented",
                    "Policy aligned with business needs",
                    "Regular review process in place",
                    "Policy communicated to users"
                ]
            },
            "A.10.1.1": {
                "name": "Cryptographic Policy",
                "category": "Cryptography",
                "description": "A policy on the use of cryptographic controls for protection of information shall be developed and implemented.",
                "implementation_guidance": [
                    "Develop cryptography policy",
                    "Define cryptographic standards",
                    "Implement key management",
                    "Regular policy updates"
                ],
                "assessment_criteria": [
                    "Cryptographic policy exists",
                    "Standards and procedures defined",
                    "Key management implemented",
                    "Regular policy review"
                ]
            },
            "A.11.1.1": {
                "name": "Physical Security Perimeter",
                "category": "Physical and Environmental Security",
                "description": "Physical security perimeters shall be defined and used to protect areas that contain either sensitive or critical information and information processing facilities.",
                "implementation_guidance": [
                    "Define security perimeters",
                    "Implement physical controls",
                    "Monitor access points",
                    "Regular security reviews"
                ],
                "assessment_criteria": [
                    "Security perimeters defined",
                    "Physical controls implemented",
                    "Access monitoring in place",
                    "Regular security assessments"
                ]
            },
            "A.12.1.1": {
                "name": "Operating Procedures",
                "category": "Operations Security",
                "description": "Operating procedures shall be documented and made available to all users who need them.",
                "implementation_guidance": [
                    "Document operating procedures",
                    "Make procedures accessible",
                    "Train personnel on procedures",
                    "Regular procedure updates"
                ],
                "assessment_criteria": [
                    "Procedures documented and current",
                    "Procedures accessible to users",
                    "Training provided to personnel",
                    "Regular review and updates"
                ]
            },
            "A.13.1.1": {
                "name": "Network Controls",
                "category": "Communications Security",
                "description": "Networks shall be managed and controlled to protect information in systems and applications.",
                "implementation_guidance": [
                    "Implement network security controls",
                    "Monitor network traffic",
                    "Control network access",
                    "Regular security assessments"
                ],
                "assessment_criteria": [
                    "Network controls implemented",
                    "Traffic monitoring in place",
                    "Access controls configured",
                    "Regular security reviews"
                ]
            },
            "A.14.1.1": {
                "name": "Security in Development Process",
                "category": "System Acquisition, Development and Maintenance",
                "description": "Information security requirements shall be included in the requirements for new information systems or enhancements to existing information systems.",
                "implementation_guidance": [
                    "Include security in SDLC",
                    "Define security requirements",
                    "Implement secure development",
                    "Regular security testing"
                ],
                "assessment_criteria": [
                    "Security requirements defined",
                    "SDLC includes security",
                    "Security testing implemented",
                    "Regular security reviews"
                ]
            },
            "A.15.1.1": {
                "name": "Supplier Relationships Policy",
                "category": "Supplier Relationships",
                "description": "An information security policy for supplier relationships shall be established and communicated to suppliers based on the organization's access control policy.",
                "implementation_guidance": [
                    "Develop supplier security policy",
                    "Communicate to suppliers",
                    "Monitor supplier compliance",
                    "Regular policy reviews"
                ],
                "assessment_criteria": [
                    "Supplier security policy exists",
                    "Policy communicated to suppliers",
                    "Compliance monitoring implemented",
                    "Regular policy updates"
                ]
            },
            "A.16.1.1": {
                "name": "Incident Management Responsibilities",
                "category": "Information Security Incident Management",
                "description": "Management responsibilities and procedures shall be established to ensure a quick, effective and orderly response to information security incidents.",
                "implementation_guidance": [
                    "Define incident response roles",
                    "Establish response procedures",
                    "Train incident response team",
                    "Regular plan testing"
                ],
                "assessment_criteria": [
                    "Incident response plan exists",
                    "Roles and responsibilities defined",
                    "Team training provided",
                    "Regular plan testing"
                ]
            },
            "A.17.1.1": {
                "name": "Business Continuity Planning",
                "category": "Business Continuity Management",
                "description": "The organization shall determine its requirements for information security and the continuity of information security management in adverse situations.",
                "implementation_guidance": [
                    "Develop business continuity plan",
                    "Include security considerations",
                    "Test continuity procedures",
                    "Regular plan updates"
                ],
                "assessment_criteria": [
                    "Business continuity plan exists",
                    "Security included in planning",
                    "Regular testing conducted",
                    "Plan regularly updated"
                ]
            },
            "A.18.1.1": {
                "name": "Compliance Requirements",
                "category": "Compliance",
                "description": "All relevant statutory, regulatory and contractual requirements and the organization's approach to meet these requirements shall be explicitly identified, documented and kept up to date for each information system and the organization.",
                "implementation_guidance": [
                    "Identify compliance requirements",
                    "Document compliance approach",
                    "Monitor regulatory changes",
                    "Regular compliance reviews"
                ],
                "assessment_criteria": [
                    "Compliance requirements identified",
                    "Compliance approach documented",
                    "Monitoring process in place",
                    "Regular compliance assessments"
                ]
            }
        }
        return controls_db

    def assess_control(self, control_id: str, scope: str = "production") -> ControlAssessment:
        """Assess individual ISO 27001 control"""
        self.logger.info(f"Assessing control {control_id}")

        if control_id not in self.controls_db:
            raise ValueError(f"Unknown control ID: {control_id}")

        control_info = self.controls_db[control_id]

        # Simulate control assessment logic
        # In a real implementation, this would involve:
        # - Evidence collection
        # - Technical testing
        # - Document review
        # - Interview results

        evidence = self._collect_evidence(control_id, scope)
        findings = self._analyze_evidence(control_id, evidence)
        status, score = self._determine_compliance_status(control_id, findings)
        risk_level = self._assess_risk_level(control_id, status, findings)
        recommendations = self._generate_recommendations(control_id, findings)

        assessment = ControlAssessment(
            control_id=control_id,
            control_name=control_info["name"],
            category=control_info["category"],
            description=control_info["description"],
            status=status,
            risk_level=risk_level,
            evidence=evidence,
            findings=findings,
            recommendations=recommendations,
            assessment_date=datetime.datetime.now().isoformat(),
            assessor=self.config["assessor"],
            score=score,
            next_review_date=(datetime.datetime.now() + datetime.timedelta(days=365)).isoformat()
        )

        return assessment

    def _collect_evidence(self, control_id: str, scope: str) -> List[str]:
        """Collect evidence for control assessment"""
        evidence = []

        # Simulate evidence collection based on control type
        control_info = self.controls_db[control_id]

        if "policy" in control_info["name"].lower():
            evidence.extend([
                f"Policy document for {control_id}",
                f"Management approval for {control_id} policy",
                f"Policy distribution records",
                f"Policy review meeting minutes"
            ])

        if "access" in control_info["name"].lower():
            evidence.extend([
                f"Access control configuration dump",
                f"User access review reports",
                f"Privileged access logs",
                f"Access request approval records"
            ])

        if "incident" in control_info["name"].lower():
            evidence.extend([
                f"Incident response plan document",
                f"Incident response team contact list",
                f"Incident response training records",
                f"Recent incident reports"
            ])

        # Save evidence files
        evidence_file = self.evidence_path / f"{control_id}_evidence.json"
        with open(evidence_file, 'w') as f:
            json.dump({
                "control_id": control_id,
                "evidence": evidence,
                "collection_date": datetime.datetime.now().isoformat(),
                "scope": scope
            }, f, indent=2)

        return evidence

    def _analyze_evidence(self, control_id: str, evidence: List[str]) -> List[str]:
        """Analyze collected evidence"""
        findings = []

        # Simulate evidence analysis
        if len(evidence) < 3:
            findings.append(f"Insufficient evidence collected for {control_id}")

        if any("policy" in e.lower() for e in evidence):
            findings.append("Policy documentation found and reviewed")
        else:
            findings.append("Missing policy documentation")

        if any("approval" in e.lower() for e in evidence):
            findings.append("Management approval documented")
        else:
            findings.append("Missing management approval evidence")

        if any("training" in e.lower() for e in evidence):
            findings.append("Training records available")
        else:
            findings.append("Training records not found")

        return findings

    def _determine_compliance_status(self, control_id: str, findings: List[str]) -> Tuple[ComplianceStatus, float]:
        """Determine compliance status and score"""
        positive_findings = sum(1 for f in findings if not f.startswith("Missing") and not f.startswith("Insufficient"))
        total_findings = len(findings)

        if total_findings == 0:
            return ComplianceStatus.PENDING_REVIEW, 0.0

        score = (positive_findings / total_findings) * 100

        if score >= self.config["thresholds"]["compliant_score"]:
            status = ComplianceStatus.COMPLIANT
        elif score >= self.config["thresholds"]["partially_compliant_score"]:
            status = ComplianceStatus.PARTIALLY_COMPLIANT
        else:
            status = ComplianceStatus.NON_COMPLIANT

        return status, score

    def _assess_risk_level(self, control_id: str, status: ComplianceStatus, findings: List[str]) -> RiskLevel:
        """Assess risk level based on compliance status"""
        if status == ComplianceStatus.COMPLIANT:
            return RiskLevel.LOW
        elif status == ComplianceStatus.PARTIALLY_COMPLIANT:
            return RiskLevel.MEDIUM
        elif status == ComplianceStatus.NON_COMPLIANT:
            # Critical controls get higher risk
            critical_controls = ["A.9.1.1", "A.10.1.1", "A.16.1.1", "A.18.1.1"]
            if control_id in critical_controls:
                return RiskLevel.CRITICAL
            else:
                return RiskLevel.HIGH
        else:
            return RiskLevel.MEDIUM

    def _generate_recommendations(self, control_id: str, findings: List[str]) -> List[str]:
        """Generate remediation recommendations"""
        recommendations = []

        for finding in findings:
            if "Missing" in finding:
                if "policy" in finding.lower():
                    recommendations.append("Develop and implement required policy documentation")
                elif "approval" in finding.lower():
                    recommendations.append("Obtain formal management approval and documentation")
                elif "training" in finding.lower():
                    recommendations.append("Implement training program and maintain records")
                else:
                    recommendations.append(f"Address missing requirement: {finding}")
            elif "Insufficient" in finding:
                recommendations.append("Collect additional evidence to demonstrate control implementation")

        # Add standard recommendations
        control_info = self.controls_db[control_id]
        if "implementation_guidance" in control_info:
            recommendations.extend([
                f"Review implementation guidance: {guidance}"
                for guidance in control_info["implementation_guidance"][:2]
            ])

        return recommendations

    def run_full_assessment(self, scope: str = "production") -> ComplianceReport:
        """Run complete ISO 27001 assessment"""
        self.logger.info(f"Starting ISO 27001 assessment for scope: {scope}")

        assessment_id = f"ISO27001-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}"
        controls = []

        # Assess all controls
        for control_id in self.controls_db.keys():
            try:
                assessment = self.assess_control(control_id, scope)
                controls.append(assessment)
                self.logger.info(f"Completed assessment for {control_id}: {assessment.status.value}")
            except Exception as e:
                self.logger.error(f"Error assessing {control_id}: {e}")
                continue

        # Calculate overall metrics
        total_controls = len(controls)
        compliant_controls = sum(1 for c in controls if c.status == ComplianceStatus.COMPLIANT)
        partially_compliant = sum(1 for c in controls if c.status == ComplianceStatus.PARTIALLY_COMPLIANT)
        non_compliant = sum(1 for c in controls if c.status == ComplianceStatus.NON_COMPLIANT)

        overall_score = sum(c.score for c in controls) / total_controls if total_controls > 0 else 0

        summary = {
            "total_controls": total_controls,
            "compliant": compliant_controls,
            "partially_compliant": partially_compliant,
            "non_compliant": non_compliant,
            "compliance_percentage": (compliant_controls / total_controls) * 100 if total_controls > 0 else 0
        }

        # Generate high-level recommendations
        high_level_recommendations = [
            "Prioritize remediation of non-compliant critical controls",
            "Develop comprehensive evidence collection procedures",
            "Implement regular compliance monitoring and review processes",
            "Enhance staff training on information security policies and procedures"
        ]

        report = ComplianceReport(
            framework="ISO 27001:2022",
            version="2022",
            assessment_id=assessment_id,
            scope=scope,
            assessment_date=datetime.datetime.now().isoformat(),
            assessor=self.config["assessor"],
            organization=self.config["organization"],
            controls=controls,
            overall_score=overall_score,
            summary=summary,
            recommendations=high_level_recommendations
        )

        self.logger.info(f"Assessment completed. Overall score: {overall_score:.1f}%")
        return report

    def save_report(self, report: ComplianceReport, format: str = "json") -> str:
        """Save compliance report to file"""
        report_dir = Path(self.config.get('report_path', './reports'))
        report_dir.mkdir(exist_ok=True)

        if format.lower() == "json":
            filename = f"{report.assessment_id}_report.json"
            filepath = report_dir / filename

            with open(filepath, 'w') as f:
                json.dump(asdict(report), f, indent=2, default=str)

        elif format.lower() == "yaml":
            filename = f"{report.assessment_id}_report.yaml"
            filepath = report_dir / filename

            with open(filepath, 'w') as f:
                yaml.dump(asdict(report), f, default_flow_style=False)

        else:
            raise ValueError(f"Unsupported format: {format}")

        self.logger.info(f"Report saved to: {filepath}")
        return str(filepath)

def main():
    """Main function for CLI usage"""
    parser = argparse.ArgumentParser(description="ISO 27001 Compliance Scanner")
    parser.add_argument("--scope", default="production", help="Assessment scope")
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument("--control", help="Assess specific control only")
    parser.add_argument("--format", default="json", choices=["json", "yaml"], help="Report format")
    parser.add_argument("--output", help="Output file path")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Initialize scanner
    scanner = ISO27001Scanner(args.config)

    if args.control:
        # Assess single control
        assessment = scanner.assess_control(args.control, args.scope)
        print(f"Control {args.control}: {assessment.status.value} (Score: {assessment.score:.1f}%)")

        if args.output:
            with open(args.output, 'w') as f:
                json.dump(asdict(assessment), f, indent=2, default=str)
    else:
        # Run full assessment
        report = scanner.run_full_assessment(args.scope)

        # Display summary
        print(f"\nISO 27001 Assessment Summary")
        print(f"=" * 40)
        print(f"Overall Score: {report.overall_score:.1f}%")
        print(f"Total Controls: {report.summary['total_controls']}")
        print(f"Compliant: {report.summary['compliant']}")
        print(f"Partially Compliant: {report.summary['partially_compliant']}")
        print(f"Non-Compliant: {report.summary['non_compliant']}")
        print(f"Compliance Percentage: {report.summary['compliance_percentage']:.1f}%")

        # Save report
        output_path = args.output or scanner.save_report(report, args.format)
        print(f"\nDetailed report saved to: {output_path}")

if __name__ == "__main__":
    main()