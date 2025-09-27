#!/usr/bin/env python3
"""
Comprehensive Test Suite for Compliance Automation Framework
Tests all compliance frameworks and their AWS integrations
"""

import json
import os
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Import all compliance modules
import sys
sys.path.append(str(Path(__file__).parent.parent))

from iso27001_automation.compliance_checker import ISO27001Checker
from gdpr_compliance.gdpr_validator import GDPRValidator
from nist_framework.nist_validator import NISTFrameworkValidator
from soc2_compliance.soc2_validator import SOC2Validator
from scripts.compliance_runner import ComplianceRunner
from dashboard.compliance_dashboard import ComplianceDashboard

class TestISO27001Checker(unittest.TestCase):
    """Test ISO 27001 compliance checker"""

    def setUp(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.checker = None

    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    @patch('boto3.client')
    def test_iso27001_initialization(self, mock_boto3):
        """Test ISO 27001 checker initialization"""
        mock_boto3.return_value = Mock()

        self.checker = ISO27001Checker(region='eu-west-2')

        self.assertEqual(self.checker.region, 'eu-west-2')
        self.assertIsNotNone(self.checker.results)
        self.assertEqual(self.checker.results['framework'], 'ISO 27001:2013')

    @patch('boto3.client')
    def test_iso27001_config_loading(self, mock_boto3):
        """Test configuration loading"""
        mock_boto3.return_value = Mock()

        # Create test config file
        config_data = {
            'thresholds': {
                'password_max_age': 60,
                'key_rotation_days': 180
            }
        }

        config_file = os.path.join(self.test_dir, 'test_config.yaml')
        import yaml
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)

        self.checker = ISO27001Checker(config_file=config_file)

        self.assertEqual(self.checker.config['thresholds']['password_max_age'], 60)
        self.assertEqual(self.checker.config['thresholds']['key_rotation_days'], 180)

    @patch('boto3.client')
    def test_iso27001_comprehensive_assessment(self, mock_boto3):
        """Test comprehensive assessment execution"""
        mock_client = Mock()
        mock_boto3.return_value = mock_client

        # Mock AWS service responses
        mock_client.describe_trails.return_value = {
            'trailList': [{'TrailARN': 'test-trail', 'LogFileValidationEnabled': True}]
        }
        mock_client.get_trail_status.return_value = {'IsLogging': True}
        mock_client.list_buckets.return_value = {'Buckets': [{'Name': 'test-bucket'}]}
        mock_client.get_bucket_encryption.return_value = {'ServerSideEncryptionConfiguration': {}}

        self.checker = ISO27001Checker(region='eu-west-2')

        # Create test files for pattern matching
        test_file = os.path.join(self.test_dir, 'security_policy.md')
        with open(test_file, 'w') as f:
            f.write("# Information Security Policy\n\nThis document outlines our security controls.")

        result = self.checker.run_comprehensive_assessment()

        self.assertIsInstance(result, dict)
        self.assertIn('controls', result)
        self.assertIn('summary', result)
        self.assertGreaterEqual(result['summary']['compliance_score'], 0)

class TestGDPRValidator(unittest.TestCase):
    """Test GDPR compliance validator"""

    def setUp(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    @patch('boto3.client')
    def test_gdpr_initialization(self, mock_boto3):
        """Test GDPR validator initialization"""
        mock_boto3.return_value = Mock()

        validator = GDPRValidator(region='eu-west-2')

        self.assertEqual(validator.region, 'eu-west-2')
        self.assertEqual(validator.compliance_results['framework'], 'GDPR')

    @patch('boto3.client')
    def test_gdpr_data_inventory_check(self, mock_boto3):
        """Test data inventory compliance check"""
        mock_boto3.return_value = Mock()

        validator = GDPRValidator()

        # Create test data inventory file
        inventory_file = os.path.join(self.test_dir, 'data-inventory.json')
        with open(inventory_file, 'w') as f:
            json.dump({'data_categories': ['personal', 'sensitive']}, f)

        result = validator.check_data_inventory(self.test_dir)

        self.assertEqual(result['status'], 'Implemented')
        self.assertIn('Data inventory documentation found', result['description'])

    @patch('boto3.client')
    def test_gdpr_aws_encryption_check(self, mock_boto3):
        """Test AWS encryption compliance check"""
        mock_s3 = Mock()
        mock_rds = Mock()

        mock_boto3.side_effect = lambda service, **kwargs: {
            's3': mock_s3,
            'rds': mock_rds
        }.get(service, Mock())

        # Mock S3 and RDS responses
        mock_s3.list_buckets.return_value = {'Buckets': [{'Name': 'test-bucket'}]}
        mock_s3.get_bucket_encryption.return_value = {'ServerSideEncryptionConfiguration': {}}
        mock_rds.describe_db_instances.return_value = {
            'DBInstances': [{'StorageEncrypted': True}]
        }

        validator = GDPRValidator()
        status, compliant, description = validator.check_data_encryption_aws()

        self.assertIn(status, ['Implemented', 'Partial', 'Not Implemented'])
        self.assertIsInstance(compliant, bool)
        self.assertIsInstance(description, str)

class TestNISTFrameworkValidator(unittest.TestCase):
    """Test NIST Cybersecurity Framework validator"""

    def setUp(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    @patch('boto3.client')
    def test_nist_initialization(self, mock_boto3):
        """Test NIST validator initialization"""
        mock_boto3.return_value = Mock()

        validator = NISTFrameworkValidator(region='eu-west-2')

        self.assertEqual(validator.region, 'eu-west-2')
        self.assertEqual(validator.framework_results['framework'], 'NIST Cybersecurity Framework')
        self.assertEqual(validator.framework_results['version'], '2.0')

    @patch('boto3.client')
    def test_nist_identify_function(self, mock_boto3):
        """Test NIST IDENTIFY function checks"""
        mock_boto3.return_value = Mock()

        validator = NISTFrameworkValidator()

        # Create test files for asset management
        asset_file = os.path.join(self.test_dir, 'asset_inventory.yaml')
        with open(asset_file, 'w') as f:
            f.write("asset_inventory:\n  - server1\n  - server2")

        result = validator.check_identify_function(self.test_dir)

        self.assertIn('controls', result)
        self.assertIn('score', result)
        self.assertGreaterEqual(result['score'], 0)

    @patch('boto3.client')
    def test_nist_aws_security_checks(self, mock_boto3):
        """Test NIST AWS security integrations"""
        mock_config = Mock()
        mock_securityhub = Mock()

        mock_boto3.side_effect = lambda service, **kwargs: {
            'config': mock_config,
            'securityhub': mock_securityhub
        }.get(service, Mock())

        # Mock AWS Config rules
        mock_config.describe_config_rules.return_value = {
            'ConfigRules': [{'ConfigRuleName': 'asset-inventory-check'}]
        }

        # Mock Security Hub
        mock_securityhub.get_findings.return_value = {'Findings': []}

        validator = NISTFrameworkValidator()
        aws_checks = validator._run_aws_identify_checks()

        self.assertIn('asset_management', aws_checks)
        self.assertIn('risk_assessment', aws_checks)

class TestSOC2Validator(unittest.TestCase):
    """Test SOC 2 compliance validator"""

    def setUp(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    @patch('boto3.client')
    def test_soc2_initialization(self, mock_boto3):
        """Test SOC 2 validator initialization"""
        mock_boto3.return_value = Mock()

        validator = SOC2Validator(region='eu-west-2')

        self.assertEqual(validator.region, 'eu-west-2')
        self.assertEqual(validator.validation_results['framework'], 'SOC 2 Type II')

    @patch('boto3.client')
    def test_soc2_security_criteria(self, mock_boto3):
        """Test SOC 2 security criteria checks"""
        mock_boto3.return_value = Mock()

        validator = SOC2Validator()

        # Create test security policy file
        policy_file = os.path.join(self.test_dir, 'security_policy.md')
        with open(policy_file, 'w') as f:
            f.write("# Control Environment\n\nOur governance framework...")

        result = validator.check_security_criteria(self.test_dir)

        self.assertIn('controls', result)
        self.assertIn('score', result)
        self.assertGreaterEqual(result['score'], 0)

    @patch('boto3.client')
    def test_soc2_availability_criteria(self, mock_boto3):
        """Test SOC 2 availability criteria checks"""
        mock_backup = Mock()
        mock_cloudwatch = Mock()

        mock_boto3.side_effect = lambda service, **kwargs: {
            'backup': mock_backup,
            'cloudwatch': mock_cloudwatch
        }.get(service, Mock())

        # Mock backup plans
        mock_backup.list_backup_plans.return_value = {
            'BackupPlansList': [{'BackupPlanId': 'test-plan'}]
        }

        # Mock CloudWatch alarms
        mock_cloudwatch.describe_alarms.return_value = {
            'MetricAlarms': [{'AlarmName': 'CPU-Utilization', 'ActionsEnabled': True}]
        }

        validator = SOC2Validator()
        aws_checks = validator._run_aws_availability_checks()

        self.assertIn('backup_recovery', aws_checks)
        self.assertIn('monitoring', aws_checks)

class TestComplianceRunner(unittest.TestCase):
    """Test compliance framework orchestration"""

    def setUp(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_compliance_runner_initialization(self):
        """Test compliance runner initialization"""
        runner = ComplianceRunner()

        self.assertIsNotNone(runner.config)
        self.assertIn('frameworks', runner.config)
        self.assertIn('execution', runner.config)

    def test_compliance_runner_config_loading(self):
        """Test configuration file loading"""
        config_data = {
            'frameworks': {
                'iso27001': {'enabled': True, 'timeout': 600}
            },
            'execution': {'parallel': False}
        }

        config_file = os.path.join(self.test_dir, 'runner_config.json')
        with open(config_file, 'w') as f:
            json.dump(config_data, f)

        runner = ComplianceRunner(config_file)

        self.assertEqual(runner.config['frameworks']['iso27001']['timeout'], 600)
        self.assertFalse(runner.config['execution']['parallel'])

    @patch('subprocess.run')
    def test_single_framework_execution(self, mock_subprocess):
        """Test running a single compliance framework"""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = '{"framework": "ISO 27001", "score": 85.5}'
        mock_result.stderr = ''
        mock_subprocess.return_value = mock_result

        runner = ComplianceRunner()
        framework_config = {
            'script': 'test_script.py',
            'args': ['--test'],
            'timeout': 300
        }

        result = runner.run_framework('iso27001', framework_config)

        self.assertEqual(result['status'], 'SUCCESS')
        self.assertEqual(result['framework'], 'iso27001')
        self.assertIn('compliance_data', result)

class TestComplianceDashboard(unittest.TestCase):
    """Test compliance dashboard generation"""

    def setUp(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.dashboard = ComplianceDashboard(
            data_dir=self.test_dir,
            db_path=os.path.join(self.test_dir, 'test.db')
        )

    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_dashboard_initialization(self):
        """Test dashboard initialization"""
        self.assertIsNotNone(self.dashboard.data_dir)
        self.assertTrue(os.path.exists(self.dashboard.db_path))

    def test_compliance_data_loading(self):
        """Test loading compliance data from reports"""
        # Create test report file
        report_data = {
            'timestamp': datetime.now().isoformat(),
            'framework': 'ISO 27001',
            'overall_score': 85.5,
            'controls': {'A.5.1.1': {'status': 'Implemented'}}
        }

        report_file = os.path.join(self.test_dir, 'test_report.json')
        with open(report_file, 'w') as f:
            json.dump(report_data, f)

        compliance_data = self.dashboard.load_compliance_data()

        self.assertEqual(len(compliance_data), 1)
        self.assertEqual(compliance_data[0]['framework'], 'ISO 27001')
        self.assertEqual(compliance_data[0]['overall_score'], 85.5)

    def test_dashboard_html_generation(self):
        """Test HTML dashboard generation"""
        # Create test data
        report_data = {
            'timestamp': datetime.now().isoformat(),
            'framework': 'ISO 27001',
            'overall_score': 85.5
        }

        report_file = os.path.join(self.test_dir, 'test_report.json')
        with open(report_file, 'w') as f:
            json.dump(report_data, f)

        output_file = os.path.join(self.test_dir, 'test_dashboard.html')
        generated_file = self.dashboard.generate_dashboard_html(output_file)

        self.assertTrue(os.path.exists(generated_file))

        with open(generated_file, 'r') as f:
            content = f.read()
            self.assertIn('Compliance Dashboard', content)
            self.assertIn('ISO 27001', content)

class TestIntegration(unittest.TestCase):
    """Integration tests for the complete compliance automation system"""

    def setUp(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    @patch('boto3.client')
    def test_end_to_end_compliance_assessment(self, mock_boto3):
        """Test complete end-to-end compliance assessment workflow"""
        # Mock AWS clients
        mock_client = Mock()
        mock_boto3.return_value = mock_client

        # Mock basic AWS responses
        mock_client.list_buckets.return_value = {'Buckets': []}
        mock_client.describe_trails.return_value = {'trailList': []}
        mock_client.describe_security_groups.return_value = {'SecurityGroups': []}
        mock_client.list_users.return_value = {'Users': []}
        mock_client.list_virtual_mfa_devices.return_value = {'VirtualMFADevices': []}

        # Test ISO 27001 assessment
        iso_checker = ISO27001Checker(region='eu-west-2')
        iso_result = iso_checker.run_comprehensive_assessment()

        self.assertIsInstance(iso_result, dict)
        self.assertIn('summary', iso_result)

        # Test GDPR assessment
        gdpr_validator = GDPRValidator(region='eu-west-2')
        gdpr_result = gdpr_validator.run_full_assessment(self.test_dir)

        self.assertIsInstance(gdpr_result, dict)
        self.assertIn('summary', gdpr_result)

        # Test dashboard generation with results
        dashboard = ComplianceDashboard(data_dir=self.test_dir)

        # Save test results
        for i, (name, result) in enumerate([('iso27001', iso_result), ('gdpr', gdpr_result)]):
            report_file = os.path.join(self.test_dir, f'{name}_report.json')
            with open(report_file, 'w') as f:
                json.dump(result, f)

        dashboard_file = os.path.join(self.test_dir, 'integration_dashboard.html')
        generated_file = dashboard.generate_dashboard_html(dashboard_file)

        self.assertTrue(os.path.exists(generated_file))

def run_performance_tests():
    """Run performance benchmarks for compliance frameworks"""
    import time

    print("\n🚀 Running Performance Benchmarks...")

    performance_results = {}

    with patch('boto3.client') as mock_boto3:
        mock_boto3.return_value = Mock()

        # Test ISO 27001 performance
        start_time = time.time()
        iso_checker = ISO27001Checker()
        iso_result = iso_checker.run_comprehensive_assessment()
        iso_duration = time.time() - start_time
        performance_results['ISO27001'] = iso_duration

        # Test GDPR performance
        start_time = time.time()
        gdpr_validator = GDPRValidator()
        gdpr_result = gdpr_validator.run_full_assessment()
        gdpr_duration = time.time() - start_time
        performance_results['GDPR'] = gdpr_duration

        # Test NIST performance
        start_time = time.time()
        nist_validator = NISTFrameworkValidator()
        nist_result = nist_validator.run_full_assessment()
        nist_duration = time.time() - start_time
        performance_results['NIST'] = nist_duration

    print("\n📊 Performance Results:")
    for framework, duration in performance_results.items():
        print(f"  {framework}: {duration:.2f} seconds")

    return performance_results

if __name__ == '__main__':
    print("🧪 Running Compliance Automation Test Suite...")
    print("=" * 60)

    # Run unit tests
    unittest.main(argv=[''], exit=False, verbosity=2)

    # Run performance tests
    run_performance_tests()

    print("\n✅ All tests completed!")
    print("📋 Test Summary:")
    print("  - Unit Tests: Comprehensive framework testing")
    print("  - Integration Tests: End-to-end workflow validation")
    print("  - Performance Tests: Framework execution benchmarks")
    print("  - AWS Mock Tests: Cloud service integration validation")