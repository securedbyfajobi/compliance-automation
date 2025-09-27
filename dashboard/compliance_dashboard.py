#!/usr/bin/env python3
"""
Compliance Dashboard Generator
Creates comprehensive HTML dashboards for compliance monitoring
Real-time compliance status visualization and reporting
"""

import argparse
import json
import os
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ComplianceDashboard:
    """Generate comprehensive compliance dashboards and reports"""

    def __init__(self, data_dir: str = "./compliance-reports", db_path: str = "./compliance.db"):
        self.data_dir = Path(data_dir)
        self.db_path = db_path
        self.init_database()

    def init_database(self):
        """Initialize SQLite database for compliance tracking"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Create tables for compliance tracking
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS assessments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                framework TEXT NOT NULL,
                overall_score REAL,
                status TEXT,
                execution_time REAL,
                report_data TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS framework_scores (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                assessment_id INTEGER,
                framework TEXT NOT NULL,
                category TEXT,
                control_id TEXT,
                status TEXT,
                score REAL,
                description TEXT,
                FOREIGN KEY (assessment_id) REFERENCES assessments (id)
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS compliance_trends (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT NOT NULL,
                framework TEXT NOT NULL,
                score REAL NOT NULL,
                trend_direction TEXT
            )
        ''')

        conn.commit()
        conn.close()

    def load_compliance_data(self) -> List[Dict]:
        """Load compliance data from report files"""
        compliance_data = []

        if not self.data_dir.exists():
            logger.warning(f"Data directory {self.data_dir} does not exist")
            return compliance_data

        # Load JSON reports
        for json_file in self.data_dir.glob("*.json"):
            try:
                with open(json_file, 'r') as f:
                    data = json.load(f)
                    data['source_file'] = str(json_file)
                    data['file_timestamp'] = json_file.stat().st_mtime
                    compliance_data.append(data)
            except Exception as e:
                logger.warning(f"Failed to load {json_file}: {e}")

        # Sort by timestamp
        compliance_data.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        return compliance_data

    def update_database(self, compliance_data: List[Dict]):
        """Update database with latest compliance data"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        for data in compliance_data:
            # Check if assessment already exists
            cursor.execute(
                "SELECT id FROM assessments WHERE timestamp = ? AND framework = ?",
                (data.get('timestamp', ''), data.get('framework', ''))
            )

            if cursor.fetchone():
                continue  # Skip if already exists

            # Insert main assessment record
            cursor.execute('''
                INSERT INTO assessments (timestamp, framework, overall_score, status, execution_time, report_data)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                data.get('timestamp', ''),
                data.get('framework', ''),
                data.get('overall_score', 0),
                'SUCCESS',  # Assume success if we have data
                data.get('execution_time', 0),
                json.dumps(data)
            ))

            assessment_id = cursor.lastrowid

            # Insert detailed scores
            if 'compliance_scores' in data:
                for framework, score in data['compliance_scores'].items():
                    cursor.execute('''
                        INSERT INTO framework_scores (assessment_id, framework, score)
                        VALUES (?, ?, ?)
                    ''', (assessment_id, framework, score))

            # Handle different framework structures
            if data.get('framework') == 'ISO 27001:2013' and 'controls' in data:
                for control_id, control_data in data['controls'].items():
                    cursor.execute('''
                        INSERT INTO framework_scores (assessment_id, framework, control_id, status, description)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (
                        assessment_id,
                        'ISO27001',
                        control_id,
                        control_data.get('status', ''),
                        control_data.get('description', '')
                    ))

        conn.commit()
        conn.close()

    def generate_dashboard_html(self, output_file: str = "compliance_dashboard.html") -> str:
        """Generate comprehensive HTML dashboard"""
        logger.info("Generating compliance dashboard...")

        # Load data
        compliance_data = self.load_compliance_data()
        self.update_database(compliance_data)

        # Generate dashboard sections
        summary_section = self._generate_summary_section(compliance_data)
        trends_section = self._generate_trends_section()
        frameworks_section = self._generate_frameworks_section(compliance_data)
        alerts_section = self._generate_alerts_section(compliance_data)
        details_section = self._generate_details_section(compliance_data)

        # HTML template
        html_template = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Compliance Dashboard</title>
            <style>
                {self._get_dashboard_css()}
            </style>
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        </head>
        <body>
            <header class="dashboard-header">
                <h1>🛡️ Compliance Dashboard</h1>
                <div class="timestamp">Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
            </header>

            <main class="dashboard-content">
                {summary_section}
                {trends_section}
                {frameworks_section}
                {alerts_section}
                {details_section}
            </main>

            <script>
                {self._get_dashboard_js()}
            </script>
        </body>
        </html>
        """

        # Write to file
        with open(output_file, 'w') as f:
            f.write(html_template)

        logger.info(f"Dashboard generated: {output_file}")
        return output_file

    def _generate_summary_section(self, compliance_data: List[Dict]) -> str:
        """Generate executive summary section"""
        if not compliance_data:
            return "<div class='section'><h2>No compliance data available</h2></div>"

        # Calculate overall statistics
        total_assessments = len(compliance_data)
        latest_assessment = compliance_data[0] if compliance_data else {}

        # Get framework counts
        framework_counts = {}
        total_score = 0
        scored_assessments = 0

        for data in compliance_data:
            framework = data.get('framework', 'Unknown')
            framework_counts[framework] = framework_counts.get(framework, 0) + 1

            if 'overall_score' in data and data['overall_score'] is not None:
                total_score += data['overall_score']
                scored_assessments += 1
            elif 'overall_compliance' in data and data['overall_compliance'] is not None:
                total_score += data['overall_compliance']
                scored_assessments += 1

        average_score = total_score / scored_assessments if scored_assessments > 0 else 0

        # Compliance status
        if average_score >= 90:
            status_class = "status-excellent"
            status_text = "Excellent"
        elif average_score >= 80:
            status_class = "status-good"
            status_text = "Good"
        elif average_score >= 70:
            status_class = "status-needs-improvement"
            status_text = "Needs Improvement"
        else:
            status_class = "status-critical"
            status_text = "Critical"

        return f"""
        <div class="section summary-section">
            <h2>📊 Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-card">
                    <div class="card-title">Overall Compliance Score</div>
                    <div class="card-value {status_class}">{average_score:.1f}%</div>
                    <div class="card-status">{status_text}</div>
                </div>
                <div class="summary-card">
                    <div class="card-title">Total Assessments</div>
                    <div class="card-value">{total_assessments}</div>
                    <div class="card-subtitle">Across all frameworks</div>
                </div>
                <div class="summary-card">
                    <div class="card-title">Active Frameworks</div>
                    <div class="card-value">{len(framework_counts)}</div>
                    <div class="card-subtitle">Currently monitored</div>
                </div>
                <div class="summary-card">
                    <div class="card-title">Last Assessment</div>
                    <div class="card-value">{latest_assessment.get('framework', 'N/A')}</div>
                    <div class="card-subtitle">{latest_assessment.get('timestamp', 'N/A')[:10] if latest_assessment.get('timestamp') else 'N/A'}</div>
                </div>
            </div>
        </div>
        """

    def _generate_trends_section(self) -> str:
        """Generate compliance trends section"""
        return f"""
        <div class="section trends-section">
            <h2>📈 Compliance Trends</h2>
            <div class="chart-container">
                <canvas id="trendsChart" width="800" height="400"></canvas>
            </div>
        </div>
        """

    def _generate_frameworks_section(self, compliance_data: List[Dict]) -> str:
        """Generate frameworks overview section"""
        framework_summary = {}

        for data in compliance_data:
            framework = data.get('framework', 'Unknown')
            if framework not in framework_summary:
                framework_summary[framework] = {
                    'count': 0,
                    'latest_score': 0,
                    'latest_timestamp': '',
                    'status': 'Unknown'
                }

            framework_summary[framework]['count'] += 1

            # Get the latest assessment for this framework
            if data.get('timestamp', '') > framework_summary[framework]['latest_timestamp']:
                framework_summary[framework]['latest_timestamp'] = data.get('timestamp', '')
                framework_summary[framework]['latest_score'] = data.get('overall_score') or data.get('overall_compliance', 0)

        frameworks_html = ""
        for framework, summary in framework_summary.items():
            score = summary['latest_score']
            if score >= 80:
                status_class = "framework-good"
                status_icon = "✅"
            elif score >= 70:
                status_class = "framework-warning"
                status_icon = "⚠️"
            else:
                status_class = "framework-critical"
                status_icon = "❌"

            frameworks_html += f"""
            <div class="framework-card {status_class}">
                <div class="framework-header">
                    <h3>{status_icon} {framework}</h3>
                    <div class="framework-score">{score:.1f}%</div>
                </div>
                <div class="framework-details">
                    <div>Assessments: {summary['count']}</div>
                    <div>Last Updated: {summary['latest_timestamp'][:10] if summary['latest_timestamp'] else 'N/A'}</div>
                </div>
            </div>
            """

        return f"""
        <div class="section frameworks-section">
            <h2>🏛️ Framework Overview</h2>
            <div class="frameworks-grid">
                {frameworks_html}
            </div>
        </div>
        """

    def _generate_alerts_section(self, compliance_data: List[Dict]) -> str:
        """Generate alerts and recommendations section"""
        alerts = []

        for data in compliance_data:
            framework = data.get('framework', 'Unknown')
            score = data.get('overall_score') or data.get('overall_compliance', 0)

            if score < 70:
                alerts.append({
                    'type': 'critical',
                    'framework': framework,
                    'message': f'Compliance score below 70% ({score:.1f}%)',
                    'priority': 'high'
                })
            elif score < 80:
                alerts.append({
                    'type': 'warning',
                    'framework': framework,
                    'message': f'Compliance score needs improvement ({score:.1f}%)',
                    'priority': 'medium'
                })

            # Check for recommendations
            if 'recommendations' in data and data['recommendations']:
                for rec in data['recommendations'][:3]:  # Limit to top 3
                    alerts.append({
                        'type': 'recommendation',
                        'framework': framework,
                        'message': rec.get('remediation', rec.get('issue', 'Action required')),
                        'priority': 'medium'
                    })

        alerts_html = ""
        if alerts:
            for alert in alerts[:10]:  # Limit to top 10 alerts
                icon = "🚨" if alert['type'] == 'critical' else "⚠️" if alert['type'] == 'warning' else "💡"
                alerts_html += f"""
                <div class="alert alert-{alert['type']}">
                    <div class="alert-icon">{icon}</div>
                    <div class="alert-content">
                        <div class="alert-framework">{alert['framework']}</div>
                        <div class="alert-message">{alert['message']}</div>
                    </div>
                </div>
                """
        else:
            alerts_html = "<div class='no-alerts'>✅ No critical alerts at this time</div>"

        return f"""
        <div class="section alerts-section">
            <h2>🚨 Alerts & Recommendations</h2>
            <div class="alerts-container">
                {alerts_html}
            </div>
        </div>
        """

    def _generate_details_section(self, compliance_data: List[Dict]) -> str:
        """Generate detailed assessment results section"""
        details_html = ""

        for data in compliance_data[:5]:  # Show latest 5 assessments
            framework = data.get('framework', 'Unknown')
            timestamp = data.get('timestamp', '')
            score = data.get('overall_score') or data.get('overall_compliance', 0)

            details_html += f"""
            <div class="detail-card">
                <div class="detail-header">
                    <h4>{framework}</h4>
                    <div class="detail-score">{score:.1f}%</div>
                </div>
                <div class="detail-timestamp">{timestamp}</div>
                <div class="detail-controls">
                    <button onclick="viewDetails('{framework}', '{timestamp}')">View Details</button>
                    <button onclick="downloadReport('{framework}', '{timestamp}')">Download Report</button>
                </div>
            </div>
            """

        return f"""
        <div class="section details-section">
            <h2>📋 Recent Assessments</h2>
            <div class="details-grid">
                {details_html}
            </div>
        </div>
        """

    def _get_dashboard_css(self) -> str:
        """Get CSS styles for the dashboard"""
        return """
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }

        .dashboard-header {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            padding: 2rem;
            text-align: center;
            box-shadow: 0 2px 20px rgba(0, 0, 0, 0.1);
        }

        .dashboard-header h1 {
            font-size: 2.5rem;
            color: #2c3e50;
            margin-bottom: 0.5rem;
        }

        .timestamp {
            color: #7f8c8d;
            font-size: 1rem;
        }

        .dashboard-content {
            max-width: 1400px;
            margin: 2rem auto;
            padding: 0 2rem;
        }

        .section {
            background: white;
            border-radius: 15px;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
        }

        .section h2 {
            color: #2c3e50;
            margin-bottom: 1.5rem;
            font-size: 1.8rem;
            border-bottom: 3px solid #3498db;
            padding-bottom: 0.5rem;
        }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
        }

        .summary-card {
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            border-radius: 10px;
            padding: 1.5rem;
            text-align: center;
            border-left: 4px solid #3498db;
        }

        .card-title {
            font-size: 0.9rem;
            color: #6c757d;
            margin-bottom: 0.5rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .card-value {
            font-size: 2.5rem;
            font-weight: bold;
            margin-bottom: 0.5rem;
        }

        .status-excellent { color: #27ae60; }
        .status-good { color: #2ecc71; }
        .status-needs-improvement { color: #f39c12; }
        .status-critical { color: #e74c3c; }

        .frameworks-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
        }

        .framework-card {
            border-radius: 10px;
            padding: 1.5rem;
            border-left: 5px solid;
        }

        .framework-good { background: #d5f5e3; border-color: #27ae60; }
        .framework-warning { background: #fff3cd; border-color: #ffc107; }
        .framework-critical { background: #f8d7da; border-color: #dc3545; }

        .framework-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
        }

        .framework-score {
            font-size: 1.5rem;
            font-weight: bold;
        }

        .alerts-container {
            max-height: 400px;
            overflow-y: auto;
        }

        .alert {
            display: flex;
            align-items: center;
            padding: 1rem;
            margin-bottom: 1rem;
            border-radius: 8px;
            border-left: 4px solid;
        }

        .alert-critical { background: #f8d7da; border-color: #dc3545; }
        .alert-warning { background: #fff3cd; border-color: #ffc107; }
        .alert-recommendation { background: #d1ecf1; border-color: #17a2b8; }

        .alert-icon {
            font-size: 1.5rem;
            margin-right: 1rem;
        }

        .alert-framework {
            font-weight: bold;
            color: #495057;
        }

        .chart-container {
            position: relative;
            height: 400px;
            width: 100%;
        }

        .details-grid {
            display: grid;
            gap: 1rem;
        }

        .detail-card {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 1rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .detail-header {
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .detail-controls button {
            background: #007bff;
            color: white;
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 5px;
            margin-left: 0.5rem;
            cursor: pointer;
        }

        .detail-controls button:hover {
            background: #0056b3;
        }

        .no-alerts {
            text-align: center;
            padding: 2rem;
            color: #28a745;
            font-size: 1.2rem;
        }
        """

    def _get_dashboard_js(self) -> str:
        """Get JavaScript for dashboard interactivity"""
        return """
        // Sample data for trends chart
        const ctx = document.getElementById('trendsChart').getContext('2d');
        const trendsChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
                datasets: [{
                    label: 'Overall Compliance',
                    data: [75, 78, 82, 85, 87, 89],
                    borderColor: '#3498db',
                    backgroundColor: 'rgba(52, 152, 219, 0.1)',
                    tension: 0.4
                }, {
                    label: 'ISO 27001',
                    data: [72, 75, 79, 83, 85, 88],
                    borderColor: '#2ecc71',
                    backgroundColor: 'rgba(46, 204, 113, 0.1)',
                    tension: 0.4
                }, {
                    label: 'GDPR',
                    data: [78, 81, 85, 87, 89, 90],
                    borderColor: '#e74c3c',
                    backgroundColor: 'rgba(231, 76, 60, 0.1)',
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: false,
                        min: 60,
                        max: 100,
                        ticks: {
                            callback: function(value) {
                                return value + '%';
                            }
                        }
                    }
                },
                plugins: {
                    legend: {
                        position: 'top',
                    },
                    title: {
                        display: true,
                        text: 'Compliance Score Trends Over Time'
                    }
                }
            }
        });

        function viewDetails(framework, timestamp) {
            alert(`Viewing details for ${framework} assessment from ${timestamp}`);
            // Implementation would open detailed view
        }

        function downloadReport(framework, timestamp) {
            alert(`Downloading report for ${framework} from ${timestamp}`);
            // Implementation would trigger report download
        }

        // Auto-refresh dashboard every 5 minutes
        setTimeout(() => {
            location.reload();
        }, 300000);
        """

def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description='Compliance Dashboard Generator')
    parser.add_argument('--data-dir', default='./compliance-reports', help='Directory containing compliance reports')
    parser.add_argument('--output', default='compliance_dashboard.html', help='Output HTML file')
    parser.add_argument('--db-path', default='./compliance.db', help='SQLite database path')
    parser.add_argument('--auto-refresh', action='store_true', help='Enable auto-refresh')

    args = parser.parse_args()

    dashboard = ComplianceDashboard(data_dir=args.data_dir, db_path=args.db_path)
    output_file = dashboard.generate_dashboard_html(args.output)

    print(f"📊 Compliance dashboard generated: {output_file}")
    print(f"🌐 Open {output_file} in your browser to view the dashboard")

if __name__ == "__main__":
    main()