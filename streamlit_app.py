import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
import json
import requests
import time
from typing import Dict, List, Tuple, Optional
import hashlib
import uuid
import re
from pathlib import Path
import base64
from io import BytesIO
import logging
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Optional: Import for real Claude AI integration
try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

# Page configuration
st.set_page_config(
    page_title="Container Vulnerability Management Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ==============================================================================
# STREAMLIT CLOUD OPTIMIZED CLASSES
# ==============================================================================

class CVEIntegrator:
    """Integrate with CVE databases and vulnerability feeds - Cloud optimized"""
    
    def __init__(self):
        self.nist_nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.cache = {}
        self.cache_ttl = 3600  # 1 hour cache
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Container-Vulnerability-Platform/1.0'
        })
    
    @st.cache_data(ttl=3600)
    def get_cve_details(_self, cve_id: str) -> Dict:
        """Get detailed information about a specific CVE"""
        try:
            params = {'cveId': cve_id}
            response = _self.session.get(_self.nist_nvd_url, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('vulnerabilities'):
                    vuln = data['vulnerabilities'][0]
                    cve_data = vuln['cve']
                    
                    return {
                        'id': cve_id,
                        'description': _self._extract_description(cve_data),
                        'severity': _self._extract_severity(vuln),
                        'cvss_score': _self._extract_cvss_score(vuln),
                        'published_date': cve_data.get('published', 'Unknown'),
                        'modified_date': cve_data.get('lastModified', 'Unknown'),
                        'affected_products': _self._extract_affected_products(cve_data),
                        'references': _self._extract_references(cve_data),
                        'cwe_ids': _self._extract_cwe_ids(cve_data)
                    }
            
            return {'id': cve_id, 'error': 'CVE not found or API error'}
            
        except Exception as e:
            logger.error(f"Error fetching CVE {cve_id}: {str(e)}")
            return {'id': cve_id, 'error': str(e)}
    
    @st.cache_data(ttl=3600)
    def search_cves_by_product(_self, product_name: str, limit: int = 50) -> List[Dict]:
        """Search for CVEs affecting a specific product"""
        try:
            params = {
                'keywordSearch': product_name,
                'resultsPerPage': min(limit, 100)
            }
            
            response = _self.session.get(_self.nist_nvd_url, params=params, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                cves = []
                
                for vuln in data.get('vulnerabilities', []):
                    cve_data = vuln['cve']
                    cve_info = {
                        'id': cve_data['id'],
                        'description': _self._extract_description(cve_data)[:200] + '...',
                        'severity': _self._extract_severity(vuln),
                        'cvss_score': _self._extract_cvss_score(vuln),
                        'published_date': cve_data.get('published', 'Unknown')
                    }
                    cves.append(cve_info)
                
                return cves
            
            return []
            
        except Exception as e:
            logger.error(f"Error searching CVEs for {product_name}: {str(e)}")
            return []
    
    def _extract_description(self, cve_data: Dict) -> str:
        """Extract description from CVE data"""
        descriptions = cve_data.get('descriptions', [])
        for desc in descriptions:
            if desc.get('lang') == 'en':
                return desc.get('value', 'No description available')
        return 'No description available'
    
    def _extract_severity(self, vuln: Dict) -> str:
        """Extract severity from vulnerability data"""
        metrics = vuln.get('metrics', {})
        
        if 'cvssMetricV31' in metrics:
            return metrics['cvssMetricV31'][0]['cvssData'].get('baseSeverity', 'UNKNOWN')
        if 'cvssMetricV30' in metrics:
            return metrics['cvssMetricV30'][0]['cvssData'].get('baseSeverity', 'UNKNOWN')
        if 'cvssMetricV2' in metrics:
            score = metrics['cvssMetricV2'][0]['cvssData'].get('baseScore', 0)
            if score >= 7.0:
                return 'HIGH'
            elif score >= 4.0:
                return 'MEDIUM'
            else:
                return 'LOW'
        
        return 'UNKNOWN'
    
    def _extract_cvss_score(self, vuln: Dict) -> float:
        """Extract CVSS score from vulnerability data"""
        metrics = vuln.get('metrics', {})
        
        if 'cvssMetricV31' in metrics:
            return metrics['cvssMetricV31'][0]['cvssData'].get('baseScore', 0.0)
        if 'cvssMetricV30' in metrics:
            return metrics['cvssMetricV30'][0]['cvssData'].get('baseScore', 0.0)
        if 'cvssMetricV2' in metrics:
            return metrics['cvssMetricV2'][0]['cvssData'].get('baseScore', 0.0)
        
        return 0.0
    
    def _extract_affected_products(self, cve_data: Dict) -> List[str]:
        """Extract affected products from CVE data"""
        products = []
        configurations = cve_data.get('configurations', [])
        
        for config in configurations:
            for node in config.get('nodes', []):
                for cpe_match in node.get('cpeMatch', []):
                    cpe_name = cpe_match.get('criteria', '')
                    if cpe_name:
                        parts = cpe_name.split(':')
                        if len(parts) >= 5:
                            vendor = parts[3]
                            product = parts[4]
                            products.append(f"{vendor}:{product}")
        
        return list(set(products))
    
    def _extract_references(self, cve_data: Dict) -> List[str]:
        """Extract references from CVE data"""
        references = []
        for ref in cve_data.get('references', []):
            url = ref.get('url', '')
            if url:
                references.append(url)
        return references
    
    def _extract_cwe_ids(self, cve_data: Dict) -> List[str]:
        """Extract CWE IDs from CVE data"""
        cwe_ids = []
        weaknesses = cve_data.get('weaknesses', [])
        
        for weakness in weaknesses:
            for desc in weakness.get('description', []):
                if desc.get('lang') == 'en':
                    cwe_ids.append(desc.get('value', ''))
        
        return cwe_ids


class DockerfileAnalyzer:
    """Analyze Dockerfile content for security issues - Cloud optimized"""
    
    def __init__(self):
        self.vulnerability_patterns = {
            'outdated_base_images': {
                'patterns': [
                    r'FROM\s+ubuntu:(14\.04|16\.04|18\.04)',
                    r'FROM\s+centos:[1-6]',
                    r'FROM\s+debian:[7-9]',
                    r'FROM\s+alpine:3\.[0-9](?:\.|$)',
                    r'FROM\s+node:[0-9](?:\.|$)',
                    r'FROM\s+python:[2-3]\.[0-6](?:\.|$)'
                ],
                'severity': 'HIGH',
                'description': 'Outdated base image that may contain known vulnerabilities'
            },
            'insecure_configurations': {
                'patterns': [
                    r'USER\s+root\s*$',
                    r'--privileged',
                    r'COPY\s+\.\s+/',
                    r'ADD\s+.*\s+/',
                    r'chmod\s+777',
                    r'sudo\s+',
                    r'--disable-content-trust'
                ],
                'severity': 'MEDIUM',
                'description': 'Insecure configuration that may pose security risks'
            },
            'exposed_secrets': {
                'patterns': [
                    r'password\s*=\s*["\'].*["\']',
                    r'api[_-]?key\s*=\s*["\'].*["\']',
                    r'secret\s*=\s*["\'].*["\']',
                    r'token\s*=\s*["\'].*["\']',
                    r'AWS_SECRET_ACCESS_KEY\s*=',
                    r'DATABASE_PASSWORD\s*='
                ],
                'severity': 'CRITICAL',
                'description': 'Potential exposed secret or sensitive information'
            },
            'missing_healthcheck': {
                'patterns': [r'^(?!.*HEALTHCHECK).*$'],
                'severity': 'LOW',
                'description': 'Missing health check configuration'
            }
        }
    
    def analyze_dockerfile(self, dockerfile_content: str) -> List[Dict]:
        """Analyze Dockerfile content for security issues"""
        vulnerabilities = []
        lines = dockerfile_content.split('\n')
        
        # Check for missing HEALTHCHECK
        has_healthcheck = any('HEALTHCHECK' in line for line in lines)
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Check each vulnerability category
            for category, config in self.vulnerability_patterns.items():
                if category == 'missing_healthcheck':
                    continue  # Handle separately
                
                for pattern in config['patterns']:
                    if re.search(pattern, line, re.IGNORECASE):
                        vuln = {
                            'type': 'dockerfile_issue',
                            'category': category,
                            'severity': config['severity'],
                            'line_number': line_num,
                            'line_content': line,
                            'description': config['description'],
                            'remediation': self._get_remediation(category, pattern),
                            'id': f"DOCKERFILE-{category.upper()}-{line_num}",
                            'discovered_date': datetime.now().isoformat(),
                            'status': 'open'
                        }
                        vulnerabilities.append(vuln)
        
        # Check for missing HEALTHCHECK
        if not has_healthcheck and len(lines) > 5:  # Only for substantial Dockerfiles
            vuln = {
                'type': 'dockerfile_issue',
                'category': 'missing_healthcheck',
                'severity': 'LOW',
                'line_number': len(lines),
                'line_content': '# HEALTHCHECK missing',
                'description': 'Dockerfile missing HEALTHCHECK instruction',
                'remediation': 'Add HEALTHCHECK instruction to monitor container health',
                'id': f"DOCKERFILE-HEALTHCHECK-{len(lines)}",
                'discovered_date': datetime.now().isoformat(),
                'status': 'open'
            }
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _get_remediation(self, category: str, pattern: str) -> str:
        """Get remediation advice for a pattern"""
        remediations = {
            'outdated_base_images': 'Update to the latest stable version of the base image',
            'insecure_configurations': 'Review and secure the configuration according to best practices',
            'exposed_secrets': 'Move secrets to environment variables or secret management systems',
            'missing_healthcheck': 'Add HEALTHCHECK instruction to monitor container health'
        }
        return remediations.get(category, 'Review and fix the security issue')


class VulnerabilityAnalyzer:
    """Analyze vulnerabilities and provide risk assessments - Cloud optimized"""
    
    def __init__(self):
        self.severity_weights = {
            'CRITICAL': 10,
            'HIGH': 7,
            'MEDIUM': 4,
            'LOW': 2,
            'UNKNOWN': 1
        }
    
    def calculate_risk_score(self, vulnerabilities: List[Dict]) -> Dict:
        """Calculate overall risk score for a set of vulnerabilities"""
        if not vulnerabilities:
            return {
                'total_score': 0,
                'risk_level': 'LOW',
                'vulnerability_count': 0,
                'severity_breakdown': {}
            }
        
        total_score = 0
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'UNKNOWN').upper()
            weight = self.severity_weights.get(severity, 1)
            
            # Apply additional weights based on vulnerability characteristics
            if vuln.get('category') == 'exposed_secrets':
                weight *= 2.0
            
            total_score += weight
            severity_counts[severity] += 1
        
        # Determine risk level
        avg_score = total_score / len(vulnerabilities) if vulnerabilities else 0
        
        if avg_score >= 8 or severity_counts['CRITICAL'] > 0:
            risk_level = 'CRITICAL'
        elif avg_score >= 6 or severity_counts['HIGH'] > 2:
            risk_level = 'HIGH'
        elif avg_score >= 4 or severity_counts['MEDIUM'] > 5:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        return {
            'total_score': total_score,
            'average_score': avg_score,
            'risk_level': risk_level,
            'vulnerability_count': len(vulnerabilities),
            'severity_breakdown': severity_counts
        }
    
    def prioritize_vulnerabilities(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Prioritize vulnerabilities based on risk factors"""
        
        def calculate_priority_score(vuln: Dict) -> float:
            base_score = self.severity_weights.get(vuln.get('severity', 'UNKNOWN').upper(), 1)
            
            # Factors that increase priority
            multipliers = 1.0
            
            if vuln.get('category') == 'exposed_secrets':
                multipliers *= 2.0
            
            if vuln.get('cvss_score', 0) > 9.0:
                multipliers *= 1.5
            
            # Age factor (newer vulnerabilities get higher priority)
            published_date = vuln.get('published_date')
            if published_date:
                try:
                    pub_date = datetime.fromisoformat(published_date.replace('Z', '+00:00'))
                    days_old = (datetime.now() - pub_date.replace(tzinfo=None)).days
                    
                    if days_old < 30:  # Very recent
                        multipliers *= 1.3
                    elif days_old < 90:  # Recent
                        multipliers *= 1.1
                    elif days_old > 365:  # Old
                        multipliers *= 0.9
                except:
                    pass
            
            return base_score * multipliers
        
        # Calculate priority scores and sort
        for vuln in vulnerabilities:
            vuln['priority_score'] = calculate_priority_score(vuln)
        
        return sorted(vulnerabilities, key=lambda x: x.get('priority_score', 0), reverse=True)


class AIRemediationEngine:
    """AI-powered vulnerability remediation recommendations - Cloud optimized"""
    
    def __init__(self):
        self.anthropic_client = None
        self._initialize_ai()
        
        # Built-in remediation knowledge base
        self.remediation_kb = {
            'outdated_base_images': {
                'strategy': 'Update base images to latest stable versions',
                'steps': [
                    'Identify current base image version',
                    'Check for latest stable version',
                    'Update Dockerfile with new base image',
                    'Test updated image thoroughly',
                    'Deploy updated image'
                ],
                'automation': 'dockerfile_update'
            },
            'exposed_secrets': {
                'strategy': 'Implement proper secret management',
                'steps': [
                    'Identify exposed secrets',
                    'Remove secrets from code/config',
                    'Implement secret management system',
                    'Update application to use secret manager',
                    'Rotate exposed secrets'
                ],
                'automation': 'secret_remediation'
            },
            'insecure_configurations': {
                'strategy': 'Implement security best practices',
                'steps': [
                    'Review current configuration',
                    'Apply security hardening',
                    'Implement least privilege principle',
                    'Add security scanning to CI/CD',
                    'Regular security audits'
                ],
                'automation': 'config_hardening'
            }
        }
    
    def _initialize_ai(self):
        """Initialize AI client using Streamlit secrets"""
        try:
            if ANTHROPIC_AVAILABLE and hasattr(st, 'secrets') and 'CLAUDE_API_KEY' in st.secrets:
                self.anthropic_client = anthropic.Anthropic(api_key=st.secrets["CLAUDE_API_KEY"])
                st.success("🤖 Claude AI integration enabled")
            else:
                st.info("💡 Add CLAUDE_API_KEY to secrets for AI-powered recommendations")
        except Exception as e:
            st.warning(f"⚠️ AI initialization error: {str(e)}")
    
    def generate_remediation_plan(self, vulnerabilities: List[Dict]) -> Dict:
        """Generate comprehensive remediation plan"""
        plan = {
            'immediate_actions': [],
            'short_term_actions': [],
            'long_term_actions': [],
            'automated_fixes': [],
            'manual_steps': [],
            'estimated_effort': 'Unknown',
            'risk_reduction': 0
        }
        
        # Group vulnerabilities by category for efficient remediation
        vuln_groups = {}
        for vuln in vulnerabilities:
            category = vuln.get('category', 'unknown')
            if category not in vuln_groups:
                vuln_groups[category] = []
            vuln_groups[category].append(vuln)
        
        total_effort_hours = 0
        total_risk_reduction = 0
        
        for category, vuln_list in vuln_groups.items():
            remediation = self._get_remediation_for_category(category, vuln_list)
            
            # Categorize actions by urgency
            if any(v.get('severity') == 'CRITICAL' for v in vuln_list):
                plan['immediate_actions'].extend(remediation['immediate'])
            elif any(v.get('severity') == 'HIGH' for v in vuln_list):
                plan['short_term_actions'].extend(remediation['short_term'])
            else:
                plan['long_term_actions'].extend(remediation['long_term'])
            
            # Add automation opportunities
            if remediation.get('automation'):
                plan['automated_fixes'].append(remediation['automation'])
            
            # Add manual steps
            plan['manual_steps'].extend(remediation.get('manual_steps', []))
            
            # Accumulate effort and risk reduction
            total_effort_hours += remediation.get('effort_hours', 2)
            total_risk_reduction += remediation.get('risk_reduction', 10)
        
        plan['estimated_effort'] = f"{total_effort_hours} hours"
        plan['risk_reduction'] = min(100, total_risk_reduction)
        
        # Get AI-enhanced recommendations if available
        if self.anthropic_client:
            ai_recommendations = self._get_ai_recommendations(vulnerabilities)
            plan['ai_recommendations'] = ai_recommendations
        
        return plan
    
    def _get_remediation_for_category(self, category: str, vulnerabilities: List[Dict]) -> Dict:
        """Get specific remediation steps for vulnerability category"""
        
        # Check knowledge base
        kb_entry = self.remediation_kb.get(category)
        if kb_entry:
            return {
                'immediate': kb_entry['steps'][:2],
                'short_term': kb_entry['steps'][2:4],
                'long_term': kb_entry['steps'][4:],
                'automation': {
                    'type': kb_entry.get('automation'),
                    'description': kb_entry['strategy'],
                    'feasibility': 'HIGH'
                },
                'manual_steps': kb_entry['steps'],
                'effort_hours': len(vulnerabilities) * 2,
                'risk_reduction': len(vulnerabilities) * 15
            }
        
        # Default remediation for unknown categories
        return {
            'immediate': ['Assess vulnerability impact', 'Apply temporary mitigations'],
            'short_term': ['Research proper fix', 'Test remediation'],
            'long_term': ['Implement permanent fix', 'Update security policies'],
            'automation': None,
            'manual_steps': ['Manual assessment required'],
            'effort_hours': len(vulnerabilities) * 4,
            'risk_reduction': len(vulnerabilities) * 10
        }
    
    def _get_ai_recommendations(self, vulnerabilities: List[Dict]) -> str:
        """Get AI-powered recommendations using Claude"""
        if not self.anthropic_client:
            return "AI recommendations unavailable - API key not configured"
        
        try:
            # Prepare vulnerability summary for AI
            vuln_summary = []
            for vuln in vulnerabilities[:10]:  # Limit to top 10 for context
                summary = f"- {vuln.get('id', 'Unknown')}: {vuln.get('severity', 'Unknown')} - {vuln.get('description', 'No description')[:100]}"
                vuln_summary.append(summary)
            
            context = f"""
            Analyze these container vulnerabilities and provide specific remediation recommendations:
            
            {chr(10).join(vuln_summary)}
            
            Please provide:
            1. Priority order for fixing these vulnerabilities
            2. Specific technical steps for remediation
            3. Automation opportunities
            4. Best practices to prevent similar issues
            
            Focus on practical, actionable advice for a DevSecOps team.
            """
            
            response = self.anthropic_client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1000,
                temperature=0.3,
                messages=[{"role": "user", "content": context}]
            )
            
            return response.content[0].text if response.content else "No AI recommendations available"
            
        except Exception as e:
            logger.error(f"AI recommendation error: {str(e)}")
            return f"AI recommendation error: {str(e)}"
    
    def generate_fix_script(self, vulnerability: Dict) -> str:
        """Generate automated fix script for a vulnerability"""
        category = vulnerability.get('category', '')
        
        if category == 'outdated_base_images':
            return self._generate_dockerfile_update_script(vulnerability)
        elif category == 'exposed_secrets':
            return self._generate_secret_remediation_script(vulnerability)
        elif category == 'insecure_configurations':
            return self._generate_config_fix_script(vulnerability)
        else:
            return "# Manual remediation required\n# No automated script available for this vulnerability type"
    
    def _generate_dockerfile_update_script(self, vulnerability: Dict) -> str:
        """Generate script to update Dockerfile base images"""
        return """#!/bin/bash
# Automated Dockerfile base image update script

echo "Updating base image in Dockerfile..."

# Backup original Dockerfile
cp Dockerfile Dockerfile.backup.$(date +%Y%m%d_%H%M%S)

# Update common outdated base images
sed -i 's/ubuntu:16.04/ubuntu:22.04/g' Dockerfile
sed -i 's/ubuntu:18.04/ubuntu:22.04/g' Dockerfile
sed -i 's/centos:6/centos:8/g' Dockerfile
sed -i 's/centos:7/centos:8/g' Dockerfile
sed -i 's/debian:8/debian:11/g' Dockerfile
sed -i 's/debian:9/debian:11/g' Dockerfile
sed -i 's/alpine:3.[0-9]/alpine:3.17/g' Dockerfile

echo "Base image update complete. Please review changes and test thoroughly."
echo "Original Dockerfile backed up to Dockerfile.backup.*"
"""
    
    def _generate_secret_remediation_script(self, vulnerability: Dict) -> str:
        """Generate script to remediate exposed secrets"""
        return """#!/bin/bash
# Automated secret remediation script

echo "Scanning for exposed secrets..."

# Create environment variable template
cat > .env.template << EOF
# Environment Variables Template
# Copy to .env and fill in actual values

PASSWORD=your_password_here
API_KEY=your_api_key_here
SECRET=your_secret_here
TOKEN=your_token_here
DATABASE_PASSWORD=your_db_password_here
EOF

echo "Created .env.template file"
echo "Please:"
echo "1. Copy .env.template to .env"
echo "2. Fill in actual secret values in .env"
echo "3. Add .env to .gitignore"
echo "4. Update your application to read from environment variables"
echo "5. Remove hardcoded secrets from your code"
"""
    
    def _generate_config_fix_script(self, vulnerability: Dict) -> str:
        """Generate script to fix insecure configurations"""
        return """#!/bin/bash
# Automated configuration security fix script

echo "Creating secure Dockerfile template..."

cat > Dockerfile.secure << 'EOF'
# Use specific version instead of latest
FROM ubuntu:22.04

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Install packages and clean up
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    your-packages-here && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy application files with proper ownership
COPY --chown=appuser:appuser ./app /app

# Set working directory
WORKDIR /app

# Switch to non-root user
USER appuser

# Add health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Expose port
EXPOSE 8080

# Run application
CMD ["your-app-command"]
EOF

echo "Created Dockerfile.secure with security best practices"
echo "Please review and replace your current Dockerfile"
"""


# ==============================================================================
# MAIN APPLICATION CLASS - STREAMLIT CLOUD OPTIMIZED
# ==============================================================================

class ContainerVulnerabilityPlatform:
    """Main application class for Container Vulnerability Management - Cloud optimized"""
    
    def __init__(self):
        self.initialize_session_state()
        self.setup_custom_css()
        
        # Initialize core components
        self.cve_integrator = CVEIntegrator()
        self.dockerfile_analyzer = DockerfileAnalyzer()
        self.vulnerability_analyzer = VulnerabilityAnalyzer()
        self.ai_engine = AIRemediationEngine()
    
    def initialize_session_state(self):
        """Initialize session state variables"""
        if 'vulnerabilities' not in st.session_state:
            st.session_state.vulnerabilities = []
        if 'scan_history' not in st.session_state:
            st.session_state.scan_history = []
        if 'active_tab' not in st.session_state:
            st.session_state.active_tab = "dashboard"
        if 'remediation_plans' not in st.session_state:
            st.session_state.remediation_plans = {}
    
    def setup_custom_css(self):
        """Setup custom CSS styling"""
        st.markdown("""
        <style>
            .main-header {
                background: linear-gradient(135deg, #dc3545 0%, #6f42c1 100%);
                padding: 2rem;
                border-radius: 15px;
                color: white;
                text-align: center;
                margin-bottom: 2rem;
                box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            }
            
            .vulnerability-card {
                background: white;
                padding: 1.5rem;
                border-radius: 12px;
                margin: 1rem 0;
                box-shadow: 0 2px 12px rgba(0,0,0,0.1);
                border-left: 5px solid #dc3545;
            }
            
            .critical-vuln {
                border-left-color: #dc3545;
                background: linear-gradient(135deg, #fff5f5 0%, #fed7d7 100%);
            }
            
            .high-vuln {
                border-left-color: #fd7e14;
                background: linear-gradient(135deg, #fffaf0 0%, #feebc8 100%);
            }
            
            .medium-vuln {
                border-left-color: #ffc107;
                background: linear-gradient(135deg, #fffff0 0%, #fefcbf 100%);
            }
            
            .low-vuln {
                border-left-color: #28a745;
                background: linear-gradient(135deg, #f0fff4 0%, #c6f6d5 100%);
            }
            
            .section-header {
                background: linear-gradient(135deg, #6f42c1 0%, #007bff 100%);
                color: white;
                padding: 1rem 1.5rem;
                border-radius: 8px;
                margin: 1.5rem 0 1rem 0;
                font-size: 1.2rem;
                font-weight: bold;
                box-shadow: 0 2px 8px rgba(111,66,193,0.3);
            }
            
            .metric-card {
                background: linear-gradient(135deg, #ffffff 0%, #f8f9fa 100%);
                padding: 1.5rem;
                border-radius: 12px;
                border-left: 5px solid #6f42c1;
                margin: 0.75rem 0;
                box-shadow: 0 2px 12px rgba(0,0,0,0.08);
            }
            
            .remediation-card {
                background: linear-gradient(135deg, #e8f4fd 0%, #bee5eb 100%);
                padding: 1.5rem;
                border-radius: 12px;
                border-left: 5px solid #17a2b8;
                margin: 1rem 0;
                box-shadow: 0 3px 15px rgba(23,162,184,0.1);
            }
            
            .cloud-notice {
                background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
                padding: 1rem;
                border-radius: 8px;
                border-left: 4px solid #007bff;
                margin: 1rem 0;
            }
        </style>
        """, unsafe_allow_html=True)
    
    def render_header(self):
        """Render the main header"""
        st.markdown("""
        <div class="main-header">
            <h1>🛡️ Container Vulnerability Management Platform</h1>
            <p style="font-size: 1.1rem; margin-top: 0.5rem;">AI-Powered Security • CVE Intelligence • Dockerfile Analysis</p>
            <p style="font-size: 0.9rem; margin-top: 0.5rem; opacity: 0.9;">Cloud-Optimized • Real-time CVE Data • Automated Remediation</p>
        </div>
        """, unsafe_allow_html=True)
    
    def render_navigation(self):
        """Render navigation tabs"""
        col1, col2, col3, col4, col5, col6 = st.columns(6)
        
        with col1:
            if st.button("🏠 Dashboard", key="nav_dashboard"):
                st.session_state.active_tab = "dashboard"
        with col2:
            if st.button("🔍 CVE Lookup", key="nav_cve"):
                st.session_state.active_tab = "cve"
        with col3:
            if st.button("📄 Dockerfile Scan", key="nav_dockerfile"):
                st.session_state.active_tab = "dockerfile"
        with col4:
            if st.button("🤖 AI Remediation", key="nav_ai"):
                st.session_state.active_tab = "ai_remediation"
        with col5:
            if st.button("📊 Analytics", key="nav_analytics"):
                st.session_state.active_tab = "analytics"
        with col6:
            if st.button("📋 Reports", key="nav_reports"):
                st.session_state.active_tab = "reports"
    
    def render_sidebar_controls(self):
        """Render sidebar controls"""
        st.sidebar.markdown("## ⚙️ Configuration")
        
        # Platform Notice
        st.sidebar.markdown("""
        <div class="cloud-notice">
            <strong>🌤️ Streamlit Cloud Version</strong><br>
            Optimized for cloud deployment with CVE intelligence and Dockerfile analysis.
        </div>
        """, unsafe_allow_html=True)
        
        # AI Configuration
        st.sidebar.subheader("🤖 AI Configuration")
        st.sidebar.info("Add CLAUDE_API_KEY to Streamlit Cloud secrets for AI recommendations")
        
        # Analysis Settings
        st.sidebar.subheader("🔍 Analysis Settings")
        scan_depth = st.sidebar.selectbox(
            "Scan Depth",
            ["Basic", "Detailed", "Comprehensive"],
            index=1,
            key="scan_depth"
        )
        
        include_low_severity = st.sidebar.checkbox("Include Low Severity", value=False, key="include_low")
        auto_prioritize = st.sidebar.checkbox("Auto-prioritize vulnerabilities", value=True, key="auto_prioritize")
        
        # CVE Settings
        st.sidebar.subheader("🗃️ CVE Settings")
        max_cve_results = st.sidebar.slider("Max CVE Results", 10, 100, 50, key="max_cve_results")
        cache_duration = st.sidebar.slider("Cache Duration (hours)", 1, 24, 6, key="cache_duration")
        
        # Report Settings
        st.sidebar.subheader("📋 Reports")
        include_remediation = st.sidebar.checkbox("Include remediation steps", value=True, key="include_remediation")
        export_format = st.sidebar.selectbox("Export Format", ["Markdown", "JSON", "CSV"], key="export_format")
        
        return {
            'scan_depth': scan_depth,
            'include_low_severity': include_low_severity,
            'auto_prioritize': auto_prioritize,
            'max_cve_results': max_cve_results,
            'cache_duration': cache_duration,
            'include_remediation': include_remediation,
            'export_format': export_format
        }
    
    def render_dashboard_tab(self, config):
        """Render the main dashboard"""
        st.markdown('<div class="section-header">🏠 Security Dashboard</div>', unsafe_allow_html=True)
        
        # Get current vulnerability stats
        vulnerabilities = st.session_state.vulnerabilities
        
        if vulnerabilities:
            # Calculate statistics
            total_vulns = len(vulnerabilities)
            critical_count = len([v for v in vulnerabilities if v.get('severity') == 'CRITICAL'])
            high_count = len([v for v in vulnerabilities if v.get('severity') == 'HIGH'])
            medium_count = len([v for v in vulnerabilities if v.get('severity') == 'MEDIUM'])
            low_count = len([v for v in vulnerabilities if v.get('severity') == 'LOW'])
            
            open_count = len([v for v in vulnerabilities if v.get('status') == 'open'])
            resolved_count = len([v for v in vulnerabilities if v.get('status') == 'resolved'])
            
            # Overview metrics
            col1, col2, col3, col4, col5 = st.columns(5)
            
            with col1:
                st.metric("Total Vulnerabilities", total_vulns)
            
            with col2:
                st.metric("Critical Issues", critical_count, delta="🔴" if critical_count > 0 else "✅")
            
            with col3:
                st.metric("High Priority", high_count, delta="🟠" if high_count > 0 else "✅")
            
            with col4:
                st.metric("Open Issues", open_count, delta="⚠️" if open_count > 0 else "✅")
            
            with col5:
                resolution_rate = (resolved_count / total_vulns * 100) if total_vulns > 0 else 0
                st.metric("Resolution Rate", f"{resolution_rate:.1f}%", delta=f"{resolved_count} resolved")
            
            # Severity distribution chart
            severity_data = {
                'CRITICAL': critical_count,
                'HIGH': high_count,
                'MEDIUM': medium_count,
                'LOW': low_count
            }
            
            if any(severity_data.values()):
                fig_severity = px.pie(
                    values=list(severity_data.values()),
                    names=list(severity_data.keys()),
                    title="Vulnerability Distribution by Severity",
                    color_discrete_map={
                        'CRITICAL': '#dc3545',
                        'HIGH': '#fd7e14',
                        'MEDIUM': '#ffc107',
                        'LOW': '#28a745'
                    }
                )
                st.plotly_chart(fig_severity, use_container_width=True)
            
            # Recent vulnerabilities
            st.markdown('<div class="section-header">🚨 Recent High-Priority Vulnerabilities</div>', unsafe_allow_html=True)
            
            # Sort by priority and show top 5
            sorted_vulns = sorted(vulnerabilities, 
                                key=lambda x: x.get('priority_score', 0), reverse=True)[:5]
            
            for vuln in sorted_vulns:
                severity = vuln.get('severity', 'UNKNOWN')
                severity_class = f"{severity.lower()}-vuln"
                
                st.markdown(f"""
                <div class="vulnerability-card {severity_class}">
                    <strong>{vuln.get('id', 'Unknown')}</strong> - {severity} Severity
                    <br>
                    <em>{vuln.get('description', 'No description')[:150]}...</em>
                    <br>
                    <small>Line: {vuln.get('line_number', 'N/A')} | Status: {vuln.get('status', 'Open')}</small>
                </div>
                """, unsafe_allow_html=True)
        
        else:
            st.info("No vulnerabilities detected. Start by analyzing a Dockerfile or searching CVE database.")
        
        # Quick actions
        st.markdown('<div class="section-header">⚡ Quick Actions</div>', unsafe_allow_html=True)
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            if st.button("📄 Analyze Dockerfile", type="primary"):
                st.session_state.active_tab = "dockerfile"
                st.rerun()
        
        with col2:
            if st.button("🔍 Search CVEs", type="secondary"):
                st.session_state.active_tab = "cve"
                st.rerun()
        
        with col3:
            if st.button("🤖 AI Remediation", type="secondary"):
                if vulnerabilities:
                    st.session_state.active_tab = "ai_remediation"
                    st.rerun()
                else:
                    st.warning("No vulnerabilities found. Analyze a Dockerfile first.")
        
        with col4:
            if st.button("📊 View Analytics", type="secondary"):
                st.session_state.active_tab = "analytics"
                st.rerun()
    
    def render_cve_tab(self, config):
        """Render CVE database integration tab"""
        st.markdown('<div class="section-header">🗃️ CVE Database Integration</div>', unsafe_allow_html=True)
        
        tab1, tab2 = st.tabs(["🔍 CVE Lookup", "📊 Product Search"])
        
        with tab1:
            st.subheader("CVE Lookup")
            
            cve_id = st.text_input("Enter CVE ID", placeholder="CVE-2023-12345")
            
            if st.button("🔍 Lookup CVE", type="primary"):
                if cve_id:
                    with st.spinner(f"Fetching CVE details for {cve_id}..."):
                        cve_details = self.cve_integrator.get_cve_details(cve_id)
                        
                        if 'error' not in cve_details:
                            col1, col2 = st.columns([2, 1])
                            
                            with col1:
                                st.markdown(f"""
                                **CVE ID:** {cve_details['id']}
                                
                                **Severity:** {cve_details['severity']}
                                
                                **CVSS Score:** {cve_details['cvss_score']}
                                
                                **Description:**
                                {cve_details['description']}
                                
                                **Published:** {cve_details['published_date']}
                                
                                **Last Modified:** {cve_details['modified_date']}
                                """)
                            
                            with col2:
                                st.markdown("**Affected Products:**")
                                for product in cve_details.get('affected_products', [])[:10]:
                                    st.write(f"• {product}")
                                
                                st.markdown("**CWE IDs:**")
                                for cwe in cve_details.get('cwe_ids', []):
                                    st.write(f"• {cwe}")
                                
                                # Add to vulnerabilities for tracking
                                if st.button("➕ Add to Tracking"):
                                    vuln = {
                                        'id': cve_details['id'],
                                        'severity': cve_details['severity'],
                                        'description': cve_details['description'],
                                        'cvss_score': cve_details['cvss_score'],
                                        'type': 'cve_lookup',
                                        'category': 'external_cve',
                                        'status': 'open',
                                        'discovered_date': datetime.now().isoformat(),
                                        'priority_score': cve_details['cvss_score']
                                    }
                                    st.session_state.vulnerabilities.append(vuln)
                                    st.success("CVE added to vulnerability tracking!")
                        else:
                            st.error(f"Error: {cve_details['error']}")
                else:
                    st.warning("Please enter a CVE ID.")
        
        with tab2:
            st.subheader("Product Vulnerability Search")
            
            col1, col2 = st.columns([2, 1])
            
            with col1:
                product_name = st.text_input("Product Name", placeholder="nginx")
                max_results = st.slider("Max Results", 10, 100, config['max_cve_results'])
            
            with col2:
                st.markdown("**Popular Products:**")
                popular_products = ["nginx", "apache", "mysql", "postgresql", "redis", "mongodb", "nodejs", "python"]
                
                for product in popular_products:
                    if st.button(product, key=f"popular_{product}"):
                        product_name = product
            
            if st.button("🔍 Search CVEs", type="primary") and product_name:
                with st.spinner(f"Searching CVEs for {product_name}..."):
                    cves = self.cve_integrator.search_cves_by_product(product_name, max_results)
                    
                    if cves:
                        st.success(f"Found {len(cves)} CVEs for {product_name}")
                        
                        # Create DataFrame for display
                        df = pd.DataFrame(cves)
                        
                        # Display as table with selection
                        st.markdown("**Select CVEs to add to tracking:**")
                        
                        for i, cve in enumerate(cves):
                            col1, col2, col3 = st.columns([1, 3, 1])
                            
                            with col1:
                                selected = st.checkbox("", key=f"cve_select_{i}")
                            
                            with col2:
                                severity_color = {
                                    'CRITICAL': '#dc3545',
                                    'HIGH': '#fd7e14',
                                    'MEDIUM': '#ffc107',
                                    'LOW': '#28a745'
                                }.get(cve['severity'], '#6c757d')
                                
                                st.markdown(f"""
                                **{cve['id']}** - <span style="color: {severity_color}">**{cve['severity']}**</span> (CVSS: {cve['cvss_score']})
                                
                                {cve['description']}
                                
                                *Published: {cve['published_date']}*
                                """, unsafe_allow_html=True)
                            
                            with col3:
                                if selected and st.button("➕ Add", key=f"add_cve_{i}"):
                                    vuln = {
                                        'id': cve['id'],
                                        'severity': cve['severity'],
                                        'description': cve['description'],
                                        'cvss_score': cve['cvss_score'],
                                        'type': 'cve_search',
                                        'category': 'product_vulnerability',
                                        'status': 'open',
                                        'discovered_date': datetime.now().isoformat(),
                                        'priority_score': cve['cvss_score'],
                                        'product': product_name
                                    }
                                    st.session_state.vulnerabilities.append(vuln)
                                    st.success(f"Added {cve['id']} to tracking!")
                        
                        # Severity distribution chart
                        severity_counts = df['severity'].value_counts()
                        
                        fig = px.pie(values=severity_counts.values, 
                                   names=severity_counts.index,
                                   title=f"CVE Severity Distribution for {product_name}",
                                   color_discrete_map={
                                       'CRITICAL': '#dc3545',
                                       'HIGH': '#fd7e14',
                                       'MEDIUM': '#ffc107', 
                                       'LOW': '#28a745'
                                   })
                        st.plotly_chart(fig, use_container_width=True)
                    else:
                        st.info(f"No CVEs found for {product_name}")
    
    def render_dockerfile_tab(self, config):
        """Render Dockerfile analyzer tab"""
        st.markdown('<div class="section-header">📄 Dockerfile Security Analyzer</div>', unsafe_allow_html=True)
        
        # Sample Dockerfiles for testing
        col1, col2 = st.columns([3, 1])
        
        with col2:
            st.markdown("**📋 Sample Dockerfiles**")
            
            if st.button("🔴 Insecure Example"):
                sample_dockerfile = """FROM ubuntu:16.04
USER root
RUN apt-get update && apt-get install -y nginx
COPY . /
ENV PASSWORD=mysecretpassword
ENV API_KEY=abc123secretkey
RUN chmod 777 /app
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]"""
                st.session_state.dockerfile_content = sample_dockerfile
            
            if st.button("🟢 Secure Example"):
                sample_dockerfile = """FROM ubuntu:22.04

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Install packages and clean up
RUN apt-get update && \\
    apt-get install -y --no-install-recommends nginx && \\
    apt-get clean && \\
    rm -rf /var/lib/apt/lists/*

# Copy application files with proper ownership
COPY --chown=appuser:appuser ./app /app

# Set working directory
WORKDIR /app

# Switch to non-root user
USER appuser

# Add health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \\
    CMD curl -f http://localhost:80/health || exit 1

# Expose port
EXPOSE 80

# Run application
CMD ["nginx", "-g", "daemon off;"]"""
                st.session_state.dockerfile_content = sample_dockerfile
            
            if st.button("🔄 Clear"):
                st.session_state.dockerfile_content = ""
        
        with col1:
            dockerfile_content = st.text_area(
                "Paste Dockerfile Content",
                height=400,
                value=st.session_state.get('dockerfile_content', ''),
                placeholder="""FROM ubuntu:22.04
RUN apt-get update && apt-get install -y nginx
COPY . /var/www/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]""",
                key="dockerfile_input"
            )
            
            # Update session state
            st.session_state.dockerfile_content = dockerfile_content
        
        if st.button("🔍 Analyze Dockerfile", type="primary"):
            if dockerfile_content:
                with st.spinner("Analyzing Dockerfile for security issues..."):
                    vulnerabilities = self.dockerfile_analyzer.analyze_dockerfile(dockerfile_content)
                    
                    if vulnerabilities:
                        # Prioritize vulnerabilities
                        if config['auto_prioritize']:
                            vulnerabilities = self.vulnerability_analyzer.prioritize_vulnerabilities(vulnerabilities)
                        
                        # Add to session state
                        st.session_state.vulnerabilities.extend(vulnerabilities)
                        
                        st.success(f"Analysis complete! Found {len(vulnerabilities)} security issues.")
                        
                        # Display results
                        st.markdown('<div class="section-header">🚨 Security Issues Found</div>', unsafe_allow_html=True)
                        
                        # Group by severity
                        severity_groups = {}
                        for vuln in vulnerabilities:
                            severity = vuln.get('severity', 'UNKNOWN')
                            if severity not in severity_groups:
                                severity_groups[severity] = []
                            severity_groups[severity].append(vuln)
                        
                        # Display by severity
                        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                            if severity in severity_groups:
                                st.markdown(f"### {severity} Severity Issues ({len(severity_groups[severity])})")
                                
                                for vuln in severity_groups[severity]:
                                    severity_class = f"{severity.lower()}-vuln"
                                    
                                    with st.expander(f"Line {vuln.get('line_number', 'Unknown')}: {vuln.get('category', 'Unknown').replace('_', ' ').title()}"):
                                        col1, col2 = st.columns([2, 1])
                                        
                                        with col1:
                                            st.markdown(f"""
                                            **Issue:** {vuln.get('description', 'No description')}
                                            
                                            **Line {vuln.get('line_number', 'Unknown')}:**
                                            ```dockerfile
                                            {vuln.get('line_content', '')}
                                            ```
                                            
                                            **Remediation:**
                                            {vuln.get('remediation', 'No remediation available')}
                                            """)
                                        
                                        with col2:
                                            st.markdown(f"""
                                            **Severity:** {severity}
                                            
                                            **Category:** {vuln.get('category', 'Unknown').replace('_', ' ').title()}
                                            
                                            **ID:** {vuln.get('id', 'Unknown')}
                                            """)
                                            
                                            # Status update
                                            new_status = st.selectbox(
                                                "Status", 
                                                ["open", "in_progress", "resolved", "false_positive"],
                                                key=f"status_{vuln.get('id')}"
                                            )
                                            
                                            if st.button("💾 Update", key=f"update_{vuln.get('id')}"):
                                                vuln['status'] = new_status
                                                st.success("Status updated!")
                        
                        # Summary statistics
                        risk_analysis = self.vulnerability_analyzer.calculate_risk_score(vulnerabilities)
                        
                        st.markdown('<div class="section-header">📊 Risk Assessment</div>', unsafe_allow_html=True)
                        
                        col1, col2, col3, col4 = st.columns(4)
                        
                        with col1:
                            st.metric("Risk Level", risk_analysis['risk_level'])
                        
                        with col2:
                            st.metric("Risk Score", f"{risk_analysis['total_score']:.0f}")
                        
                        with col3:
                            st.metric("Total Issues", risk_analysis['vulnerability_count'])
                        
                        with col4:
                            critical_count = risk_analysis['severity_breakdown'].get('CRITICAL', 0)
                            st.metric("Critical Issues", critical_count)
                    
                    else:
                        st.success("🎉 No security issues found in Dockerfile! Great job following security best practices.")
            else:
                st.warning("Please paste Dockerfile content to analyze.")
    
    def render_ai_remediation_tab(self, config):
        """Render AI remediation tab"""
        st.markdown('<div class="section-header">🤖 AI-Powered Remediation</div>', unsafe_allow_html=True)
        
        if not st.session_state.vulnerabilities:
            st.info("No vulnerabilities found. Please analyze a Dockerfile or search CVE database first.")
            return
        
        # Filter vulnerabilities for remediation
        open_vulns = [v for v in st.session_state.vulnerabilities if v.get('status') == 'open']
        
        if not open_vulns:
            st.success("All vulnerabilities have been addressed!")
            return
        
        st.subheader(f"🎯 Analyzing {len(open_vulns)} Open Vulnerabilities")
        
        # Generate remediation plan
        if st.button("🧠 Generate AI Remediation Plan", type="primary"):
            with st.spinner("AI is analyzing vulnerabilities and generating remediation plan..."):
                # Get risk analysis
                risk_analysis = self.vulnerability_analyzer.calculate_risk_score(open_vulns)
                
                # Generate remediation plan
                remediation_plan = self.ai_engine.generate_remediation_plan(open_vulns)
                
                # Store in session state
                st.session_state.remediation_plans['latest'] = remediation_plan
                
                # Display risk analysis
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.metric("Risk Level", risk_analysis['risk_level'])
                
                with col2:
                    st.metric("Risk Score", f"{risk_analysis['total_score']:.0f}")
                
                with col3:
                    st.metric("Estimated Effort", remediation_plan.get('estimated_effort', 'Unknown'))
                
                # Display remediation plan
                st.markdown('<div class="section-header">📋 AI Remediation Plan</div>', unsafe_allow_html=True)
                
                # Immediate actions
                if remediation_plan.get('immediate_actions'):
                    st.markdown("""
                    <div class="remediation-card">
                        <h4>🚨 Immediate Actions Required</h4>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    for action in remediation_plan['immediate_actions']:
                        st.write(f"• {action}")
                
                # Short-term actions
                if remediation_plan.get('short_term_actions'):
                    st.markdown("""
                    <div class="remediation-card">
                        <h4>⏰ Short-term Actions (1-4 weeks)</h4>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    for action in remediation_plan['short_term_actions']:
                        st.write(f"• {action}")
                
                # Long-term actions
                if remediation_plan.get('long_term_actions'):
                    st.markdown("""
                    <div class="remediation-card">
                        <h4>📅 Long-term Actions (1-3 months)</h4>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    for action in remediation_plan['long_term_actions']:
                        st.write(f"• {action}")
                
                # Automated fixes
                if remediation_plan.get('automated_fixes'):
                    st.markdown("""
                    <div class="remediation-card">
                        <h4>🤖 Automation Opportunities</h4>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    for fix in remediation_plan['automated_fixes']:
                        if isinstance(fix, dict):
                            st.write(f"• **{fix.get('type', 'Unknown')}**: {fix.get('description', 'No description')}")
                            st.write(f"  *Feasibility: {fix.get('feasibility', 'Unknown')}*")
                        else:
                            st.write(f"• {fix}")
                
                # AI recommendations
                if remediation_plan.get('ai_recommendations'):
                    st.markdown("""
                    <div class="remediation-card">
                        <h4>🔮 Advanced AI Insights</h4>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    st.markdown(remediation_plan['ai_recommendations'])
        
        # Individual vulnerability remediation
        st.markdown('<div class="section-header">🛠️ Individual Vulnerability Remediation</div>', unsafe_allow_html=True)
        
        # Select vulnerability for detailed remediation
        vuln_options = [f"{v.get('id', 'Unknown')} - {v.get('severity', 'Unknown')} - {v.get('description', 'No description')[:50]}..." 
                       for v in open_vulns[:20]]
        
        if vuln_options:
            selected_vuln_idx = st.selectbox("Select Vulnerability", range(len(vuln_options)), 
                                           format_func=lambda x: vuln_options[x])
            
            selected_vuln = open_vulns[selected_vuln_idx]
            
            col1, col2 = st.columns([2, 1])
            
            with col1:
                st.markdown(f"""
                **ID:** {selected_vuln.get('id', 'Unknown')}
                
                **Severity:** {selected_vuln.get('severity', 'Unknown')}
                
                **Category:** {selected_vuln.get('category', 'Unknown').replace('_', ' ').title()}
                
                **Description:** {selected_vuln.get('description', 'No description')}
                
                **Status:** {selected_vuln.get('status', 'Open')}
                """)
                
                if selected_vuln.get('line_number'):
                    st.markdown(f"**Line:** {selected_vuln['line_number']}")
                    st.code(selected_vuln.get('line_content', ''), language='dockerfile')
            
            with col2:
                if st.button("🔧 Generate Fix Script", key="generate_script"):
                    script = self.ai_engine.generate_fix_script(selected_vuln)
                    
                    st.code(script, language='bash')
                    
                    st.download_button(
                        label="📥 Download Fix Script",
                        data=script,
                        file_name=f"fix_{selected_vuln.get('id', 'unknown').replace('/', '_')}.sh",
                        mime="text/plain"
                    )
                
                # Status update
                new_status = st.selectbox("Update Status", 
                                        ["open", "in_progress", "resolved", "false_positive"],
                                        key="status_update")
                
                if st.button("💾 Update Status", key="update_status"):
                    selected_vuln['status'] = new_status
                    st.success(f"Status updated to: {new_status}")
                    st.rerun()
    
    def render_analytics_tab(self, config):
        """Render analytics and reporting tab"""
        st.markdown('<div class="section-header">📊 Security Analytics</div>', unsafe_allow_html=True)
        
        if not st.session_state.vulnerabilities:
            st.info("No vulnerability data available. Please analyze Dockerfiles or search CVEs to generate analytics.")
            return
        
        vulnerabilities = st.session_state.vulnerabilities
        
        # Overview statistics
        total_vulns = len(vulnerabilities)
        severity_counts = {}
        status_counts = {}
        category_counts = {}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'UNKNOWN')
            status = vuln.get('status', 'open')
            category = vuln.get('category', 'unknown')
            
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            status_counts[status] = status_counts.get(status, 0) + 1
            category_counts[category] = category_counts.get(category, 0) + 1
        
        # Overview charts
        col1, col2 = st.columns(2)
        
        with col1:
            # Severity distribution
            if severity_counts:
                fig_severity = px.pie(
                    values=list(severity_counts.values()),
                    names=list(severity_counts.keys()),
                    title="Vulnerability Distribution by Severity",
                    color_discrete_map={
                        'CRITICAL': '#dc3545',
                        'HIGH': '#fd7e14',
                        'MEDIUM': '#ffc107',
                        'LOW': '#28a745'
                    }
                )
                st.plotly_chart(fig_severity, use_container_width=True)
        
        with col2:
            # Status distribution
            if status_counts:
                fig_status = px.pie(
                    values=list(status_counts.values()),
                    names=list(status_counts.keys()),
                    title="Vulnerability Status Distribution",
                    color_discrete_map={
                        'open': '#dc3545',
                        'in_progress': '#ffc107',
                        'resolved': '#28a745',
                        'false_positive': '#6c757d'
                    }
                )
                st.plotly_chart(fig_status, use_container_width=True)
        
        # Category analysis
        if category_counts:
            st.subheader("Vulnerability Categories")
            
            fig_categories = px.bar(
                x=list(category_counts.keys()),
                y=list(category_counts.values()),
                title="Vulnerability Categories Distribution",
                labels={'x': 'Category', 'y': 'Count'}
            )
            st.plotly_chart(fig_categories, use_container_width=True)
        
        # Detailed vulnerability table
        st.subheader("Detailed Vulnerability Analysis")
        
        # Create DataFrame for analysis
        df_data = []
        for vuln in vulnerabilities:
            df_data.append({
                'ID': vuln.get('id', 'Unknown'),
                'Severity': vuln.get('severity', 'Unknown'),
                'Category': vuln.get('category', 'unknown').replace('_', ' ').title(),
                'Status': vuln.get('status', 'open'),
                'Type': vuln.get('type', 'unknown'),
                'Line': vuln.get('line_number', 'N/A'),
                'Priority Score': vuln.get('priority_score', 0),
                'Description': vuln.get('description', 'No description')[:100] + '...'
            })
        
        if df_data:
            df = pd.DataFrame(df_data)
            
            # Add filters
            col1, col2, col3 = st.columns(3)
            
            with col1:
                severity_filter = st.multiselect("Filter by Severity", 
                                               df['Severity'].unique().tolist(),
                                               default=df['Severity'].unique().tolist())
            
            with col2:
                status_filter = st.multiselect("Filter by Status",
                                             df['Status'].unique().tolist(),
                                             default=df['Status'].unique().tolist())
            
            with col3:
                category_filter = st.multiselect("Filter by Category",
                                               df['Category'].unique().tolist(),
                                               default=df['Category'].unique().tolist())
            
            # Apply filters
            filtered_df = df[
                (df['Severity'].isin(severity_filter)) &
                (df['Status'].isin(status_filter)) &
                (df['Category'].isin(category_filter))
            ]
            
            # Display filtered table
            if not filtered_df.empty:
                st.dataframe(filtered_df, use_container_width=True)
                
                # Export option
                csv = filtered_df.to_csv(index=False)
                st.download_button(
                    label="📥 Export Filtered Data",
                    data=csv,
                    file_name=f"vulnerability_analysis_{datetime.now().strftime('%Y%m%d')}.csv",
                    mime="text/csv"
                )
            else:
                st.info("No vulnerabilities match the current filters.")
    
    def render_reports_tab(self, config):
        """Render reports tab"""
        st.markdown('<div class="section-header">📋 Security Reports</div>', unsafe_allow_html=True)
        
        if not st.session_state.vulnerabilities:
            st.info("No vulnerability data available. Please analyze Dockerfiles or search CVEs to generate reports.")
            return
        
        vulnerabilities = st.session_state.vulnerabilities
        
        # Report generation
        report_type = st.selectbox("Select Report Type", 
                                 ["Executive Summary", "Technical Report", "Remediation Plan"])
        
        if st.button("📊 Generate Report", type="primary"):
            with st.spinner("Generating report..."):
                if report_type == "Executive Summary":
                    report = self._generate_executive_summary(vulnerabilities)
                elif report_type == "Technical Report":
                    report = self._generate_technical_report(vulnerabilities)
                elif report_type == "Remediation Plan":
                    report = self._generate_remediation_report(vulnerabilities)
                
                st.markdown(report)
                
                # Download option
                st.download_button(
                    label="📥 Download Report",
                    data=report,
                    file_name=f"{report_type.lower().replace(' ', '_')}_{datetime.now().strftime('%Y%m%d')}.md",
                    mime="text/markdown"
                )
    
    def _generate_executive_summary(self, vulnerabilities: List[Dict]) -> str:
        """Generate executive summary report"""
        risk_analysis = self.vulnerability_analyzer.calculate_risk_score(vulnerabilities)
        
        severity_counts = risk_analysis['severity_breakdown']
        status_counts = {}
        for vuln in vulnerabilities:
            status = vuln.get('status', 'open')
            status_counts[status] = status_counts.get(status, 0) + 1
        
        return f"""# Container Security Assessment - Executive Summary

## Overall Security Posture
- **Total Vulnerabilities Identified:** {len(vulnerabilities)}
- **Risk Level:** {risk_analysis['risk_level']}
- **Critical Issues:** {severity_counts.get('CRITICAL', 0)}
- **High Priority Issues:** {severity_counts.get('HIGH', 0)}

## Remediation Status
- **Open Vulnerabilities:** {status_counts.get('open', 0)}
- **In Progress:** {status_counts.get('in_progress', 0)}
- **Resolved:** {status_counts.get('resolved', 0)}
- **False Positives:** {status_counts.get('false_positive', 0)}

## Key Recommendations
1. Immediate attention required for {severity_counts.get('CRITICAL', 0)} critical vulnerabilities
2. Prioritize remediation of high-severity issues
3. Implement automated security scanning in CI/CD pipeline
4. Establish regular security review cycles

## Risk Assessment
- **Total Risk Score:** {risk_analysis['total_score']:.0f}
- **Average Risk Score:** {risk_analysis['average_score']:.1f}

Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
    
    def _generate_technical_report(self, vulnerabilities: List[Dict]) -> str:
        """Generate technical report"""
        report = f"""# Container Security Technical Report

## Vulnerability Details

"""
        for vuln in vulnerabilities[:20]:  # Top 20 vulnerabilities
            report += f"""
### {vuln.get('id', 'Unknown')} - {vuln.get('severity', 'Unknown')} Severity

**Description:** {vuln.get('description', 'No description available')}

**Category:** {vuln.get('category', 'Unknown').replace('_', ' ').title()}

**Status:** {vuln.get('status', 'Open')}

**Line:** {vuln.get('line_number', 'N/A')}

**Remediation:** {vuln.get('remediation', 'Under investigation')}

---
"""
        
        return report
    
    def _generate_remediation_report(self, vulnerabilities: List[Dict]) -> str:
        """Generate remediation plan report"""
        if 'latest' in st.session_state.remediation_plans:
            plan = st.session_state.remediation_plans['latest']
        else:
            plan = self.ai_engine.generate_remediation_plan(vulnerabilities)
        
        report = f"""# Container Security Remediation Plan

## Immediate Actions Required
{chr(10).join(['- ' + action for action in plan.get('immediate_actions', [])])}

## Short-term Actions (1-4 weeks)
{chr(10).join(['- ' + action for action in plan.get('short_term_actions', [])])}

## Long-term Actions (1-3 months)
{chr(10).join(['- ' + action for action in plan.get('long_term_actions', [])])}

## Automation Opportunities
{chr(10).join(['- ' + str(action) for action in plan.get('automated_fixes', [])])}

**Estimated Effort:** {plan.get('estimated_effort', 'Unknown')}
**Risk Reduction:** {plan.get('risk_reduction', 0)}%

Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
        return report
    
    def run(self):
        """Main application entry point"""
        # Render header and navigation
        self.render_header()
        self.render_navigation()
        
        # Get configuration from sidebar
        config = self.render_sidebar_controls()
        
        # Render appropriate tab based on selection
        if st.session_state.active_tab == "dashboard":
            self.render_dashboard_tab(config)
        elif st.session_state.active_tab == "cve":
            self.render_cve_tab(config)
        elif st.session_state.active_tab == "dockerfile":
            self.render_dockerfile_tab(config)
        elif st.session_state.active_tab == "ai_remediation":
            self.render_ai_remediation_tab(config)
        elif st.session_state.active_tab == "analytics":
            self.render_analytics_tab(config)
        elif st.session_state.active_tab == "reports":
            self.render_reports_tab(config)


def main():
    """Main function to run the Container Vulnerability Management Platform"""
    try:
        # Initialize and run the platform
        platform = ContainerVulnerabilityPlatform()
        platform.run()
        
    except Exception as e:
        st.error(f"An error occurred: {str(e)}")
        st.write("Please check your configuration and try again.")
        
        # Provide support information
        st.info("If the problem persists, please check the logs or contact support.")


# Application entry point
if __name__ == "__main__":
    main()