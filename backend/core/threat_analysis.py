import logging
from typing import Dict, List, Any

class ThreatAnalyzer:
    def __init__(self, logger=None):
        """
        Initialize ThreatAnalyzer with optional custom logger
        
        :param logger: Optional custom logger, defaults to standard logging
        """
        self.logger = logger or logging.getLogger(__name__)
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )

    def classify_threat_severity(self, threat_data: Dict[str, int]) -> str:
        """
        Classify threat severity based on malware and suspicious indicators
        
        :param threat_data: Dictionary containing threat metrics
        :return: Threat severity level ('low', 'medium', 'high')
        """
        malware_count = threat_data.get('malware_count', 0)
        suspicious_count = threat_data.get('suspicious_count', 0)
        
        if malware_count > 5 or suspicious_count > 3:
            severity = 'high'
            self.logger.warning(f"High severity threat detected: {threat_data}")
        elif malware_count > 2 or suspicious_count > 1:
            severity = 'medium'
            self.logger.info(f"Medium severity threat detected: {threat_data}")
        else:
            severity = 'low'
            self.logger.debug(f"Low severity threat detected: {threat_data}")
        
        return severity

    def correlate_threats(self, threats: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Correlate and filter threats based on type and characteristics
        
        :param threats: List of threat dictionaries
        :return: Filtered and correlated list of threats
        """
        try:
            # Filter malware threats
            malware_threats = [
                threat for threat in threats 
                if threat.get('type', '').lower() == 'malware'
            ]
            
            # Additional correlation logic can be added here
            self.logger.info(f"Correlated {len(malware_threats)} malware threats")
            
            return malware_threats
        except Exception as e:
            self.logger.error(f"Error in threat correlation: {e}")
            return []

    def analyze_threat_intelligence(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Comprehensive threat intelligence analysis
        
        :param threat_data: Aggregated threat data from multiple sources
        :return: Analyzed threat report
        """
        try:
            # Severity classification
            severity = self.classify_threat_severity({
                'malware_count': threat_data.get('malware_count', 0),
                'suspicious_count': threat_data.get('suspicious_count', 0)
            })
            
            # Threat report generation
            threat_report = {
                'severity': severity,
                'sources': list(threat_data.keys()),
                'indicators': {
                    'malicious_ip_count': threat_data.get('malicious_ip_count', 0),
                    'suspicious_domains': threat_data.get('suspicious_domains', [])
                },
                'recommendations': self._generate_recommendations(severity)
            }
            
            self.logger.info(f"Generated threat report: {threat_report}")
            return threat_report
        
        except Exception as e:
            self.logger.error(f"Threat analysis failed: {e}")
            return {}

    def _generate_recommendations(self, severity: str) -> List[str]:
        """
        Generate threat mitigation recommendations
        
        :param severity: Threat severity level
        :return: List of recommended actions
        """
        recommendations = {
            'high': [
                'Immediately isolate affected systems',
                'Initiate incident response protocol',
                'Conduct comprehensive forensic analysis'
            ],
            'medium': [
                'Perform detailed system scan',
                'Update security patches',
                'Monitor system for suspicious activities'
            ],
            'low': [
                'Conduct routine security checks',
                'Update antivirus definitions',
                'Review system logs'
            ]
        }
        
        return recommendations.get(severity, [])

def main():
    # Example usage
    analyzer = ThreatAnalyzer()
    sample_threat = {
        'malware_count': 4,
        'suspicious_count': 2,
        'malicious_ip_count': 3,
        'suspicious_domains': ['example.com', 'malware.net']
    }
    
    threat_report = analyzer.analyze_threat_intelligence(sample_threat)
    print(threat_report)

if __name__ == '__main__':
    main()