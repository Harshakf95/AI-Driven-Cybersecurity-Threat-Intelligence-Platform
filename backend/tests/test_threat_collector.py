import unittest
from unittest.mock import patch, MagicMock

class ThreatCollector:
    def __init__(self, sources=None):
        self.sources = sources or ['virustotal', 'alienvault', 'otx']
    
    def collect_threat_data(self, indicator):
        """
        Simulate collecting threat data from multiple sources
        """
        threat_data = {}
        for source in self.sources:
            if source == 'virustotal':
                threat_data['virustotal'] = self._get_virustotal_data(indicator)
            elif source == 'alienvault':
                threat_data['alienvault'] = self._get_alienvault_data(indicator)
            elif source == 'otx':
                threat_data['otx'] = self._get_otx_data(indicator)
        return threat_data
    
    def _get_virustotal_data(self, indicator):
        return {
            'positives': 5,
            'total_scans': 10,
            'detection_ratio': '5/10',
            'last_analysis_date': '2025-04-10'
        }
    
    def _get_alienvault_data(self, indicator):
        return {
            'reputation': 'malicious',
            'threat_level': 'high',
            'pulse_count': 3,
            'first_seen': '2025-04-09'
        }
    
    def _get_otx_data(self, indicator):
        return {
            'pulses': 2,
            'malware_family': 'Unknown',
            'risk_score': 7.5
        }
    
    def aggregate_threat_intelligence(self, threat_data):
        """
        Aggregate threat intelligence from multiple sources
        """
        aggregated_threat = {
            'overall_risk': 'high',
            'sources_detected': len(threat_data),
            'detailed_data': threat_data
        }
        return aggregated_threat

class TestThreatCollector(unittest.TestCase):
    def setUp(self):
        """
        Setup method to initialize test resources
        """
        self.threat_collector = ThreatCollector()

    def test_threat_collector_initialization(self):
        """
        Test threat collector initialization
        """
        default_sources = ['virustotal', 'alienvault', 'otx']
        self.assertEqual(self.threat_collector.sources, default_sources)

    def test_virustotal_data_collection(self):
        """
        Test VirusTotal data collection
        """
        indicator = 'example.com'
        virustotal_data = self.threat_collector._get_virustotal_data(indicator)
        
        self.assertIsNotNone(virustotal_data)
        self.assertEqual(virustotal_data['positives'], 5)
        self.assertEqual(virustotal_data['total_scans'], 10)

    def test_alienvault_data_collection(self):
        """
        Test AlienVault data collection
        """
        indicator = 'example.com'
        alienvault_data = self.threat_collector._get_alienvault_data(indicator)
        
        self.assertIsNotNone(alienvault_data)
        self.assertEqual(alienvault_data['reputation'], 'malicious')
        self.assertEqual(alienvault_data['threat_level'], 'high')

    def test_otx_data_collection(self):
        """
        Test OTX data collection
        """
        indicator = 'example.com'
        otx_data = self.threat_collector._get_otx_data(indicator)
        
        self.assertIsNotNone(otx_data)
        self.assertEqual(otx_data['pulses'], 2)
        self.assertIsNotNone(otx_data['malware_family'])

    def test_threat_intelligence_aggregation(self):
        """
        Test threat intelligence aggregation
        """
        sample_threat_data = {
            'virustotal': {
                'positives': 5,
                'total_scans': 10
            },
            'alienvault': {
                'reputation': 'malicious',
                'threat_level': 'high'
            }
        }

        aggregated_threat = self.threat_collector.aggregate_threat_intelligence(sample_threat_data)
        
        self.assertIsNotNone(aggregated_threat)
        self.assertEqual(aggregated_threat['overall_risk'], 'high')
        self.assertEqual(aggregated_threat['sources_detected'], 2)
        self.assertIn('detailed_data', aggregated_threat)

    def test_collect_threat_data_multiple_sources(self):
        """
        Test collecting threat data from multiple sources
        """
        indicator = 'malicious-domain.com'
        threat_data = self.threat_collector.collect_threat_data(indicator)
        
        self.assertIsNotNone(threat_data)
        self.assertIn('virustotal', threat_data)
        self.assertIn('alienvault', threat_data)
        self.assertIn('otx', threat_data)

def main():
    unittest.main()

if __name__ == '__main__':
    main()