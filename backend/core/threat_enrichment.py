import requests
import json
from typing import Dict, Any, List
import logging

class ThreatEnrichment:
    def __init__(self, virustotal_api_key: str, alienvault_api_key: str):
        """
        Initialize threat enrichment service with API keys
        
        :param virustotal_api_key: API key for VirusTotal
        :param alienvault_api_key: API key for AlienVault OTX
        """
        self.virustotal_api_key = virustotal_api_key
        self.alienvault_api_key = alienvault_api_key
        self.logger = logging.getLogger(__name__)
        logging.basicConfig(level=logging.INFO)

    def enrich_ioc(self, ioc: str, ioc_type: str) -> Dict[str, Any]:
        """
        Enrich an Indicator of Compromise (IOC) with additional threat intelligence
        
        :param ioc: The indicator to enrich (IP, domain, hash, etc.)
        :param ioc_type: Type of IOC (ip, domain, file_hash, etc.)
        :return: Enriched threat intelligence data
        """
        enriched_data = {
            'original_ioc': ioc,
            'ioc_type': ioc_type,
            'sources': []
        }

        try:
            # Enrich from VirusTotal
            vt_data = self._enrich_virustotal(ioc, ioc_type)
            if vt_data:
                enriched_data['sources'].append({
                    'source': 'VirusTotal',
                    'data': vt_data
                })

            # Enrich from AlienVault OTX
            otx_data = self._enrich_alienvault(ioc, ioc_type)
            if otx_data:
                enriched_data['sources'].append({
                    'source': 'AlienVault OTX',
                    'data': otx_data
                })

        except Exception as e:
            self.logger.error(f"Error enriching IOC {ioc}: {str(e)}")
            enriched_data['error'] = str(e)

        return enriched_data

    def _enrich_virustotal(self, ioc: str, ioc_type: str) -> Dict[str, Any]:
        """
        Retrieve threat intelligence from VirusTotal
        
        :param ioc: Indicator of Compromise
        :param ioc_type: Type of IOC
        :return: VirusTotal threat data
        """
        vt_endpoint_map = {
            'ip': f'https://www.virustotal.com/api/v3/ip_addresses/{ioc}',
            'domain': f'https://www.virustotal.com/api/v3/domains/{ioc}',
            'file_hash': f'https://www.virustotal.com/api/v3/files/{ioc}'
        }

        if ioc_type not in vt_endpoint_map:
            return None

        headers = {
            'x-apikey': self.virustotal_api_key
        }

        try:
            response = requests.get(vt_endpoint_map[ioc_type], headers=headers)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            self.logger.warning(f"VirusTotal API error: {str(e)}")
            return None

    def _enrich_alienvault(self, ioc: str, ioc_type: str) -> Dict[str, Any]:
        """
        Retrieve threat intelligence from AlienVault OTX
        
        :param ioc: Indicator of Compromise
        :param ioc_type: Type of IOC
        :return: AlienVault OTX threat data
        """
        otx_endpoint_map = {
            'ip': f'https://otx.alienvault.com/api/v1/indicators/IPv4/{ioc}',
            'domain': f'https://otx.alienvault.com/api/v1/indicators/domain/{ioc}',
            'file_hash': f'https://otx.alienvault.com/api/v1/indicators/file/{ioc}'
        }

        if ioc_type not in otx_endpoint_map:
            return None

        headers = {
            'X-OTX-API-KEY': self.alienvault_api_key
        }

        try:
            response = requests.get(otx_endpoint_map[ioc_type], headers=headers)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            self.logger.warning(f"AlienVault OTX API error: {str(e)}")
            return None

    def bulk_enrich_iocs(self, iocs: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        """
        Bulk enrich multiple IOCs
        
        :param iocs: List of IOCs with type
        :return: List of enriched IOCs
        """
        return [self.enrich_ioc(ioc['value'], ioc['type']) for ioc in iocs]

def main():
    # Example usage
    enricher = ThreatEnrichment(
        virustotal_api_key='YOUR_VIRUSTOTAL_API_KEY', 
        alienvault_api_key='YOUR_ALIENVAULT_API_KEY'
    )
    
    # Example IOC enrichment
    ioc_to_enrich = {
        'value': '8.8.8.8',  # Google's public DNS IP
        'type': 'ip'
    }
    
    enriched_data = enricher.enrich_ioc(
        ioc_to_enrich['value'], 
        ioc_to_enrich['type']
    )
    print(json.dumps(enriched_data, indent=2))

if __name__ == '__main__':
    main()