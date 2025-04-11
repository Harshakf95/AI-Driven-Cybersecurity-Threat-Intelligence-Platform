import requests
from typing import Dict, List
import os

class VirusTotalCollector:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = '[https://www.virustotal.com/api/v3](https://www.virustotal.com/api/v3)'
        self.headers = {
            'x-apikey': self.api_key
        }

    def get_file_report(self, file_hash: str) -> Dict:
        """
        Retrieve threat intelligence for a given file hash
        """
        endpoint = f'/files/{file_hash}'
        try:
            response = requests.get(f'{self.base_url}{endpoint}', headers=self.headers)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            print(f"Error fetching VirusTotal report: {e}")
            return {}

    def collect_threat_data(self, hashes: List[str]) -> List[Dict]:
        """
        Collect threat data for multiple file hashes
        """
        return [self.get_file_report(hash_value) for hash_value in hashes]