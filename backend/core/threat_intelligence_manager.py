# backend/core/threat_intelligence_manager.py
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
import requests

class ThreatIntelligenceManager:
    """Manages threat intelligence aggregation from multiple sources."""

    def __init__(
        self,
        virustotal_api_key: Optional[str] = None,
        alienvault_api_key: Optional[str] = None,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize the Threat Intelligence Manager.

        Args:
            virustotal_api_key (str, optional): API key for VirusTotal.
            alienvault_api_key (str, optional): API key for AlienVault OTX.
            logger (logging.Logger, optional): Custom logger instance.
        """
        self.logger = logger or logging.getLogger(__name__)
        if not self.logger.handlers:
            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )

        # API Configuration
        self.virustotal_api_key = virustotal_api_key
        self.alienvault_api_key = alienvault_api_key

        # Base API URLs
        self.VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"
        self.ALIENVAULT_BASE_URL = "https://otx.alienvault.com/api/v1"

    def get_virustotal_file_report(self, file_hash: str) -> Dict[str, Any]:
        """
        Retrieve file report from VirusTotal.

        Args:
            file_hash (str): Hash of the file to analyze (e.g., MD5, SHA1, SHA256).

        Returns:
            Dict[str, Any]: Threat intelligence report or empty dict if failed.
        """
        if not self.virustotal_api_key:
            self.logger.warning("VirusTotal API key not configured")
            return {}

        try:
            headers = {"x-apikey": self.virustotal_api_key}
            response = requests.get(
                f"{self.VIRUSTOTAL_BASE_URL}/files/{file_hash}", 
                headers=headers,
                timeout=10
            )
            response.raise_for_status()
            data = response.json().get("data", {}).get("attributes", {})

            last_analysis_stats = data.get("last_analysis_stats", {})
            return {
                "positives": last_analysis_stats.get("malicious", 0),
                "total_scans": sum(last_analysis_stats.values()),
                "detection_ratio": f"{last_analysis_stats.get('malicious', 0)}/{sum(last_analysis_stats.values())}",
                "last_analysis_date": datetime.fromtimestamp(
                    data.get("last_analysis_date", datetime.now().timestamp())
                ).isoformat()
            }
        except requests.RequestException as e:
            self.logger.error(f"VirusTotal API error for file_hash {file_hash}: {e}")
            return {}

    def get_alienvault_indicator_details(self, indicator: str) -> Dict[str, Any]:
        """
        Retrieve threat intelligence for an indicator from AlienVault OTX.

        Args:
            indicator (str): Indicator to analyze (e.g., IP, domain, hash).

        Returns:
            Dict[str, Any]: Threat intelligence report or empty dict if failed.
        """
        if not self.alienvault_api_key:
            self.logger.warning("AlienVault API key not configured")
            return {}

        try:
            headers = {"X-OTX-API-KEY": self.alienvault_api_key}
            response = requests.get(
                f"{self.ALIENVAULT_BASE_URL}/indicators/{indicator}/general",
                headers=headers,
                timeout=10
            )
            response.raise_for_status()
            data = response.json()

            return {
                "threat_level": data.get("threat_level", "unknown"),
                "reputation": data.get("reputation", "unknown"),
                "pulse_count": data.get("pulse_info", {}).get("count", 0)
            }
        except requests.RequestException as e:
            self.logger.error(f"AlienVault API error for indicator {indicator}: {e}")
            return {}

    def aggregate_threat_intelligence(self, indicators: List[str]) -> Dict[str, Any]:
        """
        Aggregate threat intelligence across multiple sources.

        Args:
            indicators (List[str]): List of indicators to analyze (e.g., hashes, IPs).

        Returns:
            Dict[str, Any]: Comprehensive threat intelligence report.
        """
        aggregated_report = {
            "analyzed_indicators": indicators,
            "total_threats": 0,
            "high_risk_indicators": [],
            "sources": [],
            "detailed_results": {}
        }

        for indicator in indicators:
            vt_report = self.get_virustotal_file_report(indicator)
            av_report = self.get_alienvault_indicator_details(indicator)

            # Store detailed results
            aggregated_report["detailed_results"][indicator] = {
                "virustotal": vt_report,
                "alienvault": av_report
            }

            # Aggregate threat metrics
            if vt_report and vt_report.get("positives", 0) > 0:
                aggregated_report["sources"].append("virustotal")
                aggregated_report["total_threats"] += 1
                aggregated_report["high_risk_indicators"].append(indicator)

            if av_report and av_report.get("threat_level") in ["high", "medium"]:
                aggregated_report["sources"].append("alienvault")
                if indicator not in aggregated_report["high_risk_indicators"]:
                    aggregated_report["total_threats"] += 1
                    aggregated_report["high_risk_indicators"].append(indicator)

        # Remove duplicates from sources
        aggregated_report["sources"] = list(set(aggregated_report["sources"]))
        return aggregated_report

    def analyze_threat_indicators(self, indicators: List[str]) -> Dict[str, Any]:
        """
        Analyze threat indicators and return a report.

        Args:
            indicators (List[str]): List of indicators to analyze.

        Returns:
            Dict[str, Any]: Aggregated threat intelligence report.
        """
        try:
            report = self.aggregate_threat_intelligence(indicators)
            self.logger.info(f"Threat analysis completed for {len(indicators)} indicators")
            return report
        except Exception as e:
            self.logger.error(f"Threat analysis failed: {e}")
            raise

def main():
    """Example usage of ThreatIntelligenceManager."""
    # Replace with actual API keys
    threat_manager = ThreatIntelligenceManager(
        virustotal_api_key="your_virustotal_api_key",
        alienvault_api_key="your_alienvault_api_key"
    )

    indicators = ["example_file_hash_123", "suspicious_domain.com"]
    report = threat_manager.analyze_threat_indicators(indicators)

    print("Threat Intelligence Report:")
    print(f"Total Threats Detected: {report['total_threats']}")
    print(f"High-Risk Indicators: {report['high_risk_indicators']}")
    print(f"Sources Used: {report['sources']}")
    print(f"Detailed Results: {report['detailed_results']}")

if __name__ == "__main__":
    main()