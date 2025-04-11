from threat_analysis import ThreatAnalyzer

def main():
    # Create an analyzer
    analyzer = ThreatAnalyzer()

    # Analyze threat intelligence
    threat_data = {
        'malware_count': 4,
        'suspicious_count': 2,
        'malicious_ip_count': 3,
        'suspicious_domains': ['example.com', 'malware.net']
    }
    
    report = analyzer.analyze_threat_intelligence(threat_data)
    
    # Pretty print the report
    print("Threat Analysis Report:")
    print("-" * 30)
    print(f"Severity: {report.get('severity', 'N/A')}")
    print("\nIndicators:")
    for key, value in report.get('indicators', {}).items():
        print(f"  {key}: {value}")
    
    print("\nRecommendations:")
    for recommendation in report.get('recommendations', []):
        print(f"  - {recommendation}")

if __name__ == '__main__':
    main()