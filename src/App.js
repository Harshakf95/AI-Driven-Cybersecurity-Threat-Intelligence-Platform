// frontend/src/App.js
import React, { useState, useEffect } from "react";
import AlertNotification from "./components/AlertNotification";
import ThreatIntelligenceManager from "./services/ThreatIntelligenceManager";

const App = () => {
  const [threats, setThreats] = useState([]);
  const threatManager = new ThreatIntelligenceManager(
    "your_virustotal_api_key",
    "your_alienvault_api_key"
  );

  useEffect(() => {
    const indicators = ["file_hash_123", "suspicious_domain.com"];
    console.log("Fetching threat data for:", indicators); // Debug: Start of fetch
    threatManager
      .analyzeThreatIndicators(indicators)
      .then((report) => {
        console.log("Raw report:", report); // Debug: Raw data from ThreatIntelligenceManager
        const threatList = report.highRiskIndicators.map((indicator, index) => {
          const threat = {
            id: index,
            severity:
              report.detailedResults?.[indicator]?.alienvault?.threatLevel === "high"
                ? "high"
                : "medium",
            title: `Threat Detected: ${indicator}`,
            description: `Source: ${report.sources.join(", ")}`,
          };
          console.log("Processed threat:", threat); // Debug: Each threat object
          return threat;
        });
        console.log("Threat list:", threatList); // Debug: Final threat list
        setThreats(threatList);
      })
      .catch((error) => console.error("Failed to fetch threats:", error));
  }, []);

  return (
    <div className="container mx-auto p-4">
      <h1 className="text-3xl font-bold mb-4">AI Cybersecurity Dashboard</h1>
      {threats.length === 0 ? (
        <p className="text-gray-500">Loading threat intelligence...</p>
      ) : (
        <div>
          <p className="mb-4">Found {threats.length} high-risk threats</p>
          {threats.map((threat) => (
            <AlertNotification
              key={threat.id}
              severity={threat.severity}
              title={threat.title}
              description={threat.description}
            />
          ))}
        </div>
      )}
    </div>
  );
};

export default App;