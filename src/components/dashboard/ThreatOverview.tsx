import React from 'react';
import { useThreatData } from '../../context/ThreatContext';
import { Shield, AlertTriangle, Zap } from 'lucide-react';

const ThreatOverview: React.FC = () => {
  const { threatData, isLoading } = useThreatData();
  
  // Count threats by status
  const countThreats = () => {
    const webActive = threatData.webThreats.filter(t => t.status === 'active').length;
    const webBlocked = threatData.webThreats.filter(t => t.status === 'blocked').length;
    const networkActive = threatData.networkThreats.filter(t => t.status === 'active').length;
    const networkBlocked = threatData.networkThreats.filter(t => t.status === 'blocked').length;
    
    return {
      active: webActive + networkActive,
      blocked: webBlocked + networkBlocked,
      total: threatData.webThreats.length + threatData.networkThreats.length,
      web: threatData.webThreats.length,
      network: threatData.networkThreats.length,
      high: [...threatData.webThreats, ...threatData.networkThreats].filter(t => t.severity === 'high').length,
      medium: [...threatData.webThreats, ...threatData.networkThreats].filter(t => t.severity === 'medium').length,
      low: [...threatData.webThreats, ...threatData.networkThreats].filter(t => t.severity === 'low').length
    };
  };
  
  const threatCounts = countThreats();

  if (isLoading) {
    return (
      <div className="animate-pulse grid grid-cols-1 md:grid-cols-3 gap-4">
        {[...Array(3)].map((_, index) => (
          <div key={index} className="bg-gray-800 rounded-lg p-4">
            <div className="h-5 bg-gray-700 rounded w-1/3 mb-2"></div>
            <div className="h-10 bg-gray-700 rounded w-1/2"></div>
          </div>
        ))}
      </div>
    );
  }

  return (
    <>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <div className="bg-gradient-to-br from-red-900 to-red-800 rounded-lg p-4 border border-red-700 shadow-lg">
          <div className="flex items-center">
            <AlertTriangle className="h-8 w-8 text-red-300" />
            <div className="ml-3">
              <h3 className="text-sm font-medium text-red-200">Active Threats</h3>
              <p className="text-3xl font-bold text-white">{threatCounts.active}</p>
            </div>
          </div>
          <div className="mt-3 text-xs text-red-200">
            {threatCounts.high} high, {threatCounts.medium} medium, {threatCounts.low} low severity
          </div>
        </div>

        <div className="bg-gradient-to-br from-blue-900 to-blue-800 rounded-lg p-4 border border-blue-700 shadow-lg">
          <div className="flex items-center">
            <Shield className="h-8 w-8 text-blue-300" />
            <div className="ml-3">
              <h3 className="text-sm font-medium text-blue-200">Blocked Threats</h3>
              <p className="text-3xl font-bold text-white">{threatCounts.blocked}</p>
            </div>
          </div>
          <div className="mt-3 text-xs text-blue-200">
            Security measures stopped {Math.round((threatCounts.blocked / threatCounts.total) * 100)}% of all threats
          </div>
        </div>

        <div className="bg-gradient-to-br from-green-900 to-green-800 rounded-lg p-4 border border-green-700 shadow-lg">
          <div className="flex items-center">
            <Zap className="h-8 w-8 text-green-300" />
            <div className="ml-3">
              <h3 className="text-sm font-medium text-green-200">Threat Distribution</h3>
              <p className="text-3xl font-bold text-white">{threatCounts.web} / {threatCounts.network}</p>
            </div>
          </div>
          <div className="mt-3 text-xs text-green-200">
            Web vs Network threats detected in the last 24 hours
          </div>
        </div>
      </div>

      <div className="mb-4">
        <h3 className="text-lg font-semibold mb-3">Threat Severity Breakdown</h3>
        <div className="bg-gray-800 rounded-lg p-4 shadow">
          <div className="flex flex-col space-y-2">
            <div>
              <div className="flex justify-between mb-1">
                <span className="text-sm text-red-300 font-medium">High Severity</span>
                <span className="text-sm text-red-300">{threatCounts.high} threats</span>
              </div>
              <div className="w-full bg-gray-700 rounded-full h-2.5">
                <div className="bg-red-600 h-2.5 rounded-full" style={{ width: `${(threatCounts.high / threatCounts.total) * 100}%` }}></div>
              </div>
            </div>
            
            <div>
              <div className="flex justify-between mb-1">
                <span className="text-sm text-amber-300 font-medium">Medium Severity</span>
                <span className="text-sm text-amber-300">{threatCounts.medium} threats</span>
              </div>
              <div className="w-full bg-gray-700 rounded-full h-2.5">
                <div className="bg-amber-500 h-2.5 rounded-full" style={{ width: `${(threatCounts.medium / threatCounts.total) * 100}%` }}></div>
              </div>
            </div>
            
            <div>
              <div className="flex justify-between mb-1">
                <span className="text-sm text-green-300 font-medium">Low Severity</span>
                <span className="text-sm text-green-300">{threatCounts.low} threats</span>
              </div>
              <div className="w-full bg-gray-700 rounded-full h-2.5">
                <div className="bg-green-500 h-2.5 rounded-full" style={{ width: `${(threatCounts.low / threatCounts.total) * 100}%` }}></div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
};

export default ThreatOverview;