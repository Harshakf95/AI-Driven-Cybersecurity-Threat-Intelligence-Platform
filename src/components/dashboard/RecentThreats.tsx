import React from 'react';
import { useThreatData } from '../../context/ThreatContext';
import { WebThreat, NetworkThreat } from '../../types';
import { Shield, Globe, Network, Clock, XCircle, CheckCircle, AlertTriangle } from 'lucide-react';

const RecentThreats: React.FC = () => {
  const { threatData, blockThreat, ignoreThreat, isLoading } = useThreatData();
  
  const formatTimestamp = (timestamp: Date | string) => {
    const date = new Date(timestamp);
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };

  // Combine and sort threats by timestamp (newest first)
  const recentThreats = [...threatData.webThreats, ...threatData.networkThreats]
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
    .slice(0, 5); // Show only 5 most recent

  const getSeverityBadge = (severity: 'low' | 'medium' | 'high') => {
    switch (severity) {
      case 'high':
        return <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200">High</span>;
      case 'medium':
        return <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-200">Medium</span>;
      case 'low':
        return <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">Low</span>;
      default:
        return null;
    }
  };

  const getThreatIcon = (threat: WebThreat | NetworkThreat) => {
    const isWeb = 'targetEndpoint' in threat;
    
    if (isWeb) {
      return <Globe className={`h-5 w-5 ${getThreatIconColor(threat.severity)}`} />;
    } else {
      return <Network className={`h-5 w-5 ${getThreatIconColor(threat.severity)}`} />;
    }
  };

  const getThreatIconColor = (severity: 'low' | 'medium' | 'high') => {
    switch (severity) {
      case 'high': return 'text-red-500';
      case 'medium': return 'text-amber-500';
      case 'low': return 'text-green-500';
      default: return 'text-gray-500';
    }
  };

  if (isLoading) {
    return (
      <div className="animate-pulse">
        {[...Array(5)].map((_, index) => (
          <div key={index} className="p-4 border-b border-gray-700">
            <div className="h-4 bg-gray-700 rounded w-3/4 mb-2"></div>
            <div className="h-3 bg-gray-700 rounded w-1/2"></div>
          </div>
        ))}
      </div>
    );
  }

  return (
    <div className="divide-y divide-gray-700">
      {recentThreats.length === 0 ? (
        <div className="p-4 text-center text-gray-500">
          <Shield className="h-12 w-12 mx-auto mb-2 text-gray-600" />
          <p>No threats detected recently</p>
        </div>
      ) : (
        recentThreats.map((threat) => {
          const isWeb = 'targetEndpoint' in threat;
          const threatType = isWeb ? 'web' : 'network';
          const description = isWeb 
            ? `${(threat as WebThreat).attackType} at ${(threat as WebThreat).targetEndpoint}`
            : `${(threat as NetworkThreat).anomalyType} (${(threat as NetworkThreat).protocol})`;

          return (
            <div key={threat.id} className="p-4 hover:bg-gray-800 transition threat-item">
              <div className="flex justify-between items-start">
                <div className="flex items-start">
                  <div className="flex-shrink-0 mr-3 mt-1">
                    {getThreatIcon(threat)}
                  </div>
                  <div>
                    <h4 className="text-sm font-medium">{description}</h4>
                    <div className="mt-1 flex items-center text-xs text-gray-400">
                      <Clock className="h-3 w-3 mr-1" />
                      {formatTimestamp(threat.timestamp)}
                      <span className="mx-2">•</span>
                      <span>from {threat.sourceIP}</span>
                    </div>
                  </div>
                </div>
                <div className="ml-2">
                  {getSeverityBadge(threat.severity)}
                </div>
              </div>
              
              {threat.status === 'active' && (
                <div className="mt-2 flex justify-end space-x-2">
                  <button 
                    onClick={() => blockThreat(threat.id, threatType)}
                    className="inline-flex items-center px-2 py-1 text-xs rounded-md bg-red-900 text-red-100 hover:bg-red-800 transition"
                  >
                    <XCircle className="h-3 w-3 mr-1" />
                    Block
                  </button>
                  <button 
                    onClick={() => ignoreThreat(threat.id, threatType)}
                    className="inline-flex items-center px-2 py-1 text-xs rounded-md bg-gray-700 text-gray-100 hover:bg-gray-600 transition"
                  >
                    <CheckCircle className="h-3 w-3 mr-1" />
                    Ignore
                  </button>
                </div>
              )}
              
              {threat.status === 'blocked' && (
                <div className="mt-2 text-xs text-red-500 flex items-center justify-end">
                  <XCircle className="h-3 w-3 mr-1" />
                  Blocked
                </div>
              )}
              
              {threat.status === 'ignored' && (
                <div className="mt-2 text-xs text-gray-500 flex items-center justify-end">
                  <CheckCircle className="h-3 w-3 mr-1" />
                  Ignored
                </div>
              )}
            </div>
          );
        })
      )}
    </div>
  );
};

export default RecentThreats;