import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { ThreatData, WebThreat, NetworkThreat, SystemMetrics } from '../types';
import { generateThreats, generateSystemMetrics } from '../utils/threatGenerator';

interface ThreatContextType {
  threatData: ThreatData;
  isLoading: boolean;
  refreshData: () => void;
  addWebThreat: (threat: WebThreat) => void;
  addNetworkThreat: (threat: NetworkThreat) => void;
  blockThreat: (id: string, type: 'web' | 'network') => void;
  ignoreThreat: (id: string, type: 'web' | 'network') => void;
  systemMetrics: SystemMetrics;
}

const ThreatContext = createContext<ThreatContextType>({
  threatData: { webThreats: [], networkThreats: [] },
  isLoading: true,
  refreshData: () => {},
  addWebThreat: () => {},
  addNetworkThreat: () => {},
  blockThreat: () => {},
  ignoreThreat: () => {},
  systemMetrics: {
    cpuUsage: 0,
    memoryUsage: 0,
    networkIn: 0,
    networkOut: 0,
    threatScore: 0,
    activeConnections: 0,
    totalRequests: 0,
    blockedRequests: 0
  }
});

export const useThreatData = () => useContext(ThreatContext);

interface ThreatProviderProps {
  children: ReactNode;
}

export const ThreatProvider: React.FC<ThreatProviderProps> = ({ children }) => {
  const [threatData, setThreatData] = useState<ThreatData>({
    webThreats: [],
    networkThreats: []
  });
  const [systemMetrics, setSystemMetrics] = useState<SystemMetrics>({
    cpuUsage: 0,
    memoryUsage: 0,
    networkIn: 0,
    networkOut: 0,
    threatScore: 0,
    activeConnections: 0,
    totalRequests: 0,
    blockedRequests: 0
  });
  const [isLoading, setIsLoading] = useState(true);

  const fetchData = () => {
    setIsLoading(true);
    // Simulate API call with generated data
    setTimeout(() => {
      const generatedThreats = generateThreats();
      const metrics = generateSystemMetrics();
      setThreatData(generatedThreats);
      setSystemMetrics(metrics);
      setIsLoading(false);
    }, 1000);
  };

  useEffect(() => {
    fetchData();
    
    // Refresh data periodically
    const interval = setInterval(() => {
      fetchData();
    }, 60000); // Refresh every minute
    
    return () => clearInterval(interval);
  }, []);

  const refreshData = () => {
    fetchData();
  };

  const addWebThreat = (threat: WebThreat) => {
    setThreatData(prev => ({
      ...prev,
      webThreats: [threat, ...prev.webThreats]
    }));
  };

  const addNetworkThreat = (threat: NetworkThreat) => {
    setThreatData(prev => ({
      ...prev,
      networkThreats: [threat, ...prev.networkThreats]
    }));
  };

  const blockThreat = (id: string, type: 'web' | 'network') => {
    if (type === 'web') {
      setThreatData(prev => ({
        ...prev,
        webThreats: prev.webThreats.map(threat => 
          threat.id === id ? { ...threat, status: 'blocked' } : threat
        )
      }));
    } else {
      setThreatData(prev => ({
        ...prev,
        networkThreats: prev.networkThreats.map(threat => 
          threat.id === id ? { ...threat, status: 'blocked' } : threat
        )
      }));
    }
  };

  const ignoreThreat = (id: string, type: 'web' | 'network') => {
    if (type === 'web') {
      setThreatData(prev => ({
        ...prev,
        webThreats: prev.webThreats.map(threat => 
          threat.id === id ? { ...threat, status: 'ignored' } : threat
        )
      }));
    } else {
      setThreatData(prev => ({
        ...prev,
        networkThreats: prev.networkThreats.map(threat => 
          threat.id === id ? { ...threat, status: 'ignored' } : threat
        )
      }));
    }
  };

  return (
    <ThreatContext.Provider 
      value={{
        threatData,
        isLoading,
        refreshData,
        addWebThreat,
        addNetworkThreat,
        blockThreat,
        ignoreThreat,
        systemMetrics
      }}
    >
      {children}
    </ThreatContext.Provider>
  );
};