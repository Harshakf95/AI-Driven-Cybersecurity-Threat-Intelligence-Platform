import React from 'react';
import { useThreatData } from '../../context/ThreatContext';
import { Cpu, HardDrive, ArrowDown, ArrowUp, Activity, Shield, Database, AlertOctagon } from 'lucide-react';

const SystemMetrics: React.FC = () => {
  const { systemMetrics, isLoading } = useThreatData();
  
  const metricItems = [
    {
      label: 'CPU Usage',
      value: `${systemMetrics.cpuUsage}%`,
      icon: <Cpu className="h-5 w-5 text-blue-400" />,
      color: systemMetrics.cpuUsage > 80 ? 'text-red-500' : systemMetrics.cpuUsage > 60 ? 'text-amber-500' : 'text-blue-500'
    },
    {
      label: 'Memory Usage',
      value: `${systemMetrics.memoryUsage}%`,
      icon: <HardDrive className="h-5 w-5 text-purple-400" />,
      color: systemMetrics.memoryUsage > 80 ? 'text-red-500' : systemMetrics.memoryUsage > 60 ? 'text-amber-500' : 'text-purple-500'
    },
    {
      label: 'Network In',
      value: `${systemMetrics.networkIn} Mbps`,
      icon: <ArrowDown className="h-5 w-5 text-green-400" />,
      color: 'text-green-500'
    },
    {
      label: 'Network Out',
      value: `${systemMetrics.networkOut} Mbps`,
      icon: <ArrowUp className="h-5 w-5 text-amber-400" />,
      color: 'text-amber-500'
    },
    {
      label: 'Active Connections',
      value: systemMetrics.activeConnections.toLocaleString(),
      icon: <Activity className="h-5 w-5 text-blue-400" />,
      color: 'text-blue-500'
    },
    {
      label: 'Total Requests',
      value: systemMetrics.totalRequests.toLocaleString(),
      icon: <Database className="h-5 w-5 text-indigo-400" />,
      color: 'text-indigo-500'
    },
    {
      label: 'Blocked Requests',
      value: systemMetrics.blockedRequests.toLocaleString(),
      icon: <Shield className="h-5 w-5 text-red-400" />,
      color: 'text-red-500'
    },
    {
      label: 'Threats Detected',
      value: `${Math.floor(Math.random() * 10) + 5} today`,
      icon: <AlertOctagon className="h-5 w-5 text-red-400" />,
      color: 'text-red-500'
    }
  ];

  if (isLoading) {
    return (
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 animate-pulse">
        {[...Array(8)].map((_, index) => (
          <div key={index} className="bg-gray-800 rounded-lg p-4 min-h-20">
            <div className="h-4 bg-gray-700 rounded-full w-16 mb-2"></div>
            <div className="h-6 bg-gray-700 rounded-full w-24"></div>
          </div>
        ))}
      </div>
    );
  }

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
      {metricItems.map((item, index) => (
        <div key={index} className="bg-gray-800 rounded-lg p-4 border border-gray-700 hover:border-gray-600 transition-colors">
          <div className="flex items-center mb-2">
            {item.icon}
            <span className="text-gray-400 ml-2 text-sm">{item.label}</span>
          </div>
          <div className={`text-lg font-semibold ${item.color}`}>{item.value}</div>
        </div>
      ))}
    </div>
  );
};

export default SystemMetrics;