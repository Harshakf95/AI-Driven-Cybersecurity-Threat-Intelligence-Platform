import React from 'react';
import { useThreatData } from '../context/ThreatContext';
import { RefreshCw } from 'lucide-react';
import ThreatOverview from '../components/dashboard/ThreatOverview';
import SystemMetrics from '../components/dashboard/SystemMetrics';
import ThreatScoreGauge from '../components/dashboard/ThreatScoreGauge';
import RecentThreats from '../components/dashboard/RecentThreats';
import NetworkGraph from '../components/visualizations/NetworkGraph';

const Dashboard: React.FC = () => {
  const { refreshData, isLoading } = useThreatData();

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold">Security Dashboard</h1>
        <button 
          onClick={refreshData} 
          disabled={isLoading}
          className="flex items-center space-x-2 px-3 py-1.5 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 disabled:opacity-70 text-white rounded-md transition-colors"
        >
          <RefreshCw className={`h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      <ThreatOverview />

      <div className="grid grid-cols-1 lg:grid-cols-7 gap-6">
        <div className="lg:col-span-5 space-y-6">
          <div className="dashboard-card">
            <div className="p-4 border-b border-gray-700">
              <h2 className="text-lg font-medium">System Metrics</h2>
            </div>
            <div className="p-4">
              <SystemMetrics />
            </div>
          </div>

          <div className="dashboard-card">
            <div className="p-4 border-b border-gray-700">
              <h2 className="text-lg font-medium">Network Activity Map</h2>
            </div>
            <div className="p-4">
              <NetworkGraph />
            </div>
          </div>
        </div>

        <div className="lg:col-span-2 space-y-6">
          <div className="dashboard-card">
            <div className="p-4 border-b border-gray-700">
              <h2 className="text-lg font-medium">Threat Score</h2>
            </div>
            <div className="p-4">
              <ThreatScoreGauge />
            </div>
          </div>

          <div className="dashboard-card">
            <div className="p-4 border-b border-gray-700">
              <h2 className="text-lg font-medium">Recent Threats</h2>
            </div>
            <RecentThreats />
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;