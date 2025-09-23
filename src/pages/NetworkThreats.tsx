import React, { useState } from 'react';
import { useThreatData } from '../context/ThreatContext';
import { NetworkThreat } from '../types';
import { Filter, AlertTriangle, ChevronDown, ChevronUp, Network, ShieldCheck, Shield, AlertOctagon } from 'lucide-react';

const NetworkThreats: React.FC = () => {
  const { threatData, blockThreat, ignoreThreat, isLoading } = useThreatData();
  const [sortBy, setSortBy] = useState<keyof NetworkThreat>('timestamp');
  const [sortDirection, setSortDirection] = useState<'asc' | 'desc'>('desc');
  const [filter, setFilter] = useState<{
    status: string;
    severity: string;
    type: string;
    protocol: string;
  }>({
    status: 'all',
    severity: 'all',
    type: 'all',
    protocol: 'all',
  });

  const handleSort = (column: keyof NetworkThreat) => {
    if (sortBy === column) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortBy(column);
      setSortDirection('desc');
    }
  };

  // Apply filters and sorting
  const filteredThreats = threatData.networkThreats.filter(threat => {
    let matches = true;
    
    if (filter.status !== 'all' && threat.status !== filter.status) {
      matches = false;
    }
    
    if (filter.severity !== 'all' && threat.severity !== filter.severity) {
      matches = false;
    }
    
    if (filter.type !== 'all' && threat.anomalyType !== filter.type) {
      matches = false;
    }
    
    if (filter.protocol !== 'all' && threat.protocol !== filter.protocol) {
      matches = false;
    }
    
    return matches;
  });

  // List of unique anomaly types and protocols for filtering
  const anomalyTypes = Array.from(new Set(threatData.networkThreats.map(threat => threat.anomalyType)));
  const protocols = Array.from(new Set(threatData.networkThreats.map(threat => threat.protocol)));

  // Sort the threats
  const sortedThreats = [...filteredThreats].sort((a, b) => {
    if (sortBy === 'timestamp') {
      const aTime = new Date(a[sortBy]).getTime();
      const bTime = new Date(b[sortBy]).getTime();
      return sortDirection === 'asc' ? aTime - bTime : bTime - aTime;
    }
    
    if (a[sortBy] < b[sortBy]) {
      return sortDirection === 'asc' ? -1 : 1;
    }
    if (a[sortBy] > b[sortBy]) {
      return sortDirection === 'asc' ? 1 : -1;
    }
    return 0;
  });

  const formatTimestamp = (timestamp: Date | string) => {
    const date = new Date(timestamp);
    return date.toLocaleString();
  };

  const getSeverityIcon = (severity: 'low' | 'medium' | 'high') => {
    switch (severity) {
      case 'high':
        return <AlertOctagon className="h-5 w-5 text-red-500" />;
      case 'medium':
        return <AlertTriangle className="h-5 w-5 text-amber-500" />;
      case 'low':
        return <Shield className="h-5 w-5 text-green-500" />;
      default:
        return null;
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'active':
        return <AlertTriangle className="h-5 w-5 text-amber-500" />;
      case 'blocked':
        return <ShieldCheck className="h-5 w-5 text-blue-500" />;
      case 'ignored':
        return <Shield className="h-5 w-5 text-gray-500" />;
      default:
        return null;
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold flex items-center">
          <Network className="mr-2 h-6 w-6 text-blue-500" />
          Network Traffic Threats
        </h1>
        
        <div className="flex space-x-4">
          <div className="relative">
            <select
              className="bg-gray-800 border border-gray-700 text-white rounded-md px-4 py-2 pr-8 appearance-none focus:outline-none focus:ring-2 focus:ring-blue-500"
              value={filter.status}
              onChange={(e) => setFilter({ ...filter, status: e.target.value })}
            >
              <option value="all">All Statuses</option>
              <option value="active">Active</option>
              <option value="blocked">Blocked</option>
              <option value="ignored">Ignored</option>
            </select>
            <ChevronDown className="absolute right-3 top-2.5 h-4 w-4 text-gray-400 pointer-events-none" />
          </div>
          
          <div className="relative">
            <select
              className="bg-gray-800 border border-gray-700 text-white rounded-md px-4 py-2 pr-8 appearance-none focus:outline-none focus:ring-2 focus:ring-blue-500"
              value={filter.severity}
              onChange={(e) => setFilter({ ...filter, severity: e.target.value })}
            >
              <option value="all">All Severities</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
            <ChevronDown className="absolute right-3 top-2.5 h-4 w-4 text-gray-400 pointer-events-none" />
          </div>
          
          <div className="relative">
            <select
              className="bg-gray-800 border border-gray-700 text-white rounded-md px-4 py-2 pr-8 appearance-none focus:outline-none focus:ring-2 focus:ring-blue-500"
              value={filter.type}
              onChange={(e) => setFilter({ ...filter, type: e.target.value })}
            >
              <option value="all">All Anomaly Types</option>
              {anomalyTypes.map(type => (
                <option key={type} value={type}>{type}</option>
              ))}
            </select>
            <ChevronDown className="absolute right-3 top-2.5 h-4 w-4 text-gray-400 pointer-events-none" />
          </div>
          
          <div className="relative">
            <select
              className="bg-gray-800 border border-gray-700 text-white rounded-md px-4 py-2 pr-8 appearance-none focus:outline-none focus:ring-2 focus:ring-blue-500"
              value={filter.protocol}
              onChange={(e) => setFilter({ ...filter, protocol: e.target.value })}
            >
              <option value="all">All Protocols</option>
              {protocols.map(protocol => (
                <option key={protocol} value={protocol}>{protocol}</option>
              ))}
            </select>
            <ChevronDown className="absolute right-3 top-2.5 h-4 w-4 text-gray-400 pointer-events-none" />
          </div>
        </div>
      </div>

      <div className="dashboard-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-700">
            <thead className="bg-gray-800">
              <tr>
                <th 
                  scope="col"
                  className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider cursor-pointer"
                  onClick={() => handleSort('timestamp')}
                >
                  <div className="flex items-center">
                    Timestamp
                    {sortBy === 'timestamp' && (
                      sortDirection === 'asc' ? 
                        <ChevronUp className="h-4 w-4 ml-1" /> : 
                        <ChevronDown className="h-4 w-4 ml-1" />
                    )}
                  </div>
                </th>
                <th 
                  scope="col"
                  className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider cursor-pointer"
                  onClick={() => handleSort('sourceIP')}
                >
                  <div className="flex items-center">
                    Source IP
                    {sortBy === 'sourceIP' && (
                      sortDirection === 'asc' ? 
                        <ChevronUp className="h-4 w-4 ml-1" /> : 
                        <ChevronDown className="h-4 w-4 ml-1" />
                    )}
                  </div>
                </th>
                <th 
                  scope="col"
                  className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider cursor-pointer"
                  onClick={() => handleSort('destinationIP')}
                >
                  <div className="flex items-center">
                    Destination IP
                    {sortBy === 'destinationIP' && (
                      sortDirection === 'asc' ? 
                        <ChevronUp className="h-4 w-4 ml-1" /> : 
                        <ChevronDown className="h-4 w-4 ml-1" />
                    )}
                  </div>
                </th>
                <th 
                  scope="col"
                  className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider cursor-pointer"
                  onClick={() => handleSort('protocol')}
                >
                  <div className="flex items-center">
                    Protocol / Port
                    {sortBy === 'protocol' && (
                      sortDirection === 'asc' ? 
                        <ChevronUp className="h-4 w-4 ml-1" /> : 
                        <ChevronDown className="h-4 w-4 ml-1" />
                    )}
                  </div>
                </th>
                <th 
                  scope="col"
                  className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider cursor-pointer"
                  onClick={() => handleSort('anomalyType')}
                >
                  <div className="flex items-center">
                    Anomaly Type
                    {sortBy === 'anomalyType' && (
                      sortDirection === 'asc' ? 
                        <ChevronUp className="h-4 w-4 ml-1" /> : 
                        <ChevronDown className="h-4 w-4 ml-1" />
                    )}
                  </div>
                </th>
                <th 
                  scope="col"
                  className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider cursor-pointer"
                  onClick={() => handleSort('severity')}
                >
                  <div className="flex items-center">
                    Severity
                    {sortBy === 'severity' && (
                      sortDirection === 'asc' ? 
                        <ChevronUp className="h-4 w-4 ml-1" /> : 
                        <ChevronDown className="h-4 w-4 ml-1" />
                    )}
                  </div>
                </th>
                <th 
                  scope="col"
                  className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider cursor-pointer"
                  onClick={() => handleSort('status')}
                >
                  <div className="flex items-center">
                    Status
                    {sortBy === 'status' && (
                      sortDirection === 'asc' ? 
                        <ChevronUp className="h-4 w-4 ml-1" /> : 
                        <ChevronDown className="h-4 w-4 ml-1" />
                    )}
                  </div>
                </th>
                <th 
                  scope="col"
                  className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider"
                >
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="bg-gray-800 divide-y divide-gray-700">
              {isLoading ? (
                <tr>
                  <td colSpan={8} className="px-6 py-4 text-center text-gray-500">
                    <div className="flex justify-center items-center space-x-2">
                      <Filter className="h-5 w-5 animate-spin" />
                      <span>Loading threats...</span>
                    </div>
                  </td>
                </tr>
              ) : sortedThreats.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-6 py-4 text-center text-gray-500">
                    No network threats found matching the current filters.
                  </td>
                </tr>
              ) : (
                sortedThreats.map((threat) => (
                  <tr key={threat.id} className="hover:bg-gray-750">
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-200">
                      {formatTimestamp(threat.timestamp)}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-200">
                      {threat.sourceIP}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-200">
                      {threat.destinationIP}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-200">
                      {threat.protocol}:{threat.port}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-200">
                      {threat.anomalyType}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center">
                        {getSeverityIcon(threat.severity)}
                        <span 
                          className={`ml-2 text-sm ${
                            threat.severity === 'high' ? 'text-red-500' : 
                            threat.severity === 'medium' ? 'text-amber-500' : 
                            'text-green-500'
                          }`}
                        >
                          {threat.severity.charAt(0).toUpperCase() + threat.severity.slice(1)}
                        </span>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center">
                        {getStatusIcon(threat.status)}
                        <span 
                          className={`ml-2 text-sm ${
                            threat.status === 'active' ? 'text-amber-500' : 
                            threat.status === 'blocked' ? 'text-blue-500' : 
                            'text-gray-500'
                          }`}
                        >
                          {threat.status.charAt(0).toUpperCase() + threat.status.slice(1)}
                        </span>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                      {threat.status === 'active' && (
                        <div className="flex space-x-2">
                          <button
                            onClick={() => blockThreat(threat.id, 'network')}
                            className="text-blue-500 hover:text-blue-400 transition-colors"
                          >
                            Block
                          </button>
                          <button
                            onClick={() => ignoreThreat(threat.id, 'network')}
                            className="text-gray-400 hover:text-gray-300 transition-colors"
                          >
                            Ignore
                          </button>
                        </div>
                      )}
                      {threat.status !== 'active' && (
                        <span className="text-gray-500">No actions available</span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default NetworkThreats;