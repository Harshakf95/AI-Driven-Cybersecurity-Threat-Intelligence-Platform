import React from 'react';
import { AlertTriangle, Shield, Bell } from 'lucide-react';
import { useThreatData } from '../context/ThreatContext';

const Alerts: React.FC = () => {
  const { threatData } = useThreatData();

  const alerts = [
    {
      id: 1,
      title: 'Critical SQL Injection Attempt',
      description: 'Multiple SQL injection attempts detected from IP 192.168.1.105',
      severity: 'high',
      timestamp: new Date(Date.now() - 1000 * 60 * 30).toISOString(), // 30 minutes ago
      status: 'unread'
    },
    {
      id: 2,
      title: 'Unusual Network Activity',
      description: 'Spike in outbound traffic detected from internal network',
      severity: 'medium',
      timestamp: new Date(Date.now() - 1000 * 60 * 60).toISOString(), // 1 hour ago
      status: 'unread'
    },
    {
      id: 3,
      title: 'Failed Login Attempts',
      description: 'Multiple failed login attempts for admin user',
      severity: 'high',
      timestamp: new Date(Date.now() - 1000 * 60 * 120).toISOString(), // 2 hours ago
      status: 'unread'
    }
  ];

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'high':
        return 'text-red-500 bg-red-500/10';
      case 'medium':
        return 'text-amber-500 bg-amber-500/10';
      case 'low':
        return 'text-green-500 bg-green-500/10';
      default:
        return 'text-gray-500 bg-gray-500/10';
    }
  };

  const formatTimestamp = (timestamp: string) => {
    const date = new Date(timestamp);
    return date.toLocaleString();
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold flex items-center">
          <Bell className="mr-2 h-6 w-6 text-blue-500" />
          Security Alerts
        </h1>
      </div>

      <div className="grid gap-6">
        {alerts.map((alert) => (
          <div
            key={alert.id}
            className="dashboard-card p-4 hover:transform hover:-translate-y-1 transition-all duration-200"
          >
            <div className="flex items-start justify-between">
              <div className="flex items-start space-x-4">
                <div className={`p-2 rounded-lg ${getSeverityColor(alert.severity)}`}>
                  <AlertTriangle className="h-6 w-6" />
                </div>
                <div>
                  <h3 className="font-semibold text-lg">{alert.title}</h3>
                  <p className="text-gray-400 mt-1">{alert.description}</p>
                  <div className="flex items-center mt-2 text-sm text-gray-500">
                    <Shield className="h-4 w-4 mr-1" />
                    <span className="capitalize">{alert.severity} Severity</span>
                    <span className="mx-2">•</span>
                    <span>{formatTimestamp(alert.timestamp)}</span>
                  </div>
                </div>
              </div>
              <div className="flex items-center space-x-2">
                <button className="px-3 py-1 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors">
                  View Details
                </button>
                <button className="px-3 py-1 bg-gray-700 text-white rounded-md hover:bg-gray-600 transition-colors">
                  Mark as Read
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default Alerts;