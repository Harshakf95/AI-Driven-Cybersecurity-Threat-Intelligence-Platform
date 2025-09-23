import React, { useState } from 'react';
import { useTheme } from '../context/ThemeContext';
import { 
  Settings as SettingsIcon, 
  Bell, 
  Shield, 
  User, 
  Database, 
  Server, 
  Globe,
  Save,
  CheckCircle
} from 'lucide-react';

const Settings: React.FC = () => {
  const { darkMode, toggleTheme } = useTheme();
  const [saveStatus, setSaveStatus] = useState<'idle' | 'saving' | 'success'>('idle');
  
  const [settings, setSettings] = useState({
    notifications: {
      emailAlerts: true,
      slackIntegration: false,
      alertFrequency: 'high',
      quietHours: false,
      quietHoursStart: '22:00',
      quietHoursEnd: '07:00'
    },
    security: {
      autoBlockHighThreats: true,
      scanFrequency: 'medium',
      ipAllowlist: '',
      ipBlocklist: '',
      enableMFA: true,
      sessionTimeout: 30
    },
    system: {
      logRetention: 90,
      performanceMode: 'balanced',
      aiLearningMode: 'active',
      dataCollectionConsent: true
    }
  });
  
  const handleChange = (category: string, setting: string, value: any) => {
    setSettings(prev => ({
      ...prev,
      [category]: {
        ...prev[category as keyof typeof prev],
        [setting]: value
      }
    }));
  };
  
  const handleSave = () => {
    setSaveStatus('saving');
    
    // Simulate save to backend
    setTimeout(() => {
      setSaveStatus('success');
      
      // Reset success message after 3 seconds
      setTimeout(() => {
        setSaveStatus('idle');
      }, 3000);
    }, 1000);
  };
  
  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold flex items-center">
          <SettingsIcon className="mr-2 h-6 w-6 text-blue-500" />
          System Settings
        </h1>
        
        <button 
          onClick={handleSave}
          disabled={saveStatus === 'saving'}
          className={`flex items-center space-x-2 px-4 py-2 rounded-md transition-colors ${
            saveStatus === 'success' 
              ? 'bg-green-600 hover:bg-green-700 text-white'
              : 'bg-blue-600 hover:bg-blue-700 text-white'
          }`}
        >
          {saveStatus === 'idle' && (
            <>
              <Save className="h-4 w-4" />
              <span>Save Settings</span>
            </>
          )}
          
          {saveStatus === 'saving' && (
            <>
              <div className="h-4 w-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
              <span>Saving...</span>
            </>
          )}
          
          {saveStatus === 'success' && (
            <>
              <CheckCircle className="h-4 w-4" />
              <span>Saved!</span>
            </>
          )}
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Notification Settings */}
        <div className="dashboard-card">
          <div className="p-4 border-b border-gray-700 flex items-center">
            <Bell className="h-5 w-5 text-blue-500 mr-2" />
            <h2 className="text-lg font-medium">Notification Settings</h2>
          </div>
          <div className="p-4 space-y-4">
            <div>
              <label className="flex items-center space-x-2 cursor-pointer">
                <input 
                  type="checkbox" 
                  className="form-checkbox h-4 w-4 text-blue-500 rounded bg-gray-700 border-gray-600 focus:ring-blue-500"
                  checked={settings.notifications.emailAlerts}
                  onChange={(e) => handleChange('notifications', 'emailAlerts', e.target.checked)}
                />
                <span>Email Alerts</span>
              </label>
              <p className="text-sm text-gray-400 mt-1 ml-6">Receive threat notifications via email</p>
            </div>
            
            <div>
              <label className="flex items-center space-x-2 cursor-pointer">
                <input 
                  type="checkbox" 
                  className="form-checkbox h-4 w-4 text-blue-500 rounded bg-gray-700 border-gray-600 focus:ring-blue-500" 
                  checked={settings.notifications.slackIntegration}
                  onChange={(e) => handleChange('notifications', 'slackIntegration', e.target.checked)}
                />
                <span>Slack Integration</span>
              </label>
              <p className="text-sm text-gray-400 mt-1 ml-6">Send threat alerts to Slack channel</p>
            </div>
            
            <div>
              <label className="block text-sm font-medium mb-1">Alert Frequency</label>
              <select 
                className="w-full bg-gray-700 border border-gray-600 text-white rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                value={settings.notifications.alertFrequency}
                onChange={(e) => handleChange('notifications', 'alertFrequency', e.target.value)}
              >
                <option value="high">High (All Threats)</option>
                <option value="medium">Medium (Medium & High Threats)</option>
                <option value="low">Low (High Threats Only)</option>
              </select>
              <p className="text-sm text-gray-400 mt-1">Control how often you receive alerts</p>
            </div>
            
            <div>
              <label className="flex items-center space-x-2 cursor-pointer">
                <input 
                  type="checkbox" 
                  className="form-checkbox h-4 w-4 text-blue-500 rounded bg-gray-700 border-gray-600 focus:ring-blue-500" 
                  checked={settings.notifications.quietHours}
                  onChange={(e) => handleChange('notifications', 'quietHours', e.target.checked)}
                />
                <span>Enable Quiet Hours</span>
              </label>
              
              {settings.notifications.quietHours && (
                <div className="grid grid-cols-2 gap-2 mt-2 ml-6">
                  <div>
                    <label className="block text-sm mb-1">Start Time</label>
                    <input 
                      type="time" 
                      className="w-full bg-gray-700 border border-gray-600 text-white rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                      value={settings.notifications.quietHoursStart}
                      onChange={(e) => handleChange('notifications', 'quietHoursStart', e.target.value)}
                    />
                  </div>
                  <div>
                    <label className="block text-sm mb-1">End Time</label>
                    <input 
                      type="time" 
                      className="w-full bg-gray-700 border border-gray-600 text-white rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                      value={settings.notifications.quietHoursEnd}
                      onChange={(e) => handleChange('notifications', 'quietHoursEnd', e.target.value)}
                    />
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
        
        {/* Security Settings */}
        <div className="dashboard-card">
          <div className="p-4 border-b border-gray-700 flex items-center">
            <Shield className="h-5 w-5 text-blue-500 mr-2" />
            <h2 className="text-lg font-medium">Security Settings</h2>
          </div>
          <div className="p-4 space-y-4">
            <div>
              <label className="flex items-center space-x-2 cursor-pointer">
                <input 
                  type="checkbox" 
                  className="form-checkbox h-4 w-4 text-blue-500 rounded bg-gray-700 border-gray-600 focus:ring-blue-500"
                  checked={settings.security.autoBlockHighThreats}
                  onChange={(e) => handleChange('security', 'autoBlockHighThreats', e.target.checked)}
                />
                <span>Auto-block High Severity Threats</span>
              </label>
              <p className="text-sm text-gray-400 mt-1 ml-6">Immediately block any high severity threats</p>
            </div>
            
            <div>
              <label className="block text-sm font-medium mb-1">Scan Frequency</label>
              <select 
                className="w-full bg-gray-700 border border-gray-600 text-white rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                value={settings.security.scanFrequency}
                onChange={(e) => handleChange('security', 'scanFrequency', e.target.value)}
              >
                <option value="high">High (Every 5 minutes)</option>
                <option value="medium">Medium (Every 15 minutes)</option>
                <option value="low">Low (Every 30 minutes)</option>
              </select>
              <p className="text-sm text-gray-400 mt-1">How often the system scans for threats</p>
            </div>
            
            <div>
              <label className="block text-sm font-medium mb-1">IP Allowlist (one per line)</label>
              <textarea 
                className="w-full bg-gray-700 border border-gray-600 text-white rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 h-20"
                placeholder="e.g. 192.168.1.1"
                value={settings.security.ipAllowlist}
                onChange={(e) => handleChange('security', 'ipAllowlist', e.target.value)}
              ></textarea>
            </div>
            
            <div>
              <label className="flex items-center space-x-2 cursor-pointer">
                <input 
                  type="checkbox" 
                  className="form-checkbox h-4 w-4 text-blue-500 rounded bg-gray-700 border-gray-600 focus:ring-blue-500"
                  checked={settings.security.enableMFA}
                  onChange={(e) => handleChange('security', 'enableMFA', e.target.checked)}
                />
                <span>Enable Multi-Factor Authentication</span>
              </label>
            </div>
            
            <div>
              <label className="block text-sm font-medium mb-1">Session Timeout (minutes)</label>
              <input 
                type="number" 
                className="w-full bg-gray-700 border border-gray-600 text-white rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                min="1"
                max="1440"
                value={settings.security.sessionTimeout}
                onChange={(e) => handleChange('security', 'sessionTimeout', parseInt(e.target.value) || 30)}
              />
            </div>
          </div>
        </div>
        
        {/* System Settings */}
        <div className="dashboard-card">
          <div className="p-4 border-b border-gray-700 flex items-center">
            <Server className="h-5 w-5 text-blue-500 mr-2" />
            <h2 className="text-lg font-medium">System Settings</h2>
          </div>
          <div className="p-4 space-y-4">
            <div>
              <label className="block text-sm font-medium mb-1">Log Retention Period (days)</label>
              <input 
                type="number" 
                className="w-full bg-gray-700 border border-gray-600 text-white rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                min="1"
                max="365"
                value={settings.system.logRetention}
                onChange={(e) => handleChange('system', 'logRetention', parseInt(e.target.value) || 90)}
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium mb-1">Performance Mode</label>
              <select 
                className="w-full bg-gray-700 border border-gray-600 text-white rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                value={settings.system.performanceMode}
                onChange={(e) => handleChange('system', 'performanceMode', e.target.value)}
              >
                <option value="high">High Performance (More resource usage)</option>
                <option value="balanced">Balanced (Recommended)</option>
                <option value="low">Low Impact (Fewer scans, less resource usage)</option>
              </select>
            </div>
            
            <div>
              <label className="block text-sm font-medium mb-1">AI Learning Mode</label>
              <select 
                className="w-full bg-gray-700 border border-gray-600 text-white rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                value={settings.system.aiLearningMode}
                onChange={(e) => handleChange('system', 'aiLearningMode', e.target.value)}
              >
                <option value="active">Active Learning (Recommended)</option>
                <option value="passive">Passive Learning</option>
                <option value="disabled">Disabled</option>
              </select>
              <p className="text-sm text-gray-400 mt-1">Controls how the AI learns from new threats</p>
            </div>
            
            <div>
              <label className="block text-sm font-medium mb-1">Theme</label>
              <div className="flex space-x-4 mt-2">
                <label className={`flex flex-col items-center space-y-2 p-3 rounded-lg cursor-pointer border ${!darkMode ? 'border-blue-500' : 'border-gray-600'}`} onClick={toggleTheme}>
                  <div className="w-12 h-12 rounded-lg bg-white flex items-center justify-center">
                    <Globe className="h-6 w-6 text-gray-800" />
                  </div>
                  <span className="text-sm">Light</span>
                </label>
                
                <label className={`flex flex-col items-center space-y-2 p-3 rounded-lg cursor-pointer border ${darkMode ? 'border-blue-500' : 'border-gray-600'}`} onClick={toggleTheme}>
                  <div className="w-12 h-12 rounded-lg bg-gray-800 flex items-center justify-center">
                    <Globe className="h-6 w-6 text-white" />
                  </div>
                  <span className="text-sm">Dark</span>
                </label>
              </div>
            </div>
            
            <div>
              <label className="flex items-center space-x-2 cursor-pointer">
                <input 
                  type="checkbox" 
                  className="form-checkbox h-4 w-4 text-blue-500 rounded bg-gray-700 border-gray-600 focus:ring-blue-500"
                  checked={settings.system.dataCollectionConsent}
                  onChange={(e) => handleChange('system', 'dataCollectionConsent', e.target.checked)}
                />
                <span>Allow Anonymous Data Collection</span>
              </label>
              <p className="text-sm text-gray-400 mt-1 ml-6">Help improve Nethra Vigil by sharing anonymous usage data</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Settings;