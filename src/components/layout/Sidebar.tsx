import React, { useState } from 'react';
import { useTheme } from '../../context/ThemeContext';
import { Link, useLocation } from 'react-router-dom';
import { 
  LayoutDashboard, 
  Globe, 
  Network, 
  BarChart2, 
  Settings, 
  Shield, 
  AlertTriangle,
  ChevronLeft,
  ChevronRight
} from 'lucide-react';

const Sidebar: React.FC = () => {
  const { darkMode } = useTheme();
  const location = useLocation();
  const [collapsed, setCollapsed] = useState(false);

  const navItems = [
    { name: 'Dashboard', icon: <LayoutDashboard size={20} />, path: '/' },
    { name: 'Web Threats', icon: <Globe size={20} />, path: '/web-threats', badge: 5 },
    { name: 'Network Threats', icon: <Network size={20} />, path: '/network-threats', badge: 2 },
    { name: 'Analytics', icon: <BarChart2 size={20} />, path: '/analytics' },
    { name: 'Settings', icon: <Settings size={20} />, path: '/settings' },
  ];

  const secondaryItems = [
    { name: 'Alerts', icon: <AlertTriangle size={20} />, path: '/alerts', badge: 3 },
  ];

  const isActive = (path: string) => {
    return location.pathname === path;
  };

  return (
    <aside 
      className={`${darkMode ? 'bg-gray-800 text-gray-100' : 'bg-gray-100 text-gray-800'} 
        ${collapsed ? 'w-16' : 'w-64'} transition-all duration-300 flex flex-col border-r 
        ${darkMode ? 'border-gray-700' : 'border-gray-200'} relative`}
    >
      <button 
        className={`absolute -right-3 top-20 rounded-full p-1 
          ${darkMode ? 'bg-gray-700 text-gray-300' : 'bg-white text-gray-700'} 
          border ${darkMode ? 'border-gray-600' : 'border-gray-300'} shadow-md z-10`}
        onClick={() => setCollapsed(!collapsed)}
      >
        {collapsed ? <ChevronRight size={16} /> : <ChevronLeft size={16} />}
      </button>

      <div className="px-4 py-5">
        {!collapsed && (
          <div className="flex items-center">
            <Shield className="h-6 w-6 text-blue-500" />
            <h2 className="ml-2 text-lg font-bold">Nethra Vigil</h2>
          </div>
        )}
        {collapsed && (
          <div className="flex justify-center">
            <Shield className="h-6 w-6 text-blue-500" />
          </div>
        )}
      </div>

      <nav className="flex-1 py-4 px-2">
        <ul className="space-y-1">
          {navItems.map((item) => (
            <li key={item.name}>
              <Link
                to={item.path}
                className={`flex items-center ${
                  collapsed ? 'justify-center px-2' : 'px-4'
                } py-2 rounded-lg transition-colors ${
                  isActive(item.path)
                    ? 'bg-blue-600 text-white'
                    : `hover:bg-${darkMode ? 'gray-700' : 'gray-200'}`
                }`}
              >
                <span className={`${item.badge ? 'relative' : ''}`}>
                  {item.icon}
                  {item.badge && !collapsed && (
                    <span className="absolute -top-1 -right-1 bg-red-500 text-white text-xs rounded-full h-4 w-4 flex items-center justify-center">
                      {item.badge}
                    </span>
                  )}
                  {item.badge && collapsed && (
                    <span className="absolute -top-1 -right-1 bg-red-500 text-white text-xs rounded-full h-4 w-4 flex items-center justify-center">
                      {item.badge}
                    </span>
                  )}
                </span>
                {!collapsed && <span className="ml-3">{item.name}</span>}
              </Link>
            </li>
          ))}
        </ul>

        {!collapsed && <div className="mt-8 mb-2 px-4 text-xs uppercase text-gray-500 font-semibold">Advanced</div>}
        {collapsed && <div className="mt-8 mb-2 border-t border-gray-700"></div>}

        <ul className="space-y-1">
          {secondaryItems.map((item) => (
            <li key={item.name}>
              <Link
                to={item.path}
                className={`flex items-center ${
                  collapsed ? 'justify-center px-2' : 'px-4'
                } py-2 rounded-lg transition-colors ${
                  isActive(item.path)
                    ? 'bg-blue-600 text-white'
                    : `hover:bg-${darkMode ? 'gray-700' : 'gray-200'}`
                }`}
              >
                <span className={`${item.badge ? 'relative' : ''}`}>
                  {item.icon}
                  {item.badge && !collapsed && (
                    <span className="absolute -top-1 -right-1 bg-red-500 text-white text-xs rounded-full h-4 w-4 flex items-center justify-center">
                      {item.badge}
                    </span>
                  )}
                  {item.badge && collapsed && (
                    <span className="absolute -top-1 -right-1 bg-red-500 text-white text-xs rounded-full h-4 w-4 flex items-center justify-center">
                      {item.badge}
                    </span>
                  )}
                </span>
                {!collapsed && <span className="ml-3">{item.name}</span>}
              </Link>
            </li>
          ))}
        </ul>
      </nav>

      <div className="p-4 border-t border-gray-700">
        {!collapsed ? (
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <div className="h-8 w-8 rounded-full bg-blue-500 flex items-center justify-center text-white">
                A
              </div>
            </div>
            <div className="ml-3">
              <p className="text-sm font-medium">Admin User</p>
              <p className="text-xs text-gray-500">Security Admin</p>
            </div>
          </div>
        ) : (
          <div className="flex justify-center">
            <div className="h-8 w-8 rounded-full bg-blue-500 flex items-center justify-center text-white">
              A
            </div>
          </div>
        )}
      </div>
    </aside>
  );
};

export default Sidebar;