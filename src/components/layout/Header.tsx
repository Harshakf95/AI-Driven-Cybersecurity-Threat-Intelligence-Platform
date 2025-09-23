import React, { useState, useRef, useEffect } from 'react';
import { Search, Shield, LogIn, Moon, Sun } from 'lucide-react';
import { useTheme } from '../../context/ThemeContext';
import { useAuth } from '../../context/AuthContext';
import NotificationCenter from '../ui/NotificationCenter';
import UserMenu from '../ui/UserMenu';
import { Link, useNavigate } from 'react-router-dom';

type SearchSuggestion = {
  id: string;
  label: string;
  category: 'threats' | 'logs' | 'users' | 'devices';
  icon: React.ReactNode;
};

const Header: React.FC = () => {
  const { darkMode, toggleTheme } = useTheme();
  const [searchQuery, setSearchQuery] = useState('');
  const [isSearchFocused, setIsSearchFocused] = useState(false);
  const [searchSuggestions, setSearchSuggestions] = useState<SearchSuggestion[]>([]);
  const searchRef = useRef<HTMLDivElement>(null);

  const { logout, isAuthenticated } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  // Handle clicks outside search to close suggestions
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (searchRef.current && !searchRef.current.contains(event.target as Node)) {
        setIsSearchFocused(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, []);

  // Generate search suggestions based on query
  useEffect(() => {
    if (searchQuery.trim() === '') {
      setSearchSuggestions([]);
      return;
    }

    // Mock search suggestions - in a real app, this would be an API call
    const mockSuggestions: SearchSuggestion[] = [
      {
        id: 'threat-1',
        label: `Search for "${searchQuery}" in threats`,
        category: 'threats',
        icon: <Search className="h-4 w-4" />
      },
      {
        id: 'log-1',
        label: `Search for "${searchQuery}" in logs`,
        category: 'logs',
        icon: <Search className="h-4 w-4" />
      },
      {
        id: 'user-1',
        label: `Search for "${searchQuery}" in users`,
        category: 'users',
        icon: <Search className="h-4 w-4" />
      }
    ];

    setSearchSuggestions(mockSuggestions);
  }, [searchQuery]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (searchQuery.trim()) {
      console.log('Searching for:', searchQuery);
      // Handle search submission
      setIsSearchFocused(false);
    }
  };

  const handleSuggestionClick = (suggestion: SearchSuggestion) => {
    console.log('Selected suggestion:', suggestion);
    // Handle suggestion selection
    setIsSearchFocused(false);
  };

  return (
    <header 
      className={`sticky top-0 z-40 flex items-center justify-between px-4 py-3 border-b shadow-sm ${
        darkMode 
          ? 'bg-gray-800 text-white border-gray-700' 
          : 'bg-white text-gray-800 border-gray-200'
      }`}
    >
      {/* Left section - Logo and Search */}
      <div className="flex items-center">
        <Link
          to="/"
          className="flex items-center mr-4 cursor-pointer select-none"
          aria-label="Go to NetraVigil dashboard"
          title="NetraVigil"
        >
          <Shield className="h-7 w-7 text-blue-500" />
          <h1 className="ml-2 text-xl font-bold tracking-tight">
            <span className="text-blue-500">NETHRA</span> VIGIL
          </h1>
        </Link>

        {/* Search Bar */}
        <div 
          ref={searchRef}
          className={`hidden md:flex items-center rounded-lg px-3 py-1.5 ml-4 flex-1 max-w-md transition-all duration-200 ${
            isSearchFocused
              ? darkMode 
                ? 'bg-gray-900 ring-2 ring-blue-500' 
                : 'bg-white ring-2 ring-blue-400 shadow-md'
              : darkMode 
                ? 'bg-gray-700' 
                : 'bg-gray-100'
          }`}
        >
          <form onSubmit={handleSearchSubmit} className="flex-1 flex">
            <Search className={`h-4 w-4 flex-shrink-0 ${
              darkMode ? 'text-gray-400' : 'text-gray-500'
            }`} />
            <input
              type="text"
              placeholder="Search threats, alerts, and logs..."
              className={`bg-transparent border-none focus:outline-none px-2 py-1 text-sm w-full ${
                darkMode ? 'text-gray-200 placeholder-gray-400' : 'text-gray-800 placeholder-gray-500'
              }`}
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              onFocus={() => setIsSearchFocused(true)}
              aria-label="Search"
            />
          </form>
          
          {/* Search suggestions dropdown */}
          {isSearchFocused && searchSuggestions.length > 0 && (
            <div className={`absolute top-full left-0 right-0 mt-1 mx-4 rounded-md shadow-lg z-50 ${
              darkMode 
                ? 'bg-gray-800 border border-gray-700' 
                : 'bg-white border border-gray-200'
            }`}>
              <div className="py-1">
                <div className="px-4 py-2 text-xs font-medium text-gray-500">
                  Quick Actions
                </div>
                {searchSuggestions.map((suggestion) => (
                  <button 
                    key={suggestion.id}
                    onClick={() => handleSuggestionClick(suggestion)}
                    className={`w-full text-left px-4 py-2 text-sm flex items-center space-x-2 ${
                      darkMode 
                        ? 'text-gray-200 hover:bg-gray-700' 
                        : 'text-gray-700 hover:bg-gray-100'
                    }`}
                  >
                    {suggestion.icon}
                    <span>{suggestion.label}</span>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Right section - Icons and User Menu */}
      <div className="flex items-center space-x-4">
        {/* Quick Actions Button */}
        <button 
          className={`p-1.5 rounded-full ${
            darkMode 
              ? 'text-gray-300 hover:bg-gray-700 hover:text-white' 
              : 'text-gray-500 hover:bg-gray-100 hover:text-gray-700'
          }`}
          title="Quick Actions"
          onClick={() => console.log('Quick actions')}
        >
          <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
          </svg>
        </button>

        {/* Notification Center */}
        <NotificationCenter darkMode={darkMode} />

        {/* Right section - User controls */}
        <div className="flex items-center space-x-4">
          <button
            onClick={toggleTheme}
            className={`p-2 rounded-full focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 ${
              darkMode ? 'hover:bg-gray-700' : 'hover:bg-gray-100'
            }`}
            aria-label={darkMode ? 'Switch to light mode' : 'Switch to dark mode'}
          >
            {darkMode ? (
              <Sun className="h-5 w-5" />
            ) : (
              <Moon className="h-5 w-5" />
            )}
          </button>

          <NotificationCenter darkMode={darkMode} />

          {isAuthenticated ? (
            <UserMenu 
              darkMode={darkMode} 
              toggleTheme={toggleTheme} 
              onLogout={handleLogout}
            />
          ) : (
            <Link
              to="/login"
              className={`flex items-center space-x-2 px-3 py-2 rounded-md text-sm font-medium focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 ${
                darkMode
                  ? 'text-white hover:bg-gray-700'
                  : 'text-gray-700 hover:bg-gray-100'
              }`}
            >
              <LogIn className="h-5 w-5" />
              <span>Login</span>
            </Link>
          )}
        </div>
      </div>
    </header>
  );
};

export default Header;