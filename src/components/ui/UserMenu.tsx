import React, { useState, useRef, useEffect, KeyboardEvent, useCallback } from 'react';
import { LogOut, User, Settings, Moon, Sun, HelpCircle, Keyboard, X } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';

interface MenuItem {
  icon: React.ReactNode;
  label: string;
  onClick: () => void;
  shortcut?: string;
}

interface KeyboardShortcut {
  keys: string[];
  description: string;
}

interface UserMenuProps {
  darkMode: boolean;
  toggleTheme: () => void;
  onLogout: () => void;
}

// Keyboard shortcuts configuration
const keyboardShortcuts: KeyboardShortcut[] = [
  { keys: ['Ctrl', 'K'], description: 'Command palette' },
  { keys: ['Ctrl', '/'], description: 'Show all shortcuts' },
  { keys: ['Ctrl', 'N'], description: 'New item' },
  { keys: ['Ctrl', ','], description: 'Open settings' },
  { keys: ['Escape'], description: 'Close modals/panels' },
];

const UserMenu: React.FC<UserMenuProps> = ({ darkMode, toggleTheme, onLogout }) => {
  const { user } = useAuth();
  const [isOpen, setIsOpen] = useState(false);
  const [showShortcuts, setShowShortcuts] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const menuButtonRef = useRef<HTMLButtonElement>(null);
  const menuItemsRef = useRef<(HTMLButtonElement | null)[]>([]);

  const toggleMenu = () => setIsOpen(prev => !prev);
  const closeMenu = useCallback(() => setIsOpen(false), []);
  const toggleShortcuts = () => setShowShortcuts(prev => !prev);

  // Close menu when clicking outside or pressing Escape
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        closeMenu();
      }
    };

    const handleEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        closeMenu();
        if (showShortcuts) {
          setShowShortcuts(false);
        }
      }
    };

    if (isOpen || showShortcuts) {
      document.addEventListener('mousedown', handleClickOutside);
      document.addEventListener('keydown', handleEscape as any);
    }

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('keydown', handleEscape as any);
    };
  }, [isOpen, showShortcuts, closeMenu]);

  // Focus management for keyboard navigation
  useEffect(() => {
    if (isOpen && menuItemsRef.current.length > 0) {
      menuItemsRef.current[0]?.focus();
    } else if (!isOpen && menuButtonRef.current) {
      menuButtonRef.current.focus();
    }
  }, [isOpen]);

  const handleKeyDown = (e: KeyboardEvent<HTMLButtonElement>, index: number) => {
    if (!menuItemsRef.current) return;

    const menuItemCount = menuItemsRef.current.length;
    let nextIndex = index;

    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault();
        nextIndex = (index + 1) % menuItemCount;
        break;
      case 'ArrowUp':
        e.preventDefault();
        nextIndex = (index - 1 + menuItemCount) % menuItemCount;
        break;
      case 'Home':
        e.preventDefault();
        nextIndex = 0;
        break;
      case 'End':
        e.preventDefault();
        nextIndex = menuItemCount - 1;
        break;
      case 'Escape':
        closeMenu();
        return;
      default:
        return;
    }

    menuItemsRef.current[nextIndex]?.focus();
  };

  const menuItems: MenuItem[] = [
    { 
      icon: <User size={16} aria-hidden="true" />, 
      label: 'Profile', 
      onClick: () => {
        console.log('Profile clicked');
        closeMenu();
      },
      shortcut: 'P'
    },
    { 
      icon: <Settings size={16} aria-hidden="true" />, 
      label: 'Settings', 
      onClick: () => {
        console.log('Settings clicked');
        closeMenu();
      },
      shortcut: ','
    },
    { 
      icon: darkMode ? <Sun size={16} aria-hidden="true" /> : <Moon size={16} aria-hidden="true" />, 
      label: `${darkMode ? 'Light' : 'Dark'} Mode`, 
      onClick: () => {
        toggleTheme();
        closeMenu();
      },
      shortcut: 'T'
    },
    { 
      icon: <Keyboard size={16} aria-hidden="true" />, 
      label: 'Keyboard Shortcuts', 
      onClick: toggleShortcuts,
      shortcut: '?'
    },
    { 
      icon: <HelpCircle size={16} aria-hidden="true" />, 
      label: 'Help & Support', 
      onClick: () => {
        console.log('Help clicked');
        closeMenu();
      },
      shortcut: 'H'
    },
    { 
      icon: <LogOut size={16} aria-hidden="true" />, 
      label: 'Sign out', 
      onClick: () => {
        onLogout();
        closeMenu();
      },
      shortcut: 'Q'
    },
  ];

  if (!user) return null;

  const userInitial = user.name.charAt(0).toUpperCase();

  return (
    <div className="relative" ref={menuRef}>
      <button
        ref={menuButtonRef}
        onClick={toggleMenu}
        className="flex items-center space-x-2 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 rounded-full"
        aria-label="User menu"
        aria-haspopup="true"
        aria-expanded={isOpen}
      >
        <div 
          className="h-8 w-8 rounded-full bg-gradient-to-r from-blue-500 to-blue-600 flex items-center justify-center text-white font-semibold"
          aria-hidden="true"
        >
          {userInitial}
        </div>
        <span className="hidden md:inline text-sm font-medium">{user.name}</span>
      </button>

      {isOpen && (
        <div 
          className={`absolute right-0 mt-2 w-64 rounded-md shadow-lg py-1 z-50 ${
            darkMode ? 'bg-gray-800 border border-gray-700' : 'bg-white border border-gray-200'
          }`}
          role="menu"
          aria-orientation="vertical"
          aria-labelledby="user-menu-button"
          tabIndex={-1}
        >
          <div className={`px-4 py-2 border-b ${darkMode ? 'border-gray-700' : 'border-gray-100'}`}>
            <p className="text-sm font-medium">{user.name}</p>
            <p className="text-xs text-gray-500 truncate">{user.email}</p>
          </div>
          
          <div className="py-1" role="none">
            {menuItems.map((item, index) => (
              <button
                key={item.label}
                ref={el => menuItemsRef.current[index] = el}
                onClick={item.onClick}
                onKeyDown={(e) => handleKeyDown(e, index)}
                className={`w-full text-left px-4 py-2 text-sm flex items-center justify-between ${
                  darkMode 
                    ? 'text-gray-200 hover:bg-gray-700 focus:bg-gray-700' 
                    : 'text-gray-700 hover:bg-gray-100 focus:bg-gray-100'
                }`}
                role="menuitem"
                tabIndex={-1}
              >
                <div className="flex items-center">
                  <span className="mr-3" aria-hidden="true">{item.icon}</span>
                  {item.label}
                </div>
                {item.shortcut && (
                  <span className="text-xs opacity-60">
                    {item.shortcut}
                  </span>
                )}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Keyboard Shortcuts Modal */}
      {showShortcuts && (
        <div 
          className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4"
          onClick={toggleShortcuts}
          role="dialog"
          aria-labelledby="keyboard-shortcuts-title"
        >
          <div 
            className={`relative rounded-lg shadow-xl max-w-md w-full max-h-[80vh] overflow-y-auto ${
              darkMode ? 'bg-gray-800' : 'bg-white'
            }`}
            onClick={e => e.stopPropagation()}
          >
            <div className="flex items-center justify-between p-4 border-b">
              <h2 
                id="keyboard-shortcuts-title" 
                className="text-lg font-semibold"
              >
                Keyboard Shortcuts
              </h2>
              <button
                onClick={toggleShortcuts}
                className="p-1 rounded-full hover:bg-opacity-20 hover:bg-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
                aria-label="Close"
              >
                <X size={20} />
              </button>
            </div>
            <div className="p-4">
              <div className="space-y-2">
                {keyboardShortcuts.map((shortcut, index) => (
                  <div key={index} className="flex items-center justify-between py-2">
                    <span className={`text-sm ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                      {shortcut.description}
                    </span>
                    <div className="flex space-x-1">
                      {shortcut.keys.map((key, i) => (
                        <kbd 
                          key={i}
                          className={`px-2 py-1 rounded text-xs font-mono ${
                            darkMode 
                              ? 'bg-gray-700 text-gray-200 border border-gray-600' 
                              : 'bg-gray-100 text-gray-800 border border-gray-300'
                          }`}
                        >
                          {key}
                        </kbd>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
            <div className={`p-4 border-t ${
              darkMode ? 'border-gray-700' : 'border-gray-200'
            } flex justify-end`}>
              <button
                onClick={toggleShortcuts}
                className={`px-4 py-2 rounded-md text-sm font-medium focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 ${
                  darkMode 
                    ? 'bg-blue-600 text-white hover:bg-blue-700' 
                    : 'bg-blue-500 text-white hover:bg-blue-600'
                }`}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default UserMenu;
