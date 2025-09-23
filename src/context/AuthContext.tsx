import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { useNavigate } from 'react-router-dom';

interface AuthContextType {
  isAuthenticated: boolean;
  isLoading: boolean;
  user: {
    name: string;
    email: string;
    role: string;
  } | null;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType>({
  isAuthenticated: false,
  isLoading: true,
  user: null,
  login: async () => {},
  logout: () => {}
});

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<{ name: string; email: string; role: string } | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    // Auto-login for development
    if (import.meta.env.VITE_APP_ENV === 'development') {
      console.log('Development mode: Auto-login enabled');
      localStorage.setItem('isAuthenticated', 'true');
      setUser({
        name: 'Admin',
        email: 'admin@nethravigil.com',
        role: 'Administrator'
      });
      setIsLoading(false);
      return;
    }

    // Normal authentication check for production
    const isAuthenticated = localStorage.getItem('isAuthenticated') === 'true';
    if (isAuthenticated) {
      // In a real app, you would fetch user data from your API
      setUser({
        name: 'Admin',
        email: 'admin@nethravigil.com',
        role: 'Administrator'
      });
    }
    setIsLoading(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const login = async (username: string, password: string) => {
    // In a real app, this would be an API call to your backend
    if (username === 'admin' && password === 'karthik123') {
      localStorage.setItem('isAuthenticated', 'true');
      setUser({
        name: 'Admin',
        email: 'admin@nethravigil.com',
        role: 'Administrator'
      });
      navigate('/');
    } else {
      throw new Error('Invalid username or password');
    }
  };

  const logout = () => {
    localStorage.removeItem('isAuthenticated');
    setUser(null);
    navigate('/login');
  };

  return (
    <AuthContext.Provider
      value={{
        isAuthenticated: !!user,
        isLoading,
        user,
        login,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => useContext(AuthContext);
