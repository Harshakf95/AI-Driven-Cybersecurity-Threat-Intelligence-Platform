import React from 'react';
import { ThemeProvider } from './context/ThemeContext';
import { ThreatProvider } from './context/ThreatContext';
import { AuthProvider, useAuth } from './context/AuthContext';
import Layout from './components/layout/Layout';
import { createBrowserRouter, RouterProvider, Navigate, Outlet } from 'react-router-dom';
import Dashboard from './pages/Dashboard';
import WebThreats from './pages/WebThreats';
import NetworkThreats from './pages/NetworkThreats';
import Analytics from './pages/Analytics';
import Settings from './pages/Settings';
import Login from './pages/Login';
import Alerts from './pages/Alerts';
import { Loader2 } from 'lucide-react';

const PrivateRoute = ({ children }: { children: React.ReactNode }) => {
  const { isAuthenticated, isLoading } = useAuth();
  
  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-gray-900">
        <Loader2 className="w-12 h-12 text-blue-500 animate-spin" />
      </div>
    );
  }

  return isAuthenticated ? children : <Navigate to="/login" />;
};

const LayoutWrapper = () => {
  return (
    <Layout>
      <Outlet />
    </Layout>
  );
};

// Root provider element so that all routes are wrapped by app providers
const Providers: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <AuthProvider>
    <ThemeProvider>
      <ThreatProvider>
        {children}
      </ThreatProvider>
    </ThemeProvider>
  </AuthProvider>
);

function App() {
  const router = createBrowserRouter([
    {
      path: "/",
      element: (
        <Providers>
          <Outlet />
        </Providers>
      ),
      children: [
        {
          path: "/login",
          element: <Login />,
        },
        {
          path: "/",
          element: (
            <PrivateRoute>
              <LayoutWrapper />
            </PrivateRoute>
          ),
          children: [
            {
              path: "/",
              element: <Dashboard />,
            },
            {
              path: "/web-threats",
              element: <WebThreats />,
            },
            {
              path: "/network-threats",
              element: <NetworkThreats />,
            },
            {
              path: "/analytics",
              element: <Analytics />,
            },
            {
              path: "/alerts",
              element: <Alerts />,
            },
            {
              path: "/settings",
              element: <Settings />,
            },
          ],
        },
      ],
    },
    {
      path: "*",
      element: <Navigate to="/" replace />,
    },
  ]);

  return (
    <RouterProvider router={router} />
  );
}

export default App;