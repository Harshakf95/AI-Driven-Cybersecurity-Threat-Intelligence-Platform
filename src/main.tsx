import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { ErrorBoundary } from './ErrorBoundary';
import App from './App';
import './index.css';

console.log('Application starting...');
console.log('Environment:', import.meta.env.MODE);

console.log('Starting application...');

const rootElement = document.getElementById('root');

if (!rootElement) {
  throw new Error('Root element not found');
}

const root = createRoot(rootElement);

try {
  console.log('Rendering application...');
  root.render(
    <StrictMode>
      <ErrorBoundary>
        <App />
      </ErrorBoundary>
    </StrictMode>
  );
  console.log('Application rendered successfully');
} catch (error) {
  console.error('Fatal error rendering application:', error);
}

console.log('Application rendered');
