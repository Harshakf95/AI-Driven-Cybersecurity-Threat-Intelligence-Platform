# NetraVigil — AI‑Driven Cybersecurity Threat Intelligence Platform

NetraVigil is a modern, modular platform for collecting, analyzing, and visualizing cybersecurity threat intelligence. It features a React + Vite front‑end with Tailwind CSS and a context‑driven architecture designed to integrate with ML pipelines and external TI feeds.

## Key Features
- **Threat data collection and aggregation** from external feeds (e.g., VirusTotal, AlienVault OTX) — pluggable.
- **Machine learning–ready** architecture to integrate TensorFlow/scikit‑learn models.
- **Real‑time monitoring** dashboards and alerts.
- **Role‑aware UI** with authentication context and protected routes.
- **Visualization & reporting** with Chart.js, D3, and rich UI components.
- **Scalable deployment** targets (Docker, Kubernetes) planned.

## Tech Stack
- **Frontend**: React 18, TypeScript, Vite, Tailwind CSS
- **Routing**: React Router v6 (`createBrowserRouter` + `RouterProvider`)
- **Charts/Vis**: Chart.js, react-chartjs-2, D3
- **State/Contexts**: Custom React Contexts (`AuthContext`, `ThemeContext`, `ThreatContext`)
- **Icons**: lucide-react

> Backend, ML services, and DB are planned with FastAPI (Python), TensorFlow/scikit‑learn, and MongoDB. This repository currently contains the front‑end app.

## Project Structure
```
AI-Driven Cybersecurity Threat Intelligence Platform/
├─ public/
├─ src/
│  ├─ components/
│  │  ├─ layout/              # App shell (Header, Sidebar, Layout)
│  │  └─ ui/                  # Reusable UI (UserMenu, NotificationCenter, ...)
│  ├─ context/                # AuthContext, ThemeContext, ThreatContext
│  ├─ pages/                  # Dashboard, WebThreats, NetworkThreats, ...
│  ├─ App.tsx                 # Router configuration (RouterProvider)
│  ├─ main.tsx                # App bootstrap + ErrorBoundary
│  ├─ ErrorBoundary.tsx       # Friendly error UI
│  └─ index.css               # Tailwind & global styles
├─ .env                       # Environment variables (local, not committed)
├─ vite.config.ts             # Vite config
├─ tailwind.config.js         # Tailwind config
├─ package.json               # Scripts and dependencies
└─ README.md                  # This file
```

## Getting Started

### Prerequisites
- Node.js 18+ and npm

### Install
```
npm install
```

### Run (Development)
```
npm run dev
```
- The app runs at http://localhost:5173

### Build (Production)
```
npm run build
```
### Preview Production Build
```
npm run preview
```

### Lint
```
npm run lint
```

## Environment Variables
Create a `.env` (or use `.env.development`) at the project root. Example:
```
# App
VITE_APP_ENV=development

# Threat Intelligence APIs (planned integrations)
VITE_VIRUSTOTAL_API_KEY=
VITE_ALIENVAULT_OTX_API_KEY=
```
> Never commit real API keys to source control. Use environment variables or a secret manager.

## Routing & Auth
- The router is configured in `src/App.tsx` using `createBrowserRouter` and `RouterProvider`.
- Providers (`AuthProvider`, `ThemeProvider`, `ThreatProvider`) wrap all routes via a root route element.
- `AuthContext` exposes `isAuthenticated`, `isLoading`, `user`, `login()`, and `logout()`.
- `PrivateRoute` protects the main application shell (dashboard and nested pages).
- The NetraVigil logo in `src/components/layout/Header.tsx` links to `/` (Dashboard).

## Styling
- Tailwind CSS is preconfigured. Global styles are in `src/index.css`.

## Visualization
- Charts: Chart.js via `react-chartjs-2`.
- Data visualizations: D3 utilities for custom visual components.

## Error Handling
- `src/ErrorBoundary.tsx` shows a friendly error UI when an uncaught error occurs.

## Common Issues & Troubleshooting
- **useNavigate must be inside a Router**: Ensure contexts or components using `useNavigate` render under `RouterProvider`. In this app, providers are attached in the router tree (see `src/App.tsx`).
- **Port conflicts**: If `5173` is busy, Vite will suggest another port or you can specify one via CLI flags (e.g., `vite --port 5174`).

## Scripts Summary
- `npm run dev` — Start dev server
- `npm run build` — Production build
- `npm run preview` — Preview built app
- `npm run lint` — ESLint

## Roadmap
- Backend services with FastAPI, JWT auth, and MongoDB
- Threat ingestion workers and schedulers
- ML pipelines with scikit‑learn/TensorFlow
- Real‑time websockets for live alerts
- Docker images and Kubernetes manifests

## Security Notes
- Treat all TI keys and tokens as secrets.
- Use HTTPS for all API calls in production.
- Apply role‑based access controls on the backend.

## Contributing
- Fork, create a feature branch, submit a PR.
- Follow conventional commits and run `npm run lint` before pushing.

## License
Proprietary — All rights reserved. Contact the maintainers for licensing inquiries.
