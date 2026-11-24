# FileVow dashboard

React 18 + TypeScript (strict) + Vite, with React Router and TanStack Query.
The look follows the agreed design in `demo/` and the tokens in `design/`.

```powershell
npm install
npm run dev        # http://localhost:5173, proxies /api to the backend on 127.0.0.1:8443
npm run build      # production build in dist/ (served by `filevow serve`)
npm run typecheck
npm run lint
npm test
```

## Structure

```
src/
  api/          fetch client (CSRF + silent refresh), types, TanStack Query hooks
  auth/         session context and role checks
  components/   app shell, dialogs, command palette, diff view, toasts, icons
  hooks/        hotkeys, live WebSocket events, theme and density preferences
  pages/        Home, Review, Files, Folders, Runs, Audit, Settings, Login
  styles/       design tokens and app styles
  test/         Vitest + Testing Library tests
```

Security notes: the session lives in HttpOnly cookies (never in localStorage), every
state-changing request carries the CSRF token, and sensitive actions open a
"Confirm it's you" dialog that sends a fresh password and authenticator code.
