import { Navigate, Route, Routes } from "react-router-dom";
import { useWorkspace } from "./api/queries";
import { useAuth } from "./auth/AuthContext";
import { AppShell } from "./components/AppShell";
import { AuditPage } from "./pages/AuditPage";
import { FilesPage } from "./pages/FilesPage";
import { FoldersPage } from "./pages/FoldersPage";
import { HelpPage } from "./pages/HelpPage";
import { HomePage } from "./pages/HomePage";
import { LoginPage } from "./pages/LoginPage";
import { ReviewPage } from "./pages/ReviewPage";
import { RunsPage } from "./pages/RunsPage";
import { SetPassphrasePage } from "./pages/SetPassphrasePage";
import { SettingsPage } from "./pages/SettingsPage";

export function App() {
  const { user, loading } = useAuth();

  if (loading) return <div className="login-wrap"><span className="spinner" aria-label="Loading" /></div>;
  if (!user) return <LoginPage />;
  return <SignedInApp />;
}

function SignedInApp() {
  const { user } = useAuth();
  const workspace = useWorkspace();
  // E-mail-code accounts finish sign-up by choosing their passphrase (it creates the signing key).
  if (user?.is_cloud) {
    if (!workspace.data) return <div className="login-wrap"><span className="spinner" aria-label="Loading" /></div>;
    if (!workspace.data.has_signing_key) return <SetPassphrasePage />;
  }

  return (
    <AppShell>
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/review" element={<ReviewPage />} />
        <Route path="/review/:id" element={<ReviewPage />} />
        <Route path="/files" element={<FilesPage />} />
        <Route path="/folders" element={<FoldersPage />} />
        <Route path="/runs" element={<RunsPage />} />
        <Route path="/audit" element={<AuditPage />} />
        <Route path="/settings" element={<SettingsPage />} />
        <Route path="/help" element={<HelpPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AppShell>
  );
}
