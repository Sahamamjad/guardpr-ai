import { Navigate, Route, Routes } from 'react-router-dom'
import { Layout } from './components/Layout'
import { AuditLogPage } from './pages/AuditLogPage'
import { FindingDetailPage } from './pages/FindingDetailPage'
import { LoginPage } from './pages/LoginPage'
import { ReposPage } from './pages/ReposPage'
import { ScanDetailPage } from './pages/ScanDetailPage'
import { SettingsPage } from './pages/SettingsPage'

function PrivateRoute({ children }: { children: JSX.Element }) {
  const token = localStorage.getItem('guardpr_token')
  return token ? children : <Navigate to="/login" replace />
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        path="/"
        element={
          <PrivateRoute>
            <Layout />
          </PrivateRoute>
        }
      >
        <Route index element={<ReposPage />} />
        <Route path="scans/:scanId" element={<ScanDetailPage />} />
        <Route path="findings/:findingId" element={<FindingDetailPage />} />
        <Route path="repos/:repoId/settings" element={<SettingsPage />} />
        <Route path="audit" element={<AuditLogPage />} />
      </Route>
    </Routes>
  )
}
