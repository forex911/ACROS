import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './hooks/useAuth';
import { ProtectedRoute } from './components/ProtectedRoute';
import { Login } from './pages/Login';
import { DashboardLayout } from './layouts/DashboardLayout';

// Lazy load pages for performance
const Dashboard = React.lazy(() => import('./pages/Dashboard'));
const AnalysisDetail = React.lazy(() => import('./pages/AnalysisDetail'));
const Observability = React.lazy(() => import('./pages/Observability'));
const AttackDashboard = React.lazy(() => import('./pages/AttackDashboard'));
const Workspace = React.lazy(() => import('./pages/Workspace'));

const App: React.FC = () => {
  return (
    <AuthProvider>
      <BrowserRouter>
        <React.Suspense fallback={
          <div className="h-screen flex items-center justify-center bg-[#f4f6f8] text-gray-600">
            <div className="flex flex-col items-center gap-4">
              <div className="w-8 h-8 border-2 border-gray-300 border-t-green-500 rounded-full animate-spin" />
              <span className="tracking-wide text-sm font-medium">Loading...</span>
            </div>
          </div>
        }>
          <Routes>
            <Route path="/login" element={<Login />} />

            {/* Protected SOC Routes — DashboardLayout stays mounted */}
            <Route path="/" element={<ProtectedRoute><DashboardLayout /></ProtectedRoute>}>
              <Route index element={<Dashboard />} />
              <Route path="analysis/:jobId" element={<AnalysisDetail />} />
              <Route path="observability" element={<Observability />} />
              <Route path="attack-matrix" element={<AttackDashboard />} />
              <Route path="workspace" element={<Workspace />} />
            </Route>

            {/* Fallback */}
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </React.Suspense>
      </BrowserRouter>
    </AuthProvider>
  );
};

export default App;

