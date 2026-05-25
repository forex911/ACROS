import React from 'react';
import { Outlet, Link, useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import { Shield, Activity, FileSearch, Settings, LogOut, Terminal, Briefcase } from 'lucide-react';

export const DashboardLayout: React.FC = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  const navItems = [
    { path: '/', label: 'OVERVIEW', icon: Activity },
    { path: '/analysis/latest', label: 'ANALYSIS', icon: FileSearch },
    { path: '/attack-matrix', label: 'ATT&CK MATRIX', icon: Shield },
    { path: '/workspace', label: 'SOC WORKSPACE', icon: Briefcase },
    { path: '/observability', label: 'OBSERVABILITY', icon: Terminal },
  ];

  return (
    <div className="flex h-screen bg-cyber-dark text-gray-200 overflow-hidden font-sans">
      {/* Sidebar */}
      <aside className="w-64 bg-cyber-panel border-r border-cyber-border flex flex-col">
        <div className="h-16 flex items-center px-6 border-b border-cyber-border">
          <Shield className="w-6 h-6 text-cyber-accent mr-3" />
          <span className="font-bold font-mono tracking-wider text-lg">SENTINEL_AI</span>
        </div>
        
        <nav className="flex-1 py-6 px-4 space-y-2">
          {navItems.map((item) => {
            const isActive = location.pathname === item.path || (item.path !== '/' && location.pathname.startsWith(item.path));
            return (
              <Link
                key={item.path}
                to={item.path}
                className={`flex items-center px-4 py-3 rounded font-mono text-sm transition-colors ${
                  isActive 
                    ? 'bg-cyber-accent bg-opacity-10 text-cyber-accent border-l-2 border-cyber-accent' 
                    : 'text-gray-400 hover:bg-gray-800 hover:text-gray-200'
                }`}
              >
                <item.icon className="w-5 h-5 mr-3" />
                {item.label}
              </Link>
            )
          })}
        </nav>

        <div className="p-4 border-t border-cyber-border">
          <div className="flex items-center justify-between px-2 py-2 mb-2">
            <div className="flex items-center">
              <div className="w-8 h-8 rounded bg-gray-800 flex items-center justify-center border border-gray-700 mr-3">
                <span className="font-mono text-xs text-cyber-green">{user?.username.charAt(0).toUpperCase()}</span>
              </div>
              <div className="flex flex-col">
                <span className="text-sm font-bold leading-tight">{user?.username}</span>
                <span className="text-xs text-cyber-accent font-mono">[{user?.roles[0] || 'OP'}]</span>
              </div>
            </div>
          </div>
          <button
            onClick={handleLogout}
            className="w-full flex items-center px-4 py-2 text-sm text-cyber-alert hover:bg-cyber-alert hover:bg-opacity-10 rounded transition-colors font-mono"
          >
            <LogOut className="w-4 h-4 mr-3" />
            DISCONNECT
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 flex flex-col h-screen overflow-hidden">
        <header className="h-16 bg-cyber-panel border-b border-cyber-border flex items-center justify-between px-8">
          <h1 className="text-xl font-bold font-mono tracking-wide text-gray-100">
            {navItems.find(i => location.pathname === i.path || (i.path !== '/' && location.pathname.startsWith(i.path)))?.label || 'DASHBOARD'}
          </h1>
          <div className="flex items-center space-x-4">
             <div className="flex items-center text-xs font-mono">
               <span className="w-2 h-2 rounded-full bg-cyber-green mr-2 animate-pulse"></span>
               SYS_ONLINE
             </div>
          </div>
        </header>
        <div className="flex-1 overflow-auto p-8 bg-cyber-dark">
          <Outlet />
        </div>
      </main>
    </div>
  );
};
