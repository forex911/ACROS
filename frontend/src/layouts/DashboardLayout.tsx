import React, { useState, useRef } from 'react';
import { Outlet, Link, useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import { Shield, Activity, FileSearch, LogOut, Terminal, Briefcase, Search, Plus, Bell, MessageSquare, Loader2 } from 'lucide-react';
import api from '../api/client';

export const DashboardLayout: React.FC = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [isUploading, setIsUploading] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  const handleUploadClick = () => {
    fileInputRef.current?.click();
  };

  const handleFileChange = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    setIsUploading(true);
    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await api.post('/upload', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });
      if (response.data.file_id) {
        navigate(`/analysis/${response.data.file_id}`);
      }
    } catch (error) {
      console.error('Upload failed', error);
      alert('Upload failed. Please try again.');
    } finally {
      setIsUploading(false);
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  const navItems = [
    { path: '/', label: 'Overview', icon: Activity },
    { path: '/analysis/latest', label: 'Analysis', icon: FileSearch },
    { path: '/attack-matrix', label: 'ATT&CK Matrix', icon: Shield },
    { path: '/workspace', label: 'Workspace', icon: Briefcase },
    { path: '/observability', label: 'Observability', icon: Terminal },
  ];

  return (
    <div className="flex h-screen bg-[#f4f6f8] text-gray-900 overflow-hidden font-sans">
      {/* Sidebar — always static, never re-mounts */}
      <aside className="w-64 bg-[#f4f6f8] flex flex-col pt-8 pb-4">
        <div className="px-8 mb-10 flex items-center">
          <div className="bg-gray-900 text-white p-1.5 rounded-lg mr-3">
            <Shield className="w-5 h-5" />
          </div>
          <span className="font-bold text-xl tracking-tight text-gray-900">SENTINEL</span>
        </div>
        
        <nav className="flex-1 px-4 space-y-1">
          {navItems.map((item) => {
            const isActive = location.pathname === item.path || (item.path !== '/' && location.pathname.startsWith(item.path));
            return (
              <Link
                key={item.path}
                to={item.path}
                className={`flex items-center px-4 py-3 rounded-2xl text-sm font-medium transition-all duration-200 ${
                  isActive 
                    ? 'bg-[#c5f37d] text-gray-900 shadow-sm' 
                    : 'text-gray-500 hover:text-gray-900 hover:bg-white/60'
                }`}
              >
                <item.icon className={`w-5 h-5 mr-3 transition-colors duration-200 ${isActive ? 'text-gray-900' : 'text-gray-400'}`} />
                {item.label}
              </Link>
            )
          })}
        </nav>

        <div className="px-4 mt-auto">
          <button
            onClick={handleLogout}
            className="w-full flex items-center px-4 py-3 text-sm text-gray-500 hover:text-red-500 hover:bg-red-50 rounded-2xl transition-all duration-200 font-medium group"
          >
            <LogOut className="w-5 h-5 mr-3 text-gray-400 group-hover:text-red-500 transition-colors" />
            Sign Out
          </button>
        </div>
      </aside>

      {/* Main Content Container */}
      <div className="flex-1 flex flex-col h-screen overflow-hidden p-4 pl-0">
        <main className="flex-1 flex flex-col bg-white rounded-3xl shadow-[0_4px_24px_rgba(0,0,0,0.02)] overflow-hidden border border-gray-100">
          {/* Header — always static */}
          <header className="h-20 bg-white flex items-center justify-between px-8 z-10 relative shrink-0">
            {/* Search Bar */}
            <div className="flex-1 max-w-md relative">
              <Search className="w-5 h-5 absolute left-4 top-1/2 transform -translate-y-1/2 text-gray-400" />
              <input 
                type="text" 
                placeholder="Search" 
                className="w-full pl-11 pr-4 py-2.5 bg-gray-50 border border-gray-100 rounded-full text-sm focus:outline-none focus:ring-2 focus:ring-[#c5f37d] focus:bg-white transition-all"
              />
            </div>

            {/* Right Header Actions */}
            <div className="flex items-center space-x-4">
               {/* Hidden file input for New Scan */}
               <input 
                 type="file" 
                 ref={fileInputRef} 
                 onChange={handleFileChange} 
                 className="hidden" 
               />
               <button 
                 onClick={handleUploadClick}
                 disabled={isUploading}
                 className={`flex items-center gap-2 px-5 py-2.5 rounded-full font-medium text-sm transition-all ${
                   isUploading 
                     ? 'bg-gray-100 text-gray-400 cursor-not-allowed' 
                     : 'bg-[#c5f37d] text-gray-900 hover:shadow-lg hover:-translate-y-0.5'
                 }`}
               >
                 {isUploading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
                 {isUploading ? 'Uploading...' : 'New Scan'}
               </button>
               
               <button 
                 onClick={() => alert('Messages feature coming soon!')}
                 className="p-2.5 rounded-full bg-gray-50 text-gray-600 hover:bg-gray-100 transition-colors"
               >
                 <MessageSquare className="w-5 h-5" />
               </button>
               <button 
                 onClick={() => alert('You have 2 new notifications.')}
                 className="p-2.5 rounded-full bg-gray-50 text-gray-600 hover:bg-gray-100 transition-colors relative"
               >
                 <Bell className="w-5 h-5" />
                 <span className="absolute top-2 right-2 w-2 h-2 bg-red-500 rounded-full border-2 border-white"></span>
               </button>
               
               <div className="w-10 h-10 rounded-full bg-gray-900 flex items-center justify-center text-white font-medium shadow-sm ml-2 cursor-pointer hover:bg-gray-800 transition-colors" title="Profile Settings">
                  {user?.username.charAt(0).toUpperCase()}
               </div>
            </div>
          </header>
          
          {/* Content area — each page handles its own animation */}
          <div className="flex-1 overflow-auto bg-white p-6">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
};

