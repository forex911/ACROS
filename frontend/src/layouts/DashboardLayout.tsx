import React, { useState, useRef } from 'react';
import { Outlet, Link, useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import { motion } from 'framer-motion';
import { Loader2 } from 'lucide-react';
import { AnimatedActivity } from '../components/icons/AnimatedActivity';
import { AnimatedFileSearch } from '../components/icons/AnimatedFileSearch';
import { AnimatedShield } from '../components/icons/AnimatedShield';
import { AnimatedBriefcase } from '../components/icons/AnimatedBriefcase';
import { AnimatedTerminal } from '../components/icons/AnimatedTerminal';
import { AnimatedLogOut } from '../components/icons/AnimatedLogOut';
import { AnimatedSearch } from '../components/icons/AnimatedSearch';
import { AnimatedPlus } from '../components/icons/AnimatedPlus';
import { AnimatedMessage } from '../components/icons/AnimatedMessage';
import { AnimatedBell } from '../components/icons/AnimatedBell';
import api from '../api/client';
import { ProfilePanel } from '../components/ProfilePanel';

const MotionLink = motion(Link);

export const DashboardLayout: React.FC = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [isUploading, setIsUploading] = useState(false);
  const [isProfileOpen, setIsProfileOpen] = useState(false);
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
    { path: '/', label: 'Overview', icon: AnimatedActivity },
    { path: '/analysis/latest', label: 'Analysis', icon: AnimatedFileSearch },
    { path: '/attack-matrix', label: 'ATT&CK Matrix', icon: AnimatedShield },
    { path: '/workspace', label: 'Workspace', icon: AnimatedBriefcase },
    { path: '/observability', label: 'Observability', icon: AnimatedTerminal },
  ];

  return (
    <div className="flex min-h-screen bg-[#000000] text-[#ffffff] font-sans">
      {/* ── Sidebar ────────────────────────────────────────── */}
      <aside className="fixed top-0 left-0 w-[280px] h-screen border-r border-[#222222] flex flex-col pt-10 pb-6 shrink-0 bg-[#000000] z-40">
        {/* Brand */}
        <div className="px-8 mb-12 flex items-center gap-4">
          <img src="/acros.png" alt="ACROS Logo" className="w-8 h-8 object-contain" />
          <span className="font-heading font-bold text-lg tracking-widest uppercase">ACROS</span>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-4 space-y-2">
          {navItems.map((item) => {
            const isActive = location.pathname === item.path || (item.path !== '/' && location.pathname.startsWith(item.path));
            return (
              <MotionLink
                key={item.path}
                to={item.path}
                initial="rest"
                whileHover="hover"
                className={`flex items-center px-4 py-3.5 text-sm font-medium transition-all duration-200 uppercase tracking-widest ${
                  isActive
                    ? 'bg-[#ffffff] text-[#000000]'
                    : 'text-[#888888] hover:text-[#ffffff] hover:bg-[#111111]'
                }`}
              >
                <item.icon className={`w-[18px] h-[18px] mr-4 ${isActive ? 'text-[#000000]' : 'text-[#888888]'}`} />
                {item.label}
              </MotionLink>
            );
          })}
        </nav>

        {/* Logout */}
        <div className="px-4 mt-auto">
          <motion.button
            onClick={handleLogout}
            initial="rest"
            whileHover="hover"
            className="w-full flex items-center px-4 py-3.5 text-sm text-[#888888] hover:text-[#ffffff] hover:bg-[#111111] transition-all duration-200 font-medium uppercase tracking-widest"
          >
            <AnimatedLogOut className="w-[18px] h-[18px] mr-4" />
            Sign Out
          </motion.button>
        </div>
      </aside>

      {/* ── Main Area ─────────────────────────────────────── */}
      <div className="flex-1 flex flex-col min-h-screen ml-[280px] min-w-0">
        {/* Top Bar */}
        <header className="sticky top-0 z-50 h-[88px] border-b border-[#222222] flex items-center justify-between px-10 shrink-0 bg-[#000000]/80 backdrop-blur-md">
          <motion.div initial="rest" whileHover="hover" className="flex-1 max-w-md relative group">
            <AnimatedSearch className="w-5 h-5 absolute left-4 top-1/2 -translate-y-1/2 text-[#666666] group-hover:text-[#ffffff] transition-colors" />
            <input
              type="text"
              placeholder="SEARCH ANALYSES..."
              onKeyDown={(e) => {
                if (e.key === 'Enter' && e.currentTarget.value.trim()) {
                  navigate(`/workspace?q=${encodeURIComponent(e.currentTarget.value.trim())}`);
                }
              }}
              className="w-full pl-12 pr-4 py-3.5 bg-[#000000] border border-[#333333] text-sm text-[#ffffff] placeholder:text-[#666666] focus:border-[#ffffff] font-mono tracking-widest transition-all outline-none"
            />
          </motion.div>

          {/* Actions */}
          <div className="flex items-center gap-6">
            <input type="file" ref={fileInputRef} onChange={handleFileChange} className="hidden" />
            <motion.button
              onClick={handleUploadClick}
              disabled={isUploading}
              initial="rest"
              whileHover="hover"
              className={`flex items-center gap-3 px-6 py-3.5 font-heading font-bold text-sm uppercase tracking-widest transition-all border ${
                isUploading
                  ? 'bg-[#111111] text-[#666666] border-[#333333] cursor-not-allowed'
                  : 'bg-[#ffffff] text-[#000000] border-[#ffffff] hover:bg-[#000000] hover:text-[#ffffff]'
              }`}
            >
              {isUploading ? <Loader2 className="w-4 h-4 animate-spin" /> : <AnimatedPlus className="w-4 h-4" />}
              {isUploading ? 'UPLOADING...' : 'NEW SCAN'}
            </motion.button>

            <div className="flex items-center gap-2 border-l border-[#222222] pl-6">
              <motion.button
                onClick={() => alert('Messages feature coming soon!')}
                initial="rest" whileHover="hover"
                className="p-2.5 text-[#888888] hover:text-[#ffffff] transition-colors"
              >
                <AnimatedMessage className="w-5 h-5" />
              </motion.button>
              <motion.button
                onClick={() => alert('You have 2 new notifications.')}
                initial="rest" whileHover="hover"
                className="p-2.5 text-[#888888] hover:text-[#ffffff] transition-colors relative"
              >
                <AnimatedBell className="w-5 h-5" />
                <span className="absolute top-2.5 right-2.5 w-2 h-2 bg-[#ffffff] rounded-full border-2 border-[#000000]"></span>
              </motion.button>

              <div 
                onClick={() => setIsProfileOpen(true)}
                className="w-10 h-10 border border-[#444444] flex items-center justify-center text-[#ffffff] font-heading font-bold ml-4 cursor-pointer hover:bg-[#ffffff] hover:text-[#000000] transition-colors"
                title="Profile"
              >
                {user?.username.charAt(0).toUpperCase()}
              </div>
            </div>
          </div>
        </header>

        {/* Content */}
        <div className="flex-1 p-10 min-w-0 overflow-x-hidden">
          <Outlet />
        </div>

        {/* Profile Panel */}
        <ProfilePanel 
          isOpen={isProfileOpen} 
          onClose={() => setIsProfileOpen(false)}
          onLogout={() => { setIsProfileOpen(false); handleLogout(); }}
        />
      </div>
    </div>
  );
};
