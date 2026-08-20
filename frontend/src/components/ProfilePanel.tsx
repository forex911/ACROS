import React, { useEffect, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { X, Shield, ShieldAlert, Cpu, CheckCircle, Key, Clock, User, Copy, ChevronRight, LogOut, Share2 } from 'lucide-react';
import api from '../api/client';

interface ProfilePanelProps {
  isOpen: boolean;
  onClose: () => void;
  onLogout: () => void;
}

export const ProfilePanel: React.FC<ProfilePanelProps> = ({ isOpen, onClose, onLogout }) => {
  const panelRef = useRef<HTMLDivElement>(null);

  const { data: profile, isLoading } = useQuery({
    queryKey: ['profile'],
    queryFn: async () => {
      const res = await api.get('/auth/profile');
      return res.data;
    },
    enabled: isOpen,
  });

  
  const { data: myJobs, refetch: refetchJobs } = useQuery({
    queryKey: ['myJobs'],
    queryFn: async () => {
      const res = await api.get('/auth/jobs/mine');
      return res.data;
    },
    enabled: isOpen,
  });

  const [shareInput, setShareInput] = useState<{ [key: string]: string }>({});
  
  const handleShare = async (jobId: string) => {
    const username = shareInput[jobId];
    if (!username) return;
    try {
      await api.post(`/auth/jobs/${jobId}/share`, { username });
      setShareInput(prev => ({ ...prev, [jobId]: '' }));
      refetchJobs();
    } catch (e) {
      console.error('Share failed', e);
      alert('Failed to share job. Check username or permissions.');
    }
  };

  // Close on outside click
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (panelRef.current && !panelRef.current.contains(e.target as Node)) {
        onClose();
      }
    };
    if (isOpen) {
      // Delay to prevent the opening click from immediately closing
      setTimeout(() => document.addEventListener('mousedown', handleClickOutside), 50);
    }
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [isOpen, onClose]);

  // Close on Escape
  useEffect(() => {
    const handleEsc = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    if (isOpen) document.addEventListener('keydown', handleEsc);
    return () => document.removeEventListener('keydown', handleEsc);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const stats = profile?.stats || {};
  const username = profile?.username || '...';
  const roles = profile?.roles || [];
  const createdAt = profile?.created_at;
  const apiKeys = profile?.api_keys || [];

  const accountAge = createdAt ? (() => {
    const diff = Date.now() - new Date(createdAt).getTime();
    const days = Math.floor(diff / (1000 * 60 * 60 * 24));
    if (days < 1) return 'Today';
    if (days === 1) return '1 day';
    if (days < 30) return `${days} days`;
    const months = Math.floor(days / 30);
    return months === 1 ? '1 month' : `${months} months`;
  })() : '—';

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  return (
    <>
      {/* Backdrop */}
      <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-[60] transition-opacity" />

      {/* Panel */}
      <div
        ref={panelRef}
        className="fixed top-0 right-0 w-[420px] h-screen bg-[#000000] border-l border-[#222222] z-[70] flex flex-col overflow-x-hidden"
        style={{ animation: 'slideInRight 0.3s cubic-bezier(0.16, 1, 0.3, 1)' }}
      >
        {/* Header */}
        <div className="px-8 pt-8 pb-6 border-b border-[#222222] shrink-0">
          <div className="flex items-center justify-between mb-8">
            <span className="text-[10px] font-mono font-bold text-[#666666] uppercase tracking-[0.2em]">Operator Profile</span>
            <button
              onClick={onClose}
              className="w-8 h-8 flex items-center justify-center border border-[#333333] text-[#888888] hover:text-[#ffffff] hover:border-[#ffffff] transition-all"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Avatar + Identity */}
          <div className="flex items-center gap-5">
            <div className="w-16 h-16 border-2 border-[#ffffff] flex items-center justify-center text-2xl font-heading font-black text-[#ffffff] bg-[#111111] shrink-0">
              {username.charAt(0).toUpperCase()}
            </div>
            <div className="min-w-0">
              <h2 className="text-xl font-heading font-black tracking-tight uppercase text-[#ffffff] truncate">{username}</h2>
              <div className="flex items-center gap-2 mt-1.5">
                {roles.map((role: string) => (
                  <span
                    key={role}
                    className={`text-[9px] font-mono font-bold uppercase tracking-[0.15em] px-2 py-0.5 border ${
                      role === 'admin'
                        ? 'border-[#ffffff] text-[#000000] bg-[#ffffff]'
                        : 'border-[#444444] text-[#888888]'
                    }`}
                  >
                    {role}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Scrollable Content */}
        <div className="flex-1 min-h-0 overflow-y-auto custom-scrollbar" data-lenis-prevent>
          {isLoading ? (
            <div className="flex items-center justify-center py-20">
              <div className="w-5 h-5 border-2 border-[#333333] border-t-[#ffffff] rounded-full animate-spin mr-3" />
              <span className="text-xs font-mono text-[#888888] uppercase tracking-widest">Loading...</span>
            </div>
          ) : (
            <div className="px-8 py-6 space-y-8">
              {/* Scan Statistics */}
              <div>
                <h3 className="text-[10px] font-mono font-bold text-[#666666] uppercase tracking-[0.2em] mb-4">Scan Statistics</h3>
                <div className="grid grid-cols-2 gap-3">
                  <StatTile icon={Cpu} label="Total Scans" value={stats.total_scans ?? 0} />
                  <StatTile icon={ShieldAlert} label="Threats Found" value={stats.threats_found ?? 0} accent="red" />
                  <StatTile icon={CheckCircle} label="Completed" value={stats.completed_scans ?? 0} accent="green" />
                  <StatTile icon={Clock} label="In Progress" value={stats.pending_scans ?? 0} accent="amber" />
                </div>
              </div>

              {/* Account Info */}
              <div>
                <h3 className="text-[10px] font-mono font-bold text-[#666666] uppercase tracking-[0.2em] mb-4">Account</h3>
                <div className="border border-[#222222] divide-y divide-[#222222]">
                  <InfoRow label="Username" value={username} />
                  <InfoRow label="Role" value={roles.join(', ')} />
                  <InfoRow label="Member For" value={accountAge} />
                  <InfoRow label="Created" value={createdAt ? new Date(createdAt).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' }) : '—'} />
                </div>
              </div>

              
              {/* My Scans & Sharing */}
              <div>
                <h3 className="text-[10px] font-mono font-bold text-[#666666] uppercase tracking-[0.2em] mb-4">My Scans & Sharing</h3>
                <div className="border border-[#222222] divide-y divide-[#222222] bg-[#080808]">
                  {(!myJobs || myJobs.length === 0) ? (
                    <div className="px-4 py-6 text-center text-xs font-mono text-[#666666]">No scans found</div>
                  ) : (
                    myJobs.map((job: any) => (
                      <div key={job.job_id} className="p-4 space-y-3">
                        <div className="flex justify-between items-start">
                          <div className="min-w-0">
                            <div className="text-xs font-mono text-[#ffffff] font-bold truncate">{job.filename}</div>
                            <div className="text-[10px] font-mono text-[#666666] mt-1">{new Date(job.created_at).toLocaleDateString()} &bull; {job.status}</div>
                          </div>
                        </div>
                        
                        {/* Shared With List */}
                        {job.shared_with && job.shared_with.length > 0 && (
                          <div className="flex flex-wrap gap-2">
                            {job.shared_with.map((u: string) => (
                              <span key={u} className="text-[9px] font-mono bg-[#222222] text-[#aaaaaa] px-1.5 py-0.5 rounded-sm flex items-center gap-1">
                                <User className="w-3 h-3" /> {u}
                              </span>
                            ))}
                          </div>
                        )}
                        
                        {/* Share Input */}
                        <div className="flex gap-2">
                          <input 
                            type="text" 
                            placeholder="Username to share with..." 
                            value={shareInput[job.job_id] || ''}
                            onChange={(e) => setShareInput(prev => ({ ...prev, [job.job_id]: e.target.value }))}
                            className="flex-1 bg-[#000000] border border-[#333333] px-3 py-1.5 text-xs font-mono text-[#ffffff] placeholder:text-[#444444] focus:border-[#ffffff] transition-colors"
                          />
                          <button 
                            onClick={() => handleShare(job.job_id)}
                            disabled={!shareInput[job.job_id]}
                            className="bg-[#222222] hover:bg-[#333333] text-[#ffffff] px-3 py-1.5 text-[10px] font-mono font-bold uppercase tracking-widest disabled:opacity-50 transition-colors flex items-center gap-2"
                          >
                            <Share2 className="w-3 h-3" /> Share
                          </button>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>

              {/* API Keys */}
              <div>
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-[10px] font-mono font-bold text-[#666666] uppercase tracking-[0.2em]">API Keys</h3>
                  <span className="text-[10px] font-mono text-[#444444]">{apiKeys.length} active</span>
                </div>

                {apiKeys.length === 0 ? (
                  <div className="border border-dashed border-[#333333] py-8 flex flex-col items-center justify-center">
                    <Key className="w-5 h-5 text-[#444444] mb-3" />
                    <span className="text-xs font-mono text-[#666666] uppercase tracking-widest">No API Keys</span>
                    <span className="text-[10px] font-mono text-[#444444] mt-1">Requires admin role</span>
                  </div>
                ) : (
                  <div className="space-y-2">
                    {apiKeys.map((k: any, i: number) => (
                      <div key={i} className="flex items-center justify-between px-4 py-3 border border-[#222222] bg-[#080808] group hover:border-[#444444] transition-colors">
                        <div className="flex items-center gap-3 min-w-0">
                          <Key className="w-3.5 h-3.5 text-[#666666] shrink-0" />
                          <span className="text-xs font-mono text-[#ffffff] truncate">{k.prefix}</span>
                        </div>
                        <button
                          onClick={() => copyToClipboard(k.prefix)}
                          className="p-1 text-[#444444] hover:text-[#ffffff] transition-colors opacity-0 group-hover:opacity-100"
                          title="Copy prefix"
                        >
                          <Copy className="w-3 h-3" />
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Threat Detection Rate */}
              <div>
                <h3 className="text-[10px] font-mono font-bold text-[#666666] uppercase tracking-[0.2em] mb-4">Detection Rate</h3>
                <div className="border border-[#222222] p-5">
                  <div className="flex items-end justify-between mb-3">
                    <span className="text-3xl font-heading font-black tracking-tighter text-[#ffffff]">
                      {stats.total_scans > 0
                        ? ((stats.threats_found / stats.total_scans) * 100).toFixed(1)
                        : '0.0'}%
                    </span>
                    <span className="text-[10px] font-mono text-[#666666] uppercase">of total scans</span>
                  </div>
                  <div className="w-full h-1.5 bg-[#222222] overflow-hidden">
                    <div
                      className="h-full bg-[#ffffff] transition-all duration-700"
                      style={{
                        width: stats.total_scans > 0
                          ? `${Math.min((stats.threats_found / stats.total_scans) * 100, 100)}%`
                          : '0%',
                      }}
                    />
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Footer Actions */}
        <div className="px-8 py-6 border-t border-[#222222] space-y-3">
          <button
            onClick={onLogout}
            className="w-full flex items-center justify-center gap-3 px-4 py-3.5 border border-[#333333] text-[#888888] hover:border-[#ffffff] hover:text-[#ffffff] transition-all font-mono text-xs uppercase tracking-widest"
          >
            <LogOut className="w-4 h-4" />
            Sign Out
          </button>
        </div>
      </div>

      <style>{`
        @keyframes slideInRight {
          from { transform: translateX(100%); opacity: 0; }
          to { transform: translateX(0); opacity: 1; }
        }
      `}</style>
    </>
  );
};


/* ── Sub-components ──────────────────────────────────────────── */

const StatTile: React.FC<{
  icon: React.FC<any>;
  label: string;
  value: number;
  accent?: 'red' | 'green' | 'amber';
}> = ({ icon: Icon, label, value, accent }) => {
  const accentColor =
    accent === 'red' ? 'text-red-500' :
    accent === 'green' ? 'text-emerald-500' :
    accent === 'amber' ? 'text-amber-500' :
    'text-[#ffffff]';

  return (
    <div className="border border-[#222222] p-4 group hover:border-[#444444] transition-colors">
      <div className="flex items-center gap-2 mb-3">
        <Icon className="w-3.5 h-3.5 text-[#666666]" />
        <span className="text-[9px] font-mono font-bold text-[#666666] uppercase tracking-[0.15em]">{label}</span>
      </div>
      <span className={`text-2xl font-heading font-black tracking-tighter ${accentColor}`}>{value}</span>
    </div>
  );
};

const InfoRow: React.FC<{ label: string; value: string }> = ({ label, value }) => (
  <div className="flex items-center justify-between px-4 py-3">
    <span className="text-[10px] font-mono font-bold text-[#666666] uppercase tracking-widest">{label}</span>
    <span className="text-xs font-mono text-[#ffffff]">{value}</span>
  </div>
);
