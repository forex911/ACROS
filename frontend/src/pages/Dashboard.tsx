import React, { useRef, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useQuery, keepPreviousData } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import gsap from 'gsap';
import { useGSAP } from '@gsap/react';
import api from '../api/client';
import { StatCard } from '../components/dashboard/StatCard';
import { Activity, ShieldAlert, Cpu, Database, ChevronDown, Calendar, FileSearch } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';

gsap.registerPlugin(useGSAP);

const Dashboard: React.FC = () => {
  const container = useRef<HTMLDivElement>(null);
  const [timeframe, setTimeframe] = useState('1W');
  const navigate = useNavigate();

  const { data, isLoading, error, isFetching } = useQuery({
    queryKey: ['dashboardOverview', timeframe],
    queryFn: async () => {
      const res = await api.get(`/dashboard/overview?timeframe=${timeframe}`);
      return res.data;
    },
    refetchInterval: 5000,
    placeholderData: keepPreviousData,
  });

  useGSAP(() => {
    if (!isLoading && !error && container.current) {
      // Header animation
      gsap.fromTo(".gsap-header", 
        { opacity: 0, y: -20 },
        { opacity: 1, y: 0, duration: 0.8, ease: "power3.out" }
      );

      // Stat cards stagger
      gsap.fromTo(".gsap-card",
        { opacity: 0, y: 30, scale: 0.95 },
        { opacity: 1, y: 0, scale: 1, duration: 0.8, stagger: 0.1, ease: "back.out(1.2)", delay: 0.2 }
      );

      // Panels stagger
      gsap.fromTo(".gsap-panel",
        { opacity: 0, y: 40 },
        { opacity: 1, y: 0, duration: 1, stagger: 0.15, ease: "power3.out", delay: 0.4 }
      );
    }
  }, { dependencies: [isLoading, error], scope: container });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full text-[#ffffff] font-mono uppercase tracking-widest">
        <div className="w-6 h-6 border-2 border-[#333333] border-t-[#ffffff] rounded-full animate-spin mr-4" />
        LOADING DASHBOARD...
      </div>
    );
  }

  if (error) {
    return <div className="text-[#ffffff] p-10 border border-[#ffffff] font-mono">ERROR LOADING DASHBOARD DATA.</div>;
  }

  const {
    active_sandboxes = 0,
    total_threats = 0,
    stored_artifacts = 0,
    recent_activity = [],
    chart_data = []
  } = data || {};

  const mappedChartData = chart_data.map((d: any) => ({
    name: d.time,
    Scans: d.scans || 0,
    Threats: d.detections || 0
  }));

  const threatFeed = data?.threat_feed || [];

  return (
    <div ref={container} className="max-w-[1400px] mx-auto space-y-10">
      <div className="gsap-header flex items-center justify-between border-b border-[#333333] pb-6">
        <h2 className="text-3xl font-heading font-bold tracking-tighter uppercase">Overview</h2>
        <div className="text-sm font-mono text-[#888888] tracking-widest">SYSTEM_STATUS: ONLINE</div>
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="gsap-card"><StatCard title="Active Scans" value={active_sandboxes.toString()} icon={Cpu} trend={{ value: 12, isUp: true, color: 'emerald' }} /></div>
        <div className="gsap-card"><StatCard title="Threats Detected" value={total_threats.toString()} icon={ShieldAlert} trend={{ value: 5, isUp: false, color: 'emerald' }} /></div>
        <div className="gsap-card"><StatCard title="Stored Artifacts" value={stored_artifacts.toString()} icon={Database} trend={{ value: 100, isUp: true, color: 'emerald' }} /></div>
        <div className="gsap-card"><StatCard title="System Health" value="99.9%" icon={Activity} trend={{ value: 0.1, isUp: true, color: 'emerald' }} /></div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Chart */}
        <div className="gsap-panel lg:col-span-2 p-8 border border-[#333333] bg-[#000000] flex flex-col h-[520px]">
          <div className="flex justify-between items-start mb-10 shrink-0">
            <div>
              <h3 className="font-heading font-bold text-lg tracking-widest uppercase mb-2">Scan Volume</h3>
              <div className="flex items-center gap-6 text-sm font-mono text-[#888888]">
                <span>SCANS <strong className="text-[#ffffff] ml-2">{stored_artifacts}</strong></span>
                <span>THREATS <strong className="text-[#ffffff] ml-2">{total_threats}</strong></span>
              </div>
            </div>
            <div className="relative group">
              <select 
                value={timeframe} 
                onChange={(e) => setTimeframe(e.target.value)}
                className="appearance-none flex items-center gap-2 border border-[#333333] bg-[#000000] px-4 py-2 pr-8 font-mono text-xs text-[#ffffff] group-hover:bg-[#ffffff] group-hover:text-[#000000] transition-colors uppercase tracking-widest cursor-pointer outline-none"
              >
                <option value="1D">Daily</option>
                <option value="1W">Weekly</option>
                <option value="1M">Monthly</option>
                <option value="3M">Quarterly</option>
                <option value="ALL">All Time</option>
              </select>
              <ChevronDown className="w-4 h-4 absolute right-2 top-1/2 -translate-y-1/2 pointer-events-none group-hover:text-[#000000] text-[#ffffff]" />
            </div>
          </div>

          <div className="flex-1 w-full min-h-0" style={{ minWidth: 0 }}>
            <ResponsiveContainer width="100%" height="100%" minWidth={100}>
              <AreaChart data={mappedChartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorScans" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ffffff" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#ffffff" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="colorThreats" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#222222" />
                <XAxis dataKey="name" axisLine={false} tickLine={false} tick={{ fill: '#888888', fontSize: 12, fontFamily: 'JetBrains Mono' }} dy={10} minTickGap={20} />
                <YAxis axisLine={false} tickLine={false} tick={{ fill: '#888888', fontSize: 12, fontFamily: 'JetBrains Mono' }} dx={-10} />
                <Tooltip
                  cursor={{ stroke: '#333333', strokeWidth: 1, strokeDasharray: '4 4' }}
                  contentStyle={{ backgroundColor: '#000000', border: '1px solid #333333', color: '#ffffff', fontFamily: 'JetBrains Mono', fontSize: '12px' }}
                  itemStyle={{ fontWeight: 'bold' }}
                />
                <Legend iconType="circle" wrapperStyle={{ paddingTop: '20px', fontFamily: 'JetBrains Mono', fontSize: '12px' }} />
                <Area type="monotone" dataKey="Scans" stroke="#ffffff" strokeWidth={2} fillOpacity={1} fill="url(#colorScans)" isAnimationActive={true} animationDuration={800} />
                <Area type="monotone" dataKey="Threats" stroke="#ef4444" strokeWidth={2} fillOpacity={1} fill="url(#colorThreats)" isAnimationActive={true} animationDuration={800} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Threat Feed */}
        <div className="gsap-panel p-8 border border-[#333333] bg-[#000000] flex flex-col h-[520px]">
          <div className="flex justify-between items-center mb-8 shrink-0">
            <h3 className="font-heading font-bold text-lg tracking-widest uppercase">Live Threats</h3>
            <span className="text-xs font-mono text-[#888888] uppercase">Global Net</span>
          </div>

          <div className="flex items-baseline justify-between border-b border-[#333333] pb-6 mb-6 shrink-0">
            <span className={`text-6xl font-heading font-bold tracking-tighter ${total_threats > 0 ? 'text-red-500' : 'text-emerald-500'}`}>{total_threats}</span>
            <span className={`font-mono text-sm font-bold border px-3 py-1 uppercase ${total_threats > 0 ? 'border-red-500 text-red-500' : 'border-emerald-500 text-emerald-500'}`}>
              {total_threats > 0 ? 'Active' : 'Clear'}
            </span>
          </div>

          <div className="flex gap-2 text-xs font-mono font-bold text-[#666666] mb-8 border-b border-[#222222] pb-4 shrink-0">
            {['1D', '1W', '1M', '3M', 'ALL'].map(tf => (
              <span 
                key={tf}
                onClick={() => setTimeframe(tf)}
                className={`px-2 py-1 cursor-pointer transition-colors ${timeframe === tf ? 'text-[#000000] bg-[#ffffff]' : 'hover:text-[#ffffff]'}`}
              >
                {tf}
              </span>
            ))}
          </div>

          <div className="flex-1 overflow-y-auto custom-scrollbar pr-2 min-h-0" data-lenis-prevent>
            <div className="space-y-6">
              {threatFeed.length === 0 && (
                <div className="text-[#888888] text-xs font-mono text-center py-10 uppercase">No recent threats detected.</div>
              )}
              {threatFeed.map((threat: any, idx: number) => (
                <div key={idx} className="flex items-center justify-between group cursor-pointer hover:bg-[#111111] p-2 -mx-2 rounded transition-colors">
                  <div className="flex items-center gap-4">
                    <div className="w-10 h-10 border border-[#444444] group-hover:border-[#ffffff] transition-colors flex items-center justify-center font-heading font-bold text-[#ffffff] text-lg">
                      {threat.name.charAt(0)}
                    </div>
                    <div>
                      <div className="text-sm font-bold text-[#ffffff] uppercase tracking-wide">{threat.name}</div>
                      <div className="text-[11px] text-[#888888] font-mono mt-0.5">{threat.id}</div>
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="text-lg font-heading font-bold text-red-500">{threat.score}</div>
                    <div className="text-[11px] font-mono font-bold text-[#888888]">
                      {threat.trend}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Recent Investigations */}
      <div className="gsap-panel p-8 border border-[#333333] bg-[#000000]">
        <div className="flex justify-between items-center mb-6">
          <h3 className="font-heading font-bold text-lg tracking-widest uppercase">Recent Activity</h3>
          <Link to="/workspace" className="text-xs font-mono text-[#666666] tracking-widest uppercase hover:text-[#ffffff] transition-colors">View All</Link>
        </div>
        
        <div className="min-h-[420px] overflow-y-auto custom-scrollbar pr-2" data-lenis-prevent>
          <table className="w-full text-left">
            <thead className="text-[11px] text-[#888888] font-mono uppercase tracking-widest border-b border-[#333333]">
              <tr>
                <th className="pb-4 font-normal">Investigation</th>
                <th className="pb-4 font-normal">Date</th>
                <th className="pb-4 font-normal">Status</th>
                <th className="pb-4 font-normal">Artifact</th>
                <th className="pb-4 font-normal text-right">Risk Score</th>
              </tr>
            </thead>
            <tbody className="text-[#ffffff] font-mono text-sm">
              {recent_activity.length === 0 && (
                <tr><td colSpan={5} className="py-12 text-center text-[#666666] text-xs uppercase">No recent activity.</td></tr>
              )}
              {recent_activity.map((job: any) => (
                <tr 
                  key={job.id} 
                  className="border-b border-[#222222] hover:bg-[#111111] transition-colors cursor-pointer group"
                  onClick={() => navigate(`/analysis/${job.id}`)}
                >
                  <td className="py-5">
                    <div className="flex items-center gap-4">
                      <div className="w-8 h-8 border border-[#444444] group-hover:border-[#ffffff] transition-colors flex items-center justify-center text-[#ffffff]">
                        <FileSearch className="w-4 h-4" />
                      </div>
                      <span className="font-bold">{job.id.substring(0, 8)}</span>
                    </div>
                  </td>
                  <td className="py-5 text-[#888888] text-xs">{new Date(job.created_at).toLocaleDateString()} {new Date(job.created_at).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}</td>
                  <td className="py-5">
                    <span className={`px-3 py-1 text-[11px] font-bold uppercase tracking-wider border ${
                      job.status === 'analyzing' ? 'border-[#ffffff] text-[#000000] bg-[#ffffff] animate-pulse' :
                      job.status === 'completed' && job.risk_score >= 50 ? 'border-red-500 text-red-500 bg-transparent' :
                      job.status === 'completed' && job.risk_score < 50 ? 'border-emerald-500 text-emerald-500 bg-transparent' :
                      'border-[#ffffff] text-[#ffffff] bg-transparent'
                    }`}>
                      {job.status}
                    </span>
                  </td>
                  <td className="py-5 text-[#888888] font-mono text-xs">{job.filename.length > 20 ? job.filename.substring(0,20)+'...' : job.filename}</td>
                  <td className="py-5 text-right">
                    {job.risk_score > 0 ? (
                      <span className={`font-mono font-bold text-lg ${job.risk_score >= 70 ? 'text-red-500' : job.risk_score >= 40 ? 'text-yellow-500' : 'text-emerald-500'}`}>
                        {job.risk_score}
                      </span>
                    ) : (
                      <span className="text-[#666666] font-mono text-xs">—</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
