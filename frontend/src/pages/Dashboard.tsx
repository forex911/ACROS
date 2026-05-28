import React from 'react';
import { useQuery } from '@tanstack/react-query';
import api from '../api/client';
import { StatCard } from '../components/dashboard/StatCard';
import { Activity, ShieldAlert, Cpu, Database } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

const Dashboard: React.FC = () => {
  const { data, isLoading, error } = useQuery({
    queryKey: ['dashboardOverview'],
    queryFn: async () => {
      const res = await api.get('/dashboard/overview');
      return res.data;
    },
    refetchInterval: 5000, // Poll every 5s for live feel
  });

  if (isLoading) {
    return <div className="text-cyber-accent font-mono p-6">LOADING LIVE DATA...</div>;
  }
  if (error) {
    return <div className="text-cyber-alert font-mono p-6">ERROR LOADING DATA</div>;
  }

  const {
    active_sandboxes = 0,
    total_threats = 0,
    stored_artifacts = 0,
    recent_activity = [],
    chart_data = []
  } = data || {};
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard title="ACTIVE SANDBOXES" value={active_sandboxes.toString()} icon={Cpu} color="accent" />
        <StatCard title="THREATS DETECTED" value={total_threats.toString()} icon={ShieldAlert} color="alert" />
        <StatCard title="STORED ARTIFACTS" value={stored_artifacts.toString()} icon={Database} color="default" />
        <StatCard title="SYSTEM LOAD" value="LIVE" icon={Activity} color="green" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Chart Panel */}
        <div className="lg:col-span-2 cyber-panel p-6">
          <h3 className="text-gray-400 font-mono text-sm tracking-wider mb-6">DETECTION FREQUENCY (24H)</h3>
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chart_data}>
                <defs>
                  <linearGradient id="colorDetections" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ff7b72" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#ff7b72" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#30363d" vertical={false} />
                <XAxis dataKey="time" stroke="#8b949e" tick={{ fill: '#8b949e', fontSize: 12 }} />
                <YAxis stroke="#8b949e" tick={{ fill: '#8b949e', fontSize: 12 }} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#161b22', borderColor: '#30363d', color: '#c9d1d9' }}
                  itemStyle={{ color: '#ff7b72' }}
                />
                <Area type="monotone" dataKey="detections" stroke="#ff7b72" fillOpacity={1} fill="url(#colorDetections)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Active Jobs Panel */}
        <div className="cyber-panel p-6">
          <div className="flex justify-between items-center mb-6">
             <h3 className="text-gray-400 font-mono text-sm tracking-wider">RECENT ACTIVITY</h3>
             <span className="text-xs bg-cyber-accent/20 text-cyber-accent px-2 py-1 rounded font-mono border border-cyber-accent">LIVE</span>
          </div>
          <div className="space-y-4">
            {recent_activity.length === 0 && <div className="text-gray-500 text-xs font-mono">No recent activity.</div>}
            {recent_activity.map((job: any) => (
              <div key={job.id} className="p-3 border border-cyber-border rounded bg-cyber-dark flex flex-col space-y-2 hover:border-cyber-accent transition-colors cursor-pointer">
                <div className="flex justify-between items-center">
                  <span className="font-mono text-xs text-gray-300">{job.id.substring(0, 8)}...</span>
                  <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                    job.status === 'analyzing' ? 'text-cyber-accent border-cyber-accent bg-cyber-accent/10' :
                    job.status === 'completed' ? 'text-cyber-green border-cyber-green bg-cyber-green/10' :
                    job.status === 'failed' ? 'text-cyber-alert border-cyber-alert bg-cyber-alert/10' :
                    'text-gray-400 border-gray-500 bg-gray-800'
                  }`}>
                    {job.status.toUpperCase()}
                  </span>
                </div>
                <div className="font-mono text-[10px] text-gray-500 truncate">{job.filename}</div>
                <div className="text-right text-[10px] text-gray-500">{new Date(job.created_at).toLocaleTimeString()}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
