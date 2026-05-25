import React from 'react';
import { StatCard } from '../components/dashboard/StatCard';
import { Activity, ShieldAlert, Cpu, Database } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

const mockChartData = [
  { time: '00:00', detections: 12 },
  { time: '04:00', detections: 19 },
  { time: '08:00', detections: 3 },
  { time: '12:00', detections: 45 },
  { time: '16:00', detections: 22 },
  { time: '20:00', detections: 14 },
  { time: '24:00', detections: 31 },
];

const mockJobs = [
  { id: 'job-9a8f2', status: 'running', hash: 'e3b0c44298fc1c149afbf4c8996fb924', time: '2 min ago' },
  { id: 'job-1b7c9', status: 'completed', hash: 'd41d8cd98f00b204e9800998ecf8427e', time: '15 min ago' },
  { id: 'job-5f2a1', status: 'failed', hash: '098f6bcd4621d373cade4e832627b4f6', time: '1 hr ago' },
];

const Dashboard: React.FC = () => {
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard title="ACTIVE SANDBOXES" value="8" icon={Cpu} color="accent" />
        <StatCard title="THREATS DETECTED" value="1,204" icon={ShieldAlert} trend={{ value: 12, isUp: true }} color="alert" />
        <StatCard title="STORED ARTIFACTS" value="8,942" icon={Database} color="default" />
        <StatCard title="SYSTEM LOAD" value="42%" icon={Activity} trend={{ value: 5, isUp: false }} color="green" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Chart Panel */}
        <div className="lg:col-span-2 cyber-panel p-6">
          <h3 className="text-gray-400 font-mono text-sm tracking-wider mb-6">DETECTION FREQUENCY (24H)</h3>
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={mockChartData}>
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
             <span className="text-xs bg-cyber-accent bg-opacity-20 text-cyber-accent px-2 py-1 rounded font-mono border border-cyber-accent">LIVE</span>
          </div>
          <div className="space-y-4">
            {mockJobs.map(job => (
              <div key={job.id} className="p-3 border border-cyber-border rounded bg-cyber-dark flex flex-col space-y-2 hover:border-cyber-accent transition-colors cursor-pointer">
                <div className="flex justify-between items-center">
                  <span className="font-mono text-xs text-gray-300">{job.id}</span>
                  <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                    job.status === 'running' ? 'text-cyber-accent border-cyber-accent bg-cyber-accent bg-opacity-10' :
                    job.status === 'completed' ? 'text-cyber-green border-cyber-green bg-cyber-green bg-opacity-10' :
                    'text-cyber-alert border-cyber-alert bg-cyber-alert bg-opacity-10'
                  }`}>
                    {job.status.toUpperCase()}
                  </span>
                </div>
                <div className="font-mono text-[10px] text-gray-500 truncate">{job.hash}</div>
                <div className="text-right text-[10px] text-gray-500">{job.time}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
