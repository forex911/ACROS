import React from 'react';
import { Terminal, Activity, Server, Database } from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

const mockCpuData = [
  { time: '10:00', worker_1: 45, worker_2: 30, worker_3: 15 },
  { time: '10:05', worker_1: 65, worker_2: 35, worker_3: 45 },
  { time: '10:10', worker_1: 85, worker_2: 50, worker_3: 75 },
  { time: '10:15', worker_1: 95, worker_2: 80, worker_3: 90 },
  { time: '10:20', worker_1: 55, worker_2: 40, worker_3: 35 },
];

const Observability: React.FC = () => {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between border-b border-cyber-border pb-4">
        <div>
          <h2 className="text-2xl font-bold font-mono text-gray-100 flex items-center">
            <Terminal className="w-6 h-6 text-cyber-accent mr-3" />
            CLUSTER OBSERVABILITY
          </h2>
          <p className="text-sm font-mono text-gray-400 mt-1">PROMETHEUS / GRAFANA INTEGRATION</p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="cyber-panel p-6 flex flex-col items-center justify-center">
          <Server className="w-8 h-8 text-cyber-green mb-4" />
          <div className="text-3xl font-bold text-cyber-green font-mono">12/12</div>
          <div className="text-xs text-gray-400 font-mono mt-2">WORKER NODES ONLINE</div>
        </div>
        <div className="cyber-panel p-6 flex flex-col items-center justify-center">
          <Activity className="w-8 h-8 text-cyber-accent mb-4" />
          <div className="text-3xl font-bold text-cyber-accent font-mono">145ms</div>
          <div className="text-xs text-gray-400 font-mono mt-2">P99 API LATENCY</div>
        </div>
        <div className="cyber-panel p-6 flex flex-col items-center justify-center">
          <Database className="w-8 h-8 text-cyber-alert mb-4" />
          <div className="text-3xl font-bold text-cyber-alert font-mono">4.2M</div>
          <div className="text-xs text-gray-400 font-mono mt-2">REDIS QUEUE DEPTH</div>
        </div>
      </div>

      <div className="cyber-panel p-6">
        <h3 className="text-gray-400 font-mono text-sm tracking-wider mb-6">WORKER CPU UTILIZATION (gVisor Sandboxes)</h3>
        <div className="h-80">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={mockCpuData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#30363d" />
              <XAxis dataKey="time" stroke="#8b949e" tick={{ fill: '#8b949e', fontSize: 12 }} />
              <YAxis stroke="#8b949e" tick={{ fill: '#8b949e', fontSize: 12 }} />
              <Tooltip 
                contentStyle={{ backgroundColor: '#161b22', borderColor: '#30363d', color: '#c9d1d9' }}
              />
              <Line type="monotone" dataKey="worker_1" stroke="#58a6ff" strokeWidth={2} dot={false} />
              <Line type="monotone" dataKey="worker_2" stroke="#00ff41" strokeWidth={2} dot={false} />
              <Line type="monotone" dataKey="worker_3" stroke="#ff7b72" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
};

export default Observability;
