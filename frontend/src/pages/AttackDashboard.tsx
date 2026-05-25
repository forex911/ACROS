import React from 'react';
import { Target, Activity, Zap } from 'lucide-react';
import { AttackMatrix } from '../components/threat/AttackMatrix';

const AttackDashboard: React.FC = () => {
  return (
    <div className="flex flex-col h-full bg-cyber-dark p-6 space-y-6 overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-100 flex items-center gap-2">
            <Target className="text-cyber-accent" />
            ATT&CK Intelligence Matrix
          </h1>
          <p className="text-gray-400 text-sm mt-1">Real-time correlation of sandbox telemetry to MITRE ATT&CK techniques.</p>
        </div>
        <div className="flex gap-4">
           <div className="flex items-center gap-2 px-4 py-2 bg-cyber-panel border border-cyber-border rounded-lg">
              <Activity size={16} className="text-cyber-green" />
              <span className="text-sm text-gray-300">Live Telemetry: <strong>Active</strong></span>
           </div>
           <div className="flex items-center gap-2 px-4 py-2 bg-cyber-alert/10 border border-cyber-alert rounded-lg">
              <Zap size={16} className="text-cyber-alert" />
              <span className="text-sm text-cyber-alert">Techniques Detected: <strong>4</strong></span>
           </div>
        </div>
      </div>

      {/* Main Matrix Area */}
      <div className="flex-1 min-h-0 border border-cyber-border rounded-xl overflow-hidden bg-[#0d1117] shadow-2xl relative">
          <div className="absolute inset-0 pointer-events-none bg-[radial-gradient(ellipse_at_center,_var(--tw-gradient-stops))] from-cyber-accent/5 via-transparent to-transparent opacity-50 z-0"></div>
          <div className="relative z-10 w-full h-full p-2">
             <AttackMatrix />
          </div>
      </div>
    </div>
  );
};

export default AttackDashboard;
