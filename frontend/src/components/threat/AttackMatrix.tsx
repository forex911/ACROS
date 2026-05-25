import React, { useState, useEffect } from 'react';
import { Activity, ShieldAlert, Cpu } from 'lucide-react';
import api from '../../api/client';

interface Tactic {
  id: string;
  name: string;
  description: string;
  techniques: Technique[];
}

interface Technique {
  id: string;
  name: string;
  description: string;
  active?: boolean;
}

const mockTactics: Tactic[] = [
  {
    id: "TA0001",
    name: "Initial Access",
    description: "The adversary is trying to get into your network.",
    techniques: [
      { id: "T1189", name: "Drive-by Compromise", description: "..." },
      { id: "T1190", name: "Exploit Public-Facing Application", description: "..." },
      { id: "T1566", name: "Phishing", description: "...", active: true }
    ]
  },
  {
    id: "TA0002",
    name: "Execution",
    description: "The adversary is trying to run malicious code.",
    techniques: [
      { id: "T1059", name: "Command and Scripting Interpreter", description: "...", active: true },
      { id: "T1203", name: "Exploitation for Client Execution", description: "..." },
      { id: "T1569", name: "System Services", description: "..." }
    ]
  },
  {
    id: "TA0003",
    name: "Persistence",
    description: "The adversary is trying to maintain their foothold.",
    techniques: [
      { id: "T1098", name: "Account Manipulation", description: "..." },
      { id: "T1136", name: "Create Account", description: "..." },
      { id: "T1543", name: "Create or Modify System Process", description: "...", active: true }
    ]
  },
  {
    id: "TA0004",
    name: "Privilege Escalation",
    description: "The adversary is trying to gain higher-level permissions.",
    techniques: [
      { id: "T1548", name: "Abuse Elevation Control Mechanism", description: "..." },
      { id: "T1134", name: "Access Token Manipulation", description: "...", active: true },
      { id: "T1055", name: "Process Injection", description: "..." }
    ]
  },
  {
    id: "TA0005",
    name: "Defense Evasion",
    description: "The adversary is trying to avoid being detected.",
    techniques: [
      { id: "T1140", name: "Deobfuscate/Decode Files or Information", description: "...", active: true },
      { id: "T1070", name: "Indicator Removal", description: "..." },
      { id: "T1036", name: "Masquerading", description: "..." }
    ]
  }
];

export const AttackMatrix: React.FC = () => {
  const [tactics, setTactics] = useState<Tactic[]>(mockTactics);
  
  return (
    <div className="w-full h-full overflow-x-auto bg-cyber-dark text-gray-300 font-sans">
      <div className="flex gap-4 p-4 min-w-max">
        {tactics.map((tactic) => (
          <div key={tactic.id} className="w-64 flex-shrink-0">
            {/* Tactic Header */}
            <div className="bg-cyber-panel border border-cyber-border rounded-t-lg p-3 mb-2 flex items-center justify-between shadow-lg">
               <div>
                  <h3 className="font-bold text-sm text-cyber-accent truncate" title={tactic.name}>
                     {tactic.name}
                  </h3>
                  <span className="text-xs text-gray-500">{tactic.id}</span>
               </div>
               <ShieldAlert size={16} className="text-cyber-accent opacity-50" />
            </div>

            {/* Techniques List */}
            <div className="flex flex-col gap-2">
              {tactic.techniques.map((technique) => (
                <div 
                  key={technique.id} 
                  className={`
                    p-3 border rounded-md cursor-pointer transition-all duration-200
                    ${technique.active 
                      ? 'bg-cyber-alert/10 border-cyber-alert text-cyber-alert shadow-[0_0_10px_rgba(255,123,114,0.2)]' 
                      : 'bg-cyber-panel/50 border-cyber-border hover:bg-cyber-panel hover:border-gray-500'
                    }
                  `}
                  title={technique.description}
                >
                   <div className="flex justify-between items-start mb-1">
                      <span className="font-medium text-sm leading-tight">{technique.name}</span>
                   </div>
                   <div className="flex justify-between items-center mt-2">
                      <span className="text-xs opacity-70 font-mono">{technique.id}</span>
                      {technique.active && (
                         <Activity size={12} className="animate-pulse text-cyber-alert" />
                      )}
                   </div>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
