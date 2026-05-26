import { useQuery } from '@tanstack/react-query';
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
  description?: string;
  active?: boolean;
  frequency?: number;
}

export const AttackMatrix: React.FC = () => {
  const { data: tactics = [], isLoading, error } = useQuery({
    queryKey: ['attackMatrix'],
    queryFn: async () => {
      const res = await api.get('/threats/matrix');
      return res.data;
    },
    refetchInterval: 5000,
  });

  if (isLoading) return <div className="text-cyber-accent font-mono p-4">LOADING MATRIX...</div>;
  if (error) return <div className="text-cyber-alert font-mono p-4">ERROR LOADING MATRIX</div>;
  if (tactics.length === 0) return <div className="text-gray-500 font-mono p-4">No active threats detected.</div>;
  
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
                         <div className="flex items-center space-x-2">
                           {technique.frequency && <span className="text-[10px] font-mono text-cyber-alert bg-cyber-alert/20 px-1 rounded">x{technique.frequency}</span>}
                           <Activity size={12} className="animate-pulse text-cyber-alert" />
                         </div>
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
