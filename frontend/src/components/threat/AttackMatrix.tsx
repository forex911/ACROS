import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { Activity, ShieldAlert } from 'lucide-react';
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

  if (isLoading) return <div className="text-[#888888] font-mono text-xs uppercase tracking-widest p-6">LOADING MATRIX...</div>;
  if (error) return <div className="text-[#ffffff] font-mono font-bold uppercase tracking-widest p-6 border border-[#ffffff] m-4 inline-block">ERROR LOADING MATRIX.</div>;
  if (tactics.length === 0) return <div className="text-[#666666] font-mono text-xs uppercase tracking-widest p-10 border border-[#222222] text-center m-4">NO ACTIVE THREATS DETECTED.</div>;
  
  return (
    <div className="w-full h-full overflow-x-auto bg-[#000000] p-4 custom-scrollbar min-w-0" data-lenis-prevent>
      <div className="flex gap-6 min-w-max">
        {tactics.map((tactic: Tactic) => (
          <div key={tactic.id} className="w-[280px] flex-shrink-0">
            {/* Tactic Header */}
            <div className="bg-[#111111] border-2 border-[#ffffff] p-4 mb-4 flex items-center justify-between">
               <div>
                  <h3 className="font-heading font-bold text-sm uppercase tracking-widest text-[#ffffff] truncate" title={tactic.name}>
                     {tactic.name}
                  </h3>
                  <span className="text-[10px] text-[#000000] font-mono font-bold bg-[#ffffff] px-2 py-1 mt-2 inline-block uppercase tracking-widest">{tactic.id}</span>
               </div>
               <ShieldAlert size={18} className="text-[#ffffff]" />
            </div>

            {/* Techniques List */}
            <div className="flex flex-col gap-3">
              {tactic.techniques.map((technique) => (
                <div 
                  key={technique.id} 
                  className={`
                    p-4 border transition-colors duration-200
                    ${technique.active 
                      ? 'bg-red-500/10 border-red-500' 
                      : 'bg-[#000000] border-[#333333] hover:border-[#666666]'
                    }
                  `}
                  title={technique.description}
                >
                   <div className="flex justify-between items-start mb-3">
                      <span className={`font-sans font-bold text-sm leading-snug ${technique.active ? 'text-red-500' : 'text-[#888888]'}`}>{technique.name}</span>
                   </div>
                   <div className="flex justify-between items-center mt-auto">
                      <span className={`text-[10px] font-mono font-bold px-2 py-1 uppercase tracking-widest border ${technique.active ? 'bg-red-500 text-[#000000] border-red-500' : 'bg-[#111111] text-[#666666] border-[#222222]'}`}>{technique.id}</span>
                      {technique.active && (
                         <div className="flex items-center space-x-2">
                           {technique.frequency && <span className="text-[10px] font-mono font-bold text-red-500 border border-red-500 px-2 py-0.5">x{technique.frequency}</span>}
                           <Activity size={14} className="animate-pulse text-red-500" />
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
