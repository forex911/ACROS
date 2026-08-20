import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Activity, ShieldAlert, X, Info } from 'lucide-react';
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

  const [selectedTechnique, setSelectedTechnique] = useState<Technique | null>(null);
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
    <div className="w-max bg-[#000000] p-4" data-lenis-prevent>
      {/* Technique Detail Modal */}
      {selectedTechnique && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="bg-[#0a0a0a] border border-[#333333] w-full max-w-2xl shadow-2xl overflow-hidden animate-in fade-in zoom-in duration-200">
            {/* Header */}
            <div className="flex items-center justify-between p-6 border-b border-[#222222] bg-[#111111]">
              <div className="flex items-center gap-4">
                <div className="w-10 h-10 border border-red-500 bg-red-500/10 flex items-center justify-center">
                  <ShieldAlert className="w-5 h-5 text-red-500" />
                </div>
                <div>
                  <div className="flex items-center gap-3 mb-1">
                    <span className="text-[10px] font-mono font-bold bg-red-500 text-black px-2 py-0.5 uppercase tracking-widest">{selectedTechnique.id}</span>
                    <span className="text-[10px] font-mono font-bold text-red-500 uppercase tracking-widest flex items-center gap-1">
                      <Activity size={12} /> ACTIVE THREAT
                    </span>
                  </div>
                  <h2 className="text-xl font-heading font-black text-white uppercase tracking-tighter">{selectedTechnique.name}</h2>
                </div>
              </div>
              <button 
                onClick={() => setSelectedTechnique(null)}
                className="p-2 text-[#666666] hover:text-white transition-colors"
              >
                <X size={20} />
              </button>
            </div>
            
            {/* Body */}
            <div className="p-8 space-y-8">
              <div>
                <h3 className="text-[10px] font-mono font-bold text-[#666666] uppercase tracking-[0.2em] mb-3 flex items-center gap-2">
                  <Info size={12} /> Threat Overview
                </h3>
                <p className="text-sm font-sans text-[#cccccc] leading-relaxed">
                  {selectedTechnique.description || "No detailed description available for this specific technique. It involves adversarial behavior mapped to the MITRE ATT&CK framework."}
                </p>
              </div>
              
              <div className="grid grid-cols-2 gap-4">
                 <div className="border border-[#222222] p-4 bg-[#050505]">
                    <span className="block text-[10px] font-mono font-bold text-[#666666] uppercase tracking-[0.2em] mb-1">Observed Frequency</span>
                    <span className="text-2xl font-heading font-black text-white">{selectedTechnique.frequency || 1}x</span>
                 </div>
                 <div className="border border-[#222222] p-4 bg-[#050505]">
                    <span className="block text-[10px] font-mono font-bold text-[#666666] uppercase tracking-[0.2em] mb-1">Status</span>
                    <span className="text-lg font-heading font-black text-red-500">DETECTED</span>
                 </div>
              </div>
            </div>
          </div>
        </div>
      )}

      <div className="flex gap-8 min-w-max">
        {tactics.map((tactic: Tactic) => (
          <div key={tactic.id} className="w-[300px] flex-shrink-0">
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
            <div className="flex flex-col gap-4">
              {tactic.techniques.map((technique) => (
                <div 
                  key={technique.id} 
                  onClick={() => setSelectedTechnique(technique)}
                  className={`
                    cursor-pointer p-4 border transition-colors duration-200
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
