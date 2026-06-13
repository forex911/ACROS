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

  if (isLoading) return <div className="text-gray-500 font-medium p-6">Loading Matrix...</div>;
  if (error) return <div className="text-red-500 font-medium p-6">Error Loading Matrix</div>;
  if (tactics.length === 0) return <div className="text-gray-500 font-medium p-6 bg-white border border-gray-100 rounded-xl">No active threats detected.</div>;
  
  return (
    <div className="w-full h-full overflow-x-auto bg-gray-50 text-gray-700 font-sans p-2 rounded-xl">
      <div className="flex gap-4 p-4 min-w-max">
        {tactics.map((tactic) => (
          <div key={tactic.id} className="w-64 flex-shrink-0">
            {/* Tactic Header */}
            <div className="bg-white border border-gray-200 rounded-lg p-3 mb-3 flex items-center justify-between shadow-sm">
               <div>
                  <h3 className="font-bold text-sm text-gray-900 truncate" title={tactic.name}>
                     {tactic.name}
                  </h3>
                  <span className="text-xs text-gray-500 font-mono bg-gray-100 px-1.5 py-0.5 rounded">{tactic.id}</span>
               </div>
               <ShieldAlert size={16} className="text-gray-400" />
            </div>

            {/* Techniques List */}
            <div className="flex flex-col gap-2">
              {tactic.techniques.map((technique) => (
                <div 
                  key={technique.id} 
                  className={`
                    p-3 border rounded-lg cursor-pointer transition-all duration-200 shadow-sm
                    ${technique.active 
                      ? 'bg-red-50 border-red-200 hover:border-red-300 hover:bg-red-100' 
                      : 'bg-white border-gray-100 hover:border-gray-300 hover:bg-gray-50'
                    }
                  `}
                  title={technique.description}
                >
                   <div className="flex justify-between items-start mb-1">
                      <span className={`font-semibold text-sm leading-tight ${technique.active ? 'text-red-700' : 'text-gray-700'}`}>{technique.name}</span>
                   </div>
                   <div className="flex justify-between items-center mt-2">
                      <span className={`text-xs font-mono px-1.5 py-0.5 rounded ${technique.active ? 'bg-red-100 text-red-600' : 'bg-gray-100 text-gray-500'}`}>{technique.id}</span>
                      {technique.active && (
                         <div className="flex items-center space-x-2">
                           {technique.frequency && <span className="text-[10px] font-bold text-red-700 bg-red-200 px-1.5 py-0.5 rounded-full">x{technique.frequency}</span>}
                           <Activity size={14} className="animate-pulse text-red-600" />
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
