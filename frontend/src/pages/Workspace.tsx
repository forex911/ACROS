import React, { useState, useEffect } from 'react';
import { Briefcase, FileText, Pin, Clock, Plus } from 'lucide-react';
import api from '../api/client';

export const Workspace: React.FC = () => {
  const [cases, setCases] = useState<any[]>([]);
  const [selectedCase, setSelectedCase] = useState<any | null>(null);

  useEffect(() => {
    fetchCases();
  }, []);

  const fetchCases = async () => {
    try {
      const response = await api.get('/cases');
      setCases(response.data);
    } catch (error) {
      console.error("Failed to fetch cases", error);
    }
  };

  const loadCase = async (caseId: string) => {
    try {
      const response = await api.get(`/cases/${caseId}`);
      setSelectedCase(response.data);
    } catch (error) {
      console.error("Failed to load case details", error);
    }
  };

  return (
    <div className="flex h-full bg-cyber-dark text-gray-300">
      {/* Case List Sidebar */}
      <div className="w-1/3 border-r border-cyber-border p-4 overflow-y-auto">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-xl font-bold font-mono text-gray-100 flex items-center gap-2">
            <Briefcase className="text-cyber-accent" />
            INVESTIGATIONS
          </h2>
          <button className="p-2 bg-cyber-accent text-white rounded hover:bg-cyber-accent/80 transition-colors">
             <Plus size={16} />
          </button>
        </div>

        <div className="space-y-4">
          {cases.map(c => (
            <div 
              key={c._id}
              onClick={() => loadCase(c._id)}
              className={`p-4 rounded border cursor-pointer transition-colors ${
                selectedCase?._id === c._id 
                  ? 'bg-cyber-panel border-cyber-accent' 
                  : 'bg-cyber-dark border-cyber-border hover:bg-cyber-panel/50'
              }`}
            >
              <h3 className="font-bold text-gray-100">{c.title}</h3>
              <p className="text-sm text-gray-500 mt-1 line-clamp-2">{c.description}</p>
              <div className="flex items-center justify-between mt-3 text-xs font-mono text-gray-400">
                <span>{c.owner}</span>
                <span className={c.status === 'OPEN' ? 'text-cyber-green' : 'text-gray-500'}>[{c.status}]</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Case Details Area */}
      <div className="flex-1 p-6 overflow-y-auto">
        {selectedCase ? (
          <div>
            <div className="flex items-center justify-between mb-6 pb-4 border-b border-cyber-border">
              <div>
                <h1 className="text-2xl font-bold text-gray-100 mb-2">{selectedCase.title}</h1>
                <p className="text-gray-400">{selectedCase.description}</p>
              </div>
              <div className="text-right font-mono text-sm text-gray-500">
                <p>OWNER: {selectedCase.owner}</p>
                <p>CREATED: {new Date(selectedCase.created_at).toLocaleDateString()}</p>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-8">
               {/* Pinned Artifacts */}
               <div>
                 <h3 className="text-lg font-bold text-gray-200 mb-4 flex items-center gap-2">
                    <Pin className="text-cyber-alert" size={20} />
                    PINNED ARTIFACTS
                 </h3>
                 <div className="space-y-2">
                   {selectedCase.artifacts.length === 0 && <p className="text-sm text-gray-500">No artifacts pinned.</p>}
                   {selectedCase.artifacts.map((art: any, i: number) => (
                      <div key={i} className="flex justify-between p-3 bg-cyber-panel border border-cyber-border rounded font-mono text-sm">
                         <span className="text-cyber-accent">{art.type.toUpperCase()}</span>
                         <span className="text-gray-300">{art.value}</span>
                      </div>
                   ))}
                 </div>
               </div>

               {/* Analyst Notes */}
               <div>
                 <h3 className="text-lg font-bold text-gray-200 mb-4 flex items-center gap-2">
                    <FileText className="text-cyber-green" size={20} />
                    ANALYST NOTES
                 </h3>
                 <div className="space-y-4">
                   {selectedCase.notes.length === 0 && <p className="text-sm text-gray-500">No notes yet.</p>}
                   {selectedCase.notes.map((note: any, i: number) => (
                      <div key={i} className="p-4 bg-cyber-panel/50 border border-cyber-border rounded">
                         <p className="text-gray-300 text-sm mb-3">{note.content}</p>
                         <div className="flex justify-between items-center text-xs font-mono text-gray-500">
                            <span>{note.author}</span>
                            <span className="flex items-center gap-1"><Clock size={12}/> {new Date(note.timestamp).toLocaleTimeString()}</span>
                         </div>
                      </div>
                   ))}
                 </div>
               </div>
            </div>
          </div>
        ) : (
          <div className="h-full flex items-center justify-center text-gray-500 font-mono">
            SELECT AN INVESTIGATION OR CREATE NEW
          </div>
        )}
      </div>
    </div>
  );
};

export default Workspace;
