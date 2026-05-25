import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { Activity, ShieldAlert, Cpu, HardDrive, TerminalSquare, AlertTriangle } from 'lucide-react';
import { useWebSocket } from '../hooks/useWebSocket';

const AnalysisDetail: React.FC = () => {
  const { jobId } = useParams<{ jobId: string }>();
  const [activeTab, setActiveTab] = useState<'overview' | 'telemetry' | 'iocs'>('overview');
  
  // Real-time telemetry feed
  const { messages, isConnected } = useWebSocket(`/ws/jobs/${jobId}/telemetry`);

  return (
    <div className="space-y-6 h-full flex flex-col">
      {/* Header Panel */}
      <div className="cyber-panel p-6 flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold font-mono text-gray-100 flex items-center">
            <ShieldAlert className="w-6 h-6 text-cyber-alert mr-3" />
            ANALYSIS REPORT
          </h2>
          <div className="text-sm font-mono text-gray-400 mt-1">JOB_ID: {jobId}</div>
        </div>
        <div className="flex space-x-6">
          <div className="text-center">
            <div className="text-xs font-mono text-gray-500 mb-1">AI RISK SCORE</div>
            <div className="text-2xl font-bold text-cyber-alert">94/100</div>
          </div>
          <div className="text-center">
            <div className="text-xs font-mono text-gray-500 mb-1">STATUS</div>
            <div className="text-sm font-mono bg-cyber-accent text-cyber-accent bg-opacity-20 border border-cyber-accent px-2 py-1 rounded">
              ANALYZING
            </div>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex space-x-1 border-b border-cyber-border">
        {['overview', 'telemetry', 'iocs'].map(tab => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab as any)}
            className={`px-4 py-2 font-mono text-sm tracking-wider uppercase transition-colors ${
              activeTab === tab
                ? 'text-cyber-accent border-b-2 border-cyber-accent bg-cyber-accent bg-opacity-10'
                : 'text-gray-500 hover:text-gray-300'
            }`}
          >
            {tab}
          </button>
        ))}
      </div>

      {/* Content Area */}
      <div className="flex-1 overflow-auto min-h-[500px]">
        {activeTab === 'overview' && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 h-full">
            <div className="col-span-2 cyber-panel p-6 flex flex-col">
              <h3 className="text-cyber-accent font-mono text-sm mb-4">AI THREAT SUMMARY</h3>
              <p className="text-gray-300 leading-relaxed font-sans text-sm">
                The analyzed sample exhibits behaviors strongly correlated with ransomware activity. 
                Specifically, it attempts to delete volume shadow copies using <code className="bg-gray-800 text-cyber-alert px-1 rounded">vssadmin.exe</code> 
                and initiates rapid, widespread file encryption across the user directory. Network activity indicates a connection to a known Tor exit node, likely for key exchange.
              </p>
              
              <h3 className="text-cyber-accent font-mono text-sm mt-8 mb-4">MITRE ATT&CK MAPPINGS</h3>
              <div className="grid grid-cols-2 gap-4">
                 <div className="bg-cyber-dark border border-cyber-border p-3 rounded">
                   <div className="text-xs font-mono text-gray-500">T1490</div>
                   <div className="text-sm text-gray-200">Inhibit System Recovery</div>
                 </div>
                 <div className="bg-cyber-dark border border-cyber-border p-3 rounded">
                   <div className="text-xs font-mono text-gray-500">T1486</div>
                   <div className="text-sm text-gray-200">Data Encrypted for Impact</div>
                 </div>
                 <div className="bg-cyber-dark border border-cyber-border p-3 rounded">
                   <div className="text-xs font-mono text-gray-500">T1090</div>
                   <div className="text-sm text-gray-200">Proxy</div>
                 </div>
              </div>
            </div>
            
            <div className="cyber-panel p-6">
              <h3 className="text-gray-400 font-mono text-sm mb-4">FILE METADATA</h3>
              <div className="space-y-4 text-sm font-mono">
                <div>
                  <div className="text-gray-500 text-xs">SHA256</div>
                  <div className="text-cyber-accent break-all text-xs">e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855</div>
                </div>
                <div>
                  <div className="text-gray-500 text-xs">FILE TYPE</div>
                  <div className="text-gray-200">Win32 EXE (PE32)</div>
                </div>
                <div>
                  <div className="text-gray-500 text-xs">SIZE</div>
                  <div className="text-gray-200">4.2 MB</div>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'telemetry' && (
          <div className="cyber-panel h-full flex flex-col p-4 bg-[#0a0a0a]">
            <div className="flex justify-between items-center mb-2">
              <h3 className="text-gray-500 font-mono text-xs flex items-center">
                <TerminalSquare className="w-4 h-4 mr-2" />
                LIVE EVENT STREAM {isConnected ? '(CONNECTED)' : '(CONNECTING...)'}
              </h3>
              <div className="flex space-x-2">
                <span className="w-2 h-2 rounded-full bg-cyber-green animate-pulse"></span>
              </div>
            </div>
            <div className="flex-1 overflow-auto font-mono text-xs space-y-1">
              {messages.length === 0 && (
                <div className="text-gray-600 italic">Waiting for telemetry...</div>
              )}
              {messages.map((msg, i) => (
                <div key={i} className="border-l-2 border-cyber-border pl-2 py-1 hover:bg-gray-800 transition-colors">
                  <span className="text-gray-500">[{new Date().toISOString().split('T')[1].split('.')[0]}]</span>{' '}
                  <span className={msg.type === 'PROCESS_CREATE' ? 'text-cyber-alert' : 'text-cyber-accent'}>
                    {msg.type}
                  </span>{' '}
                  <span className="text-gray-300">{JSON.stringify(msg.data)}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {activeTab === 'iocs' && (
          <div className="grid grid-cols-2 gap-6">
            <div className="cyber-panel p-6">
              <h3 className="text-cyber-alert font-mono text-sm mb-4 flex items-center">
                <AlertTriangle className="w-4 h-4 mr-2" />
                YARA MATCHES
              </h3>
              <div className="space-y-2">
                <div className="bg-cyber-dark p-3 rounded border border-cyber-alert font-mono text-sm text-gray-200">
                  Ransom_LockBit_v2
                </div>
                <div className="bg-cyber-dark p-3 rounded border border-cyber-alert font-mono text-sm text-gray-200">
                  Suspicious_Packed_UPX
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default AnalysisDetail;
