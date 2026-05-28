import React, { useState } from 'react';
import { useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import api from '../api/client';
import { Activity, ShieldAlert, Cpu, HardDrive, TerminalSquare, AlertTriangle } from 'lucide-react';
import { useWebSocket } from '../hooks/useWebSocket';

const AnalysisDetail: React.FC = () => {
  const { jobId } = useParams<{ jobId: string }>();
  const [activeTab, setActiveTab] = useState<'overview' | 'telemetry' | 'iocs' | 'visualization'>('overview');

  const { data: analysis, isLoading, error } = useQuery({
    queryKey: ['analysis', jobId],
    queryFn: async () => {
      const res = await api.get(`/analysis/${jobId}`);
      return res.data;
    },
    refetchInterval: (data) => (data?.status === 'completed' || data?.status === 'failed' ? false : 3000),
  });

  const actualJobId = analysis?.file_id || jobId;
  const { messages, isConnected } = useWebSocket(actualJobId !== 'latest' ? `/ws/jobs/${actualJobId}/telemetry` : '');

  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center h-full p-8 font-mono">
        <div className="relative w-24 h-24 mb-8">
           <div className="absolute inset-0 border-t-2 border-cyber-accent rounded-full animate-spin"></div>
           <div className="absolute inset-2 border-r-2 border-cyber-green rounded-full animate-spin" style={{ animationDirection: 'reverse', animationDuration: '1.5s' }}></div>
           <div className="absolute inset-4 border-b-2 border-cyber-alert rounded-full animate-spin" style={{ animationDuration: '2s' }}></div>
           <div className="absolute inset-0 flex items-center justify-center text-cyber-accent">
              <Activity className="w-6 h-6 animate-pulse" />
           </div>
        </div>
        <div className="text-cyber-accent text-lg tracking-widest animate-pulse mb-6">INITIALIZING ANALYSIS</div>
        
        <div className="w-full max-w-2xl bg-[#050505] border border-cyber-border rounded p-4 text-xs text-green-500 font-mono shadow-[0_0_10px_rgba(0,255,0,0.1)]">
           <div className="flex justify-between items-center mb-2 border-b border-gray-800 pb-2">
             <span className="text-gray-500">DEBUG CONSOLE</span>
             <span className="flex space-x-1">
               <span className="w-2 h-2 bg-gray-700 rounded-full"></span>
               <span className="w-2 h-2 bg-gray-700 rounded-full"></span>
               <span className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></span>
             </span>
           </div>
           <div className="space-y-1 opacity-80 h-32 overflow-hidden flex flex-col justify-end">
             <div className="text-gray-500">[0.000s] SYSTEM: Booting sandbox orchestrator...</div>
             <div className="text-gray-500">[0.125s] SYSTEM: Uploading artifact to secure vault...</div>
             <div>[0.450s] INIT: Spawning isolation microVM...</div>
             <div>[0.820s] NETWORK: Applying zero-trust egress filters...</div>
             <div>[1.050s] STATIC: Extracting hashes and metadata...</div>
             <div>[1.240s] RUNTIME: Hooking syscalls (eBPF)...</div>
             <div className="text-cyber-accent animate-pulse">[1.500s] AWAITING ANALYSIS COMPLETION_</div>
           </div>
        </div>
      </div>
    );
  }
  if (error) return <div className="text-cyber-alert p-6 font-mono">ERROR LOADING ANALYSIS</div>;

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
            <div className="text-2xl font-bold text-cyber-alert">{analysis?.risk_score || '--'}/100</div>
          </div>
          <div className="text-center">
            <div className="text-xs font-mono text-gray-500 mb-1">STATUS</div>
            <div className={`text-sm font-mono px-2 py-1 rounded border ${
              analysis?.status === 'analyzing' ? 'bg-cyber-accent/20 text-cyber-accent border-cyber-accent' :
              analysis?.status === 'completed' ? 'bg-cyber-green/20 text-cyber-green border-cyber-green' :
              'bg-gray-800 text-gray-400 border-gray-500'
            }`}>
              {analysis?.status?.toUpperCase() || 'UNKNOWN'}
            </div>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex space-x-1 border-b border-cyber-border">
        {['overview', 'telemetry', 'iocs', 'visualization'].map(tab => (
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
                {analysis?.ai_summary}
              </p>
              
              <h3 className="text-cyber-accent font-mono text-sm mt-8 mb-4">MITRE ATT&CK MAPPINGS</h3>
              <div className="grid grid-cols-2 gap-4">
                 {analysis?.mitre_tactics?.length > 0 ? analysis.mitre_tactics.map((tactic: any, idx: number) => (
                   <div key={idx} className="bg-cyber-dark border border-cyber-border p-3 rounded">
                     <div className="text-xs font-mono text-gray-500">{tactic.id}</div>
                     <div className="text-sm text-gray-200">{tactic.name}</div>
                   </div>
                 )) : (
                   <div className="text-gray-500 text-sm font-mono">No tactics mapped yet.</div>
                 )}
              </div>
            </div>
            
            <div className="cyber-panel p-6">
              <h3 className="text-gray-400 font-mono text-sm mb-4">FILE METADATA</h3>
              <div className="space-y-4 text-sm font-mono">
                <div>
                  <div className="text-gray-500 text-xs">SHA256</div>
                  <div className="text-cyber-accent break-all text-xs">{analysis?.metadata?.artifact_sha256 || 'N/A'}</div>
                </div>
                <div>
                  <div className="text-gray-500 text-xs">FILE NAME</div>
                  <div className="text-gray-200 truncate">{analysis?.filename || 'N/A'}</div>
                </div>
                <div>
                  <div className="text-gray-500 text-xs">SIZE</div>
                  <div className="text-gray-200 text-xs">{analysis?.metadata?.size_bytes ? `${(analysis.metadata.size_bytes / 1024).toFixed(2)} KB` : 'N/A'}</div>
                </div>
                <div>
                  <div className="text-gray-500 text-xs">MD5</div>
                  <div className="text-cyber-accent break-all text-xs">{analysis?.metadata?.md5 || 'N/A'}</div>
                </div>
                <div>
                  <div className="text-gray-500 text-xs">ENTROPY</div>
                  <div className="text-cyber-accent break-all text-xs">{analysis?.metadata?.entropy ? analysis.metadata.entropy.toFixed(2) : 'N/A'}</div>
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
                <div key={i} className={`border-l-2 pl-2 py-1 hover:bg-gray-800 transition-colors ${
                  msg.severity === 'high' ? 'border-cyber-alert' :
                  msg.severity === 'medium' ? 'border-orange-500' :
                  'border-cyber-border'
                }`}>
                  <span className="text-gray-500">[{msg.timestamp ? new Date(msg.timestamp).toISOString().split('T')[1].split('.')[0] : new Date().toISOString().split('T')[1].split('.')[0]}]</span>{' '}
                  <span className={`font-bold ${
                    msg.type === 'PROCESS_CREATE' || msg.type === 'EXECUTION' ? 'text-cyber-alert' :
                    msg.type === 'FILE_WRITE' || msg.type === 'REGISTRY_WRITE' ? 'text-orange-500' :
                    msg.type === 'NETWORK_CONNECT' || msg.type === 'HTTP_REQUEST' || msg.type === 'SOCKET_CONNECT' || msg.type === 'DNS_QUERY' ? 'text-cyber-accent' :
                    'text-gray-400'
                  }`}>
                    {msg.type}
                  </span>{' '}
                  <span className="text-gray-300 ml-2">{JSON.stringify(msg.data)}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {activeTab === 'iocs' && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="cyber-panel p-6 col-span-2">
              <h3 className="text-cyber-accent font-mono text-sm mb-4 flex items-center">
                <ShieldAlert className="w-4 h-4 mr-2" />
                EXTRACTED INDICATORS OF COMPROMISE (IOCs)
              </h3>
              <div className="overflow-x-auto">
                <table className="w-full text-left font-mono text-sm border-collapse">
                  <thead>
                    <tr className="border-b border-cyber-border text-gray-500 uppercase tracking-wider text-xs">
                      <th className="py-2 px-3">Type</th>
                      <th className="py-2 px-3">Value</th>
                      <th className="py-2 px-3">Source</th>
                      <th className="py-2 px-3 text-right">Confidence</th>
                    </tr>
                  </thead>
                  <tbody>
                    {analysis?.iocs?.length > 0 ? analysis.iocs.map((ioc: any, idx: number) => (
                      <tr key={idx} className="border-b border-gray-800 hover:bg-gray-900 transition-colors">
                        <td className={`py-3 px-3 font-bold ${
                          ioc.type === 'ip' || ioc.type === 'domain' || ioc.type === 'url' ? 'text-cyber-accent' :
                          ioc.type === 'sha256' || ioc.type === 'md5' ? 'text-gray-400' :
                          'text-cyber-alert'
                        }`}>
                          {ioc.type.toUpperCase()}
                        </td>
                        <td className="py-3 px-3 text-gray-200 break-all">{ioc.value}</td>
                        <td className="py-3 px-3 text-gray-500 text-xs">{ioc.source}</td>
                        <td className="py-3 px-3 text-right">
                           <span className={`px-2 py-1 rounded text-xs ${
                             ioc.confidence === 'High' ? 'bg-cyber-alert/20 text-cyber-alert' :
                             ioc.confidence === 'Medium' ? 'bg-orange-500/20 text-orange-500' :
                             'bg-gray-800 text-gray-400'
                           }`}>
                             {ioc.confidence || 'Medium'}
                           </span>
                        </td>
                      </tr>
                    )) : (
                      <tr>
                        <td colSpan={4} className="py-6 text-center text-gray-600 italic">No indicators extracted yet.</td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="cyber-panel p-6">
              <h3 className="text-cyber-alert font-mono text-sm mb-4 flex items-center">
                <AlertTriangle className="w-4 h-4 mr-2" />
                YARA MATCHES
              </h3>
              <div className="space-y-2">
                {analysis?.yara_matches?.length > 0 ? analysis.yara_matches.map((yara: string, idx: number) => (
                  <div key={idx} className="bg-cyber-dark p-3 rounded border border-cyber-alert font-mono text-sm text-gray-200">
                    {yara}
                  </div>
                )) : (
                  <div className="text-gray-500 font-mono text-sm">No YARA matches.</div>
                )}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'visualization' && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 h-full">
            {/* Sandbox Lifecycle */}
            <div className="cyber-panel p-6 col-span-2">
              <h3 className="text-cyber-accent font-mono text-sm mb-4">SANDBOX LIFECYCLE TIMELINE</h3>
              <div className="flex justify-between items-center bg-cyber-dark p-4 rounded border border-cyber-border">
                <div className="text-center flex-1"><div className={`w-3 h-3 rounded-full mx-auto mb-2 ${isConnected ? 'bg-cyber-green shadow-[0_0_10px_#00ff00]' : 'bg-gray-600'}`}></div><div className="text-xs font-mono text-gray-400">VM BOOTING</div></div>
                <div className="flex-1 h-px bg-cyber-border"></div>
                <div className="text-center flex-1"><div className={`w-3 h-3 rounded-full mx-auto mb-2 ${isConnected ? 'bg-cyber-green shadow-[0_0_10px_#00ff00]' : 'bg-gray-600'}`}></div><div className="text-xs font-mono text-gray-400">PAYLOAD INJECTED</div></div>
                <div className="flex-1 h-px bg-cyber-border"></div>
                <div className="text-center flex-1"><div className={`w-3 h-3 rounded-full mx-auto mb-2 ${messages.length > 0 ? 'bg-cyber-alert shadow-[0_0_10px_#ff003c]' : 'bg-gray-600'}`}></div><div className="text-xs font-mono text-gray-400">DETONATING</div></div>
                <div className="flex-1 h-px bg-cyber-border"></div>
                <div className="text-center flex-1"><div className={`w-3 h-3 rounded-full mx-auto mb-2 ${analysis?.status === 'completed' ? 'bg-cyber-green shadow-[0_0_10px_#00ff00]' : 'bg-gray-600'}`}></div><div className="text-xs font-mono text-gray-400">TEARDOWN</div></div>
              </div>
            </div>

            {/* Process Tree */}
            <div className="cyber-panel p-6 overflow-auto">
              <h3 className="text-cyber-accent font-mono text-sm mb-4">PROCESS ANCESTRY TREE</h3>
              <div className="font-mono text-sm space-y-2 text-gray-300">
                <div className="flex items-center"><Activity className="w-4 h-4 mr-2 text-gray-500" /> [1000] python.exe (sandbox_runner)</div>
                {messages.filter(m => m.type === 'PROCESS_CREATE').map((m, i) => (
                  <div key={i} className="pl-6 flex items-center border-l-2 border-cyber-border ml-2">
                    <span className="w-4 h-px bg-cyber-border mr-2"></span>
                    <TerminalSquare className="w-4 h-4 mr-2 text-cyber-alert" /> 
                    <span className="text-cyber-alert font-bold mr-2">[{m.data.pid || 'NEW'}]</span> 
                    {m.data.cmdline || m.data.filename || m.data.comm || 'Unknown Process'}
                  </div>
                ))}
                {messages.filter(m => m.type === 'PROCESS_CREATE').length === 0 && (
                   <div className="pl-6 text-gray-500 italic">No child processes spawned.</div>
                )}
              </div>
            </div>

            {/* Network Graph */}
            <div className="cyber-panel p-6 overflow-auto">
              <h3 className="text-cyber-accent font-mono text-sm mb-4">NETWORK COMMUNICATIONS</h3>
              <div className="font-mono text-sm space-y-3">
                {messages.filter(m => m.type === 'DNS_QUERY' || m.type === 'SOCKET_CONNECT' || m.type === 'HTTP_REQUEST').map((m, i) => (
                  <div key={i} className="flex items-center justify-between bg-cyber-dark p-2 rounded border border-cyber-border">
                    <div className="flex items-center text-gray-400">
                      <TerminalSquare className="w-4 h-4 mr-2" />
                      Payload
                    </div>
                    <div className="flex-1 px-4 flex items-center justify-center">
                      <div className="h-px bg-cyber-accent flex-1"></div>
                      <span className="text-[10px] text-cyber-accent px-2">{m.type}</span>
                      <div className="h-px bg-cyber-accent flex-1"></div>
                    </div>
                    <div className="text-cyber-accent break-all text-right max-w-[150px]">
                      {m.data.query || m.data.dest_ip || m.data.url || 'External Host'}
                    </div>
                  </div>
                ))}
                {messages.filter(m => m.type === 'DNS_QUERY' || m.type === 'SOCKET_CONNECT' || m.type === 'HTTP_REQUEST').length === 0 && (
                  <div className="text-gray-500 italic">No network activity observed.</div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default AnalysisDetail;
