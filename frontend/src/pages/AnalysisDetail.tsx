import React, { useState } from 'react';
import { useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { motion, AnimatePresence } from 'framer-motion';
import api from '../api/client';
import { Activity, ShieldAlert, TerminalSquare, AlertTriangle, ChevronRight, FileText } from 'lucide-react';
import { useWebSocket } from '../hooks/useWebSocket';
import { staggerContainer, fadeInUp } from '../components/ui/animations';

const tabVariants = {
  enter: { opacity: 0, y: 12 },
  center: { opacity: 1, y: 0 },
  exit: { opacity: 0, y: -8 },
};

const AnalysisDetail: React.FC = () => {
  const { jobId } = useParams<{ jobId: string }>();
  const [activeTab, setActiveTab] = useState<'overview' | 'telemetry' | 'iocs' | 'visualization' | 'debug'>('overview');

  const { data: analysis, isLoading, error } = useQuery({
    queryKey: ['analysis', jobId],
    queryFn: async () => {
      const res = await api.get(`/analysis/${jobId}`);
      return res.data;
    },
    refetchInterval: (data) => (data?.status?.toLowerCase() === 'completed' || data?.status?.toLowerCase() === 'failed' ? false : 3000),
  });

  const actualJobId = analysis?.file_id || jobId;

  const { messages, isConnected } = useWebSocket(actualJobId !== 'latest' ? `/ws/jobs/${actualJobId}/telemetry` : '');
  
  // To avoid race conditions where the backend finishes before the WebSocket connects,
  // we rely on the DB's full telemetry array once the job is marked 'completed'.
  // While 'analyzing', we display live WebSocket messages.
  const allTelemetry = analysis?.status?.toLowerCase() === 'completed'
    ? (analysis?.telemetry_events || [])
    : messages;

  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center h-full p-8 font-mono">
        <div className="relative w-24 h-24 mb-8">
           <motion.div className="absolute inset-0 border-2 border-gray-100 border-t-[#c5f37d] rounded-full" animate={{ rotate: 360 }} transition={{ duration: 1.2, repeat: Infinity, ease: 'linear' }} />
           <motion.div className="absolute inset-2 border-2 border-gray-100 border-b-gray-400 rounded-full" animate={{ rotate: -360 }} transition={{ duration: 1.8, repeat: Infinity, ease: 'linear' }} />
           <div className="absolute inset-0 flex items-center justify-center text-[#7fb827]">
              <motion.div animate={{ scale: [1, 1.1, 1] }} transition={{ duration: 1.5, repeat: Infinity, ease: 'easeInOut' }}>
                <Activity className="w-6 h-6" />
              </motion.div>
           </div>
        </div>
        <div className="text-gray-500 text-sm font-medium tracking-widest mb-6 uppercase">Initializing Analysis</div>
        
        <div className="w-full max-w-2xl bg-gray-50 border border-gray-200 rounded-xl p-5 text-xs text-gray-700 font-mono shadow-sm">
           <div className="flex justify-between items-center mb-3 border-b border-gray-200 pb-3">
             <span className="text-gray-500 font-semibold">System Console</span>
             <span className="flex space-x-1.5">
               <span className="w-2.5 h-2.5 bg-gray-300 rounded-full"></span>
               <span className="w-2.5 h-2.5 bg-gray-300 rounded-full"></span>
               <motion.span className="w-2.5 h-2.5 bg-green-500 rounded-full" animate={{ opacity: [1, 0.4, 1] }} transition={{ duration: 1, repeat: Infinity }} />
             </span>
           </div>
           <div className="space-y-1.5 h-32 overflow-hidden flex flex-col justify-end">
             {[
               { t: '0.000s', text: 'SYSTEM: Booting sandbox orchestrator...', dim: true },
               { t: '0.125s', text: 'SYSTEM: Uploading artifact to secure vault...', dim: true },
               { t: '0.450s', text: 'INIT: Spawning isolation microVM...' },
               { t: '0.820s', text: 'NETWORK: Applying zero-trust egress filters...' },
               { t: '1.050s', text: 'STATIC: Extracting hashes and metadata...' },
               { t: '1.240s', text: 'RUNTIME: Hooking syscalls (eBPF)...' },
             ].map((line, i) => (
               <motion.div key={i} className={line.dim ? 'text-gray-400' : ''} initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.5 + i * 0.15, duration: 0.3 }}>
                 [{line.t}] {line.text}
               </motion.div>
             ))}
           </div>
        </div>
      </div>
    );
  }

  if (error) return <div className="text-red-500 p-8 font-medium">Error loading analysis data.</div>;

  return (
    <motion.div className="space-y-6 h-full flex flex-col max-w-7xl mx-auto" initial={{ opacity: 0, y: 18 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -12 }} transition={{ duration: 0.4, ease: [0.25, 0.46, 0.45, 0.94] }}>
      {/* Header Panel */}
      <div className="ui-panel p-6 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-3 mb-1">
             <div className="w-10 h-10 rounded-xl bg-red-50 flex items-center justify-center text-red-500 border border-red-100">
               <ShieldAlert className="w-5 h-5" />
             </div>
             <h2 className="text-2xl font-bold text-gray-900">Analysis Report</h2>
          </div>
          <div className="flex items-center gap-2 text-sm text-gray-500 ml-13 mt-2">
            <span className="font-semibold text-gray-900">{analysis?.filename}</span>
            <span>•</span>
            <span className="font-mono bg-gray-50 px-2 py-0.5 rounded text-xs border border-gray-200">ID: {jobId}</span>
          </div>
        </div>
        
        <div className="flex items-center space-x-6 ml-13 md:ml-0 border-t md:border-t-0 border-gray-100 pt-4 md:pt-0 w-full md:w-auto">
          <div className="text-right">
            <div className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-1">AI Risk Score</div>
            <div className={`text-3xl font-bold ${analysis?.risk_score >= 70 ? 'text-red-600' : analysis?.risk_score > 0 ? 'text-gray-900' : 'text-gray-400'}`}>
              {analysis?.risk_score || '--'}<span className="text-lg text-gray-400 font-normal">/100</span>
            </div>
          </div>
          <div className="h-10 w-px bg-gray-200"></div>
          <div>
            <div className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-1">Status</div>
            <div className={`text-sm font-semibold px-3 py-1 rounded-lg border ${
              analysis?.status?.toLowerCase() === 'analyzing' ? 'bg-yellow-50 text-yellow-700 border-yellow-200' :
              analysis?.status?.toLowerCase() === 'completed' ? 'bg-[#c5f37d]/40 text-gray-900 border-[#c5f37d]/60' :
              'bg-gray-100 text-gray-500 border-gray-200'
            }`}>
              {analysis?.status?.charAt(0).toUpperCase() + analysis?.status?.slice(1).toLowerCase() || 'Unknown'}
            </div>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex space-x-2 border-b border-gray-200 px-2">
        {['overview', 'telemetry', 'iocs', 'visualization', 'debug'].map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab as any)}
            className={`relative px-5 py-3 text-sm font-semibold capitalize transition-colors ${
              activeTab === tab ? 'text-gray-900' : 'text-gray-500 hover:text-gray-700 hover:bg-gray-50 rounded-t-lg'
            }`}
          >
            {tab}
            {activeTab === tab && (
              <motion.div className="absolute bottom-0 left-0 right-0 h-0.5 bg-[#c5f37d]" layoutId="activeTabIndicator" transition={{ type: 'spring', stiffness: 500, damping: 30 }} />
            )}
          </button>
        ))}
      </div>

      {/* Content Area */}
      <div className="flex-1 overflow-auto pb-6">
        <AnimatePresence mode="wait">
          {activeTab === 'overview' && (
            <motion.div key="overview" className="grid grid-cols-1 lg:grid-cols-3 gap-6" variants={tabVariants} initial="enter" animate="center" exit="exit" transition={{ duration: 0.3 }}>
              
              <div className="lg:col-span-2 space-y-6">
                <motion.div className="ui-panel p-6" variants={fadeInUp}>
                  <h3 className="text-sm font-bold text-gray-900 mb-4 flex items-center gap-2">
                    <Activity className="w-5 h-5 text-[#7fb827]" />
                    AI Threat Summary
                  </h3>
                  <p className="text-gray-600 leading-relaxed text-sm bg-gray-50 p-4 rounded-xl border border-gray-100">
                    {analysis?.ai_summary || 'Waiting for AI analysis to complete...'}
                  </p>
                </motion.div>

                <motion.div className="ui-panel p-6" variants={fadeInUp}>
                  <h3 className="text-sm font-bold text-gray-900 mb-4 flex items-center gap-2">
                    <ShieldAlert className="w-5 h-5 text-red-500" />
                    MITRE ATT&CK Mappings
                  </h3>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                     {analysis?.mitre_tactics?.length > 0 ? analysis.mitre_tactics.map((tactic: any, idx: number) => (
                       <div key={idx} className="bg-white border border-gray-200 p-3 rounded-xl flex items-start gap-3 shadow-sm hover:shadow-md transition-shadow">
                         <div className="bg-red-50 text-red-600 font-mono text-xs px-2 py-1 rounded border border-red-100 font-bold mt-0.5">{tactic.id}</div>
                         <div className="text-sm text-gray-800 font-medium">{tactic.name}</div>
                       </div>
                     )) : (
                       <div className="text-gray-500 text-sm italic col-span-2 p-4 bg-gray-50 rounded-xl border border-gray-100 text-center">No tactics mapped yet.</div>
                     )}
                  </div>
                </motion.div>
              </div>
              
              <div className="space-y-6">
                <motion.div className="ui-panel p-6" initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.2, duration: 0.4 }}>
                  <h3 className="text-sm font-bold text-gray-900 mb-4 flex items-center gap-2">
                    <FileText className="w-5 h-5 text-gray-400" />
                    File Metadata
                  </h3>
                  <div className="space-y-4">
                    {[
                      { label: 'SHA256', value: analysis?.metadata?.artifact_sha256 },
                      { label: 'MD5', value: analysis?.metadata?.md5 },
                      { label: 'File Size', value: analysis?.metadata?.size_bytes ? `${(analysis.metadata.size_bytes / 1024).toFixed(2)} KB` : null },
                      { label: 'Entropy', value: analysis?.metadata?.entropy ? analysis.metadata.entropy.toFixed(2) : null },
                    ].map((item, i) => (
                      <div key={item.label} className="flex flex-col">
                        <span className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-1">{item.label}</span>
                        <span className="text-sm text-gray-900 font-mono bg-gray-50 p-2 rounded-lg border border-gray-100 break-all">
                          {item.value || 'N/A'}
                        </span>
                      </div>
                    ))}
                  </div>
                </motion.div>
              </div>

            </motion.div>
          )}

          {activeTab === 'telemetry' && (
            <motion.div key="telemetry" className="ui-panel h-[600px] flex flex-col p-4 bg-gray-900 text-gray-100" variants={tabVariants} initial="enter" animate="center" exit="exit" transition={{ duration: 0.3 }}>
              <div className="flex justify-between items-center mb-3 border-b border-gray-800 pb-3">
                <h3 className="font-mono text-xs flex items-center text-gray-400">
                  <TerminalSquare className="w-4 h-4 mr-2" />
                  LIVE EVENT STREAM {isConnected ? '(CONNECTED)' : '(CONNECTING...)'}
                </h3>
                <div className="flex space-x-2">
                  <motion.span className="w-2.5 h-2.5 rounded-full bg-green-500" animate={{ opacity: [1, 0.4, 1] }} transition={{ duration: 1.5, repeat: Infinity }} />
                </div>
              </div>
              <div className="flex-1 overflow-auto font-mono text-xs space-y-1.5 p-2 rounded bg-black/40">
                {allTelemetry.length === 0 && (
                  <div className="text-gray-500 italic p-4 text-center">Waiting for telemetry data stream...</div>
                )}
                {allTelemetry.map((msg, i) => (
                  <div key={i} className={`border-l-2 pl-3 py-1.5 hover:bg-gray-800/50 transition-colors ${
                      msg.severity === 'high' ? 'border-red-500 bg-red-500/5' :
                      msg.severity === 'medium' ? 'border-yellow-500 bg-yellow-500/5' :
                      'border-blue-500 bg-blue-500/5'
                    }`}
                  >
                    <span className="text-gray-500 mr-2">[{msg.timestamp ? new Date(msg.timestamp).toISOString().split('T')[1].split('.')[0] : new Date().toISOString().split('T')[1].split('.')[0]}]</span>
                    <span className={`font-bold mr-2 ${
                      msg.severity === 'high' ? 'text-red-400' :
                      msg.severity === 'medium' ? 'text-yellow-400' :
                      'text-blue-400'
                    }`}>{msg.type}</span>
                    <span className="text-gray-300 break-all">{typeof msg.data === 'object' ? JSON.stringify(msg.data) : msg.data}</span>
                  </div>
                ))}
              </div>
            </motion.div>
          )}

          {activeTab === 'iocs' && (
            <motion.div key="iocs" className="grid grid-cols-1 lg:grid-cols-3 gap-6" variants={tabVariants} initial="enter" animate="center" exit="exit" transition={{ duration: 0.3 }}>
              <div className="lg:col-span-2 ui-panel p-6">
                <h3 className="text-sm font-bold text-gray-900 mb-4 flex items-center gap-2">
                  <ShieldAlert className="w-5 h-5 text-red-500" />
                  Indicators of Compromise
                </h3>
                <div className="overflow-x-auto border border-gray-100 rounded-xl">
                  <table className="w-full text-left text-sm border-collapse">
                    <thead className="bg-gray-50 text-gray-500 border-b border-gray-100">
                      <tr>
                        <th className="py-3 px-4 font-semibold uppercase tracking-wider text-xs">Type</th>
                        <th className="py-3 px-4 font-semibold uppercase tracking-wider text-xs">Value</th>
                        <th className="py-3 px-4 font-semibold uppercase tracking-wider text-xs">Source</th>
                        <th className="py-3 px-4 font-semibold uppercase tracking-wider text-xs text-right">Confidence</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-50">
                      {analysis?.iocs?.length > 0 ? analysis.iocs.map((ioc: any, idx: number) => (
                        <tr key={idx} className="hover:bg-gray-50/50 transition-colors">
                          <td className="py-3 px-4 font-bold text-gray-900 uppercase text-xs">{ioc.type}</td>
                          <td className="py-3 px-4 text-gray-600 font-mono text-xs break-all">{ioc.value}</td>
                          <td className="py-3 px-4 text-gray-500 text-xs">{ioc.source}</td>
                          <td className="py-3 px-4 text-right">
                             <span className={`px-2.5 py-1 rounded-md text-xs font-semibold ${
                               ioc.confidence === 'High' ? 'bg-red-50 text-red-700 border border-red-100' :
                               ioc.confidence === 'Medium' ? 'bg-orange-50 text-orange-700 border border-orange-100' :
                               'bg-gray-100 text-gray-600 border border-gray-200'
                             }`}>
                               {ioc.confidence || 'Medium'}
                             </span>
                          </td>
                        </tr>
                      )) : (
                        <tr><td colSpan={4} className="py-8 text-center text-gray-500 italic">No indicators extracted yet.</td></tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

              <div className="ui-panel p-6">
                <h3 className="text-sm font-bold text-gray-900 mb-4 flex items-center gap-2">
                  <AlertTriangle className="w-5 h-5 text-orange-500" />
                  YARA Matches
                </h3>
                <div className="space-y-3">
                  {analysis?.yara_matches?.length > 0 ? analysis.yara_matches.map((yara: string, idx: number) => (
                    <div key={idx} className="bg-orange-50 p-3 rounded-lg border border-orange-100 font-mono text-xs text-orange-800 font-semibold shadow-sm">
                      {yara}
                    </div>
                  )) : (
                    <div className="text-gray-500 text-sm bg-gray-50 p-4 rounded-xl border border-gray-100 text-center">No YARA matches found.</div>
                  )}
                </div>
              </div>
            </motion.div>
          )}

          {activeTab === 'visualization' && (
            <motion.div key="visualization" className="grid grid-cols-1 lg:grid-cols-2 gap-6 h-full" variants={tabVariants} initial="enter" animate="center" exit="exit" transition={{ duration: 0.3 }}>
              {/* Sandbox Lifecycle */}
              <div className="ui-panel p-6 col-span-1 lg:col-span-2">
                <h3 className="text-sm font-bold text-gray-900 mb-6">Sandbox Execution Timeline</h3>
                <div className="flex items-center bg-white p-6 rounded-xl border border-gray-100 shadow-sm relative overflow-x-auto">
                  {/* Background Track */}
                  <div className="absolute left-10 right-10 top-1/2 -translate-y-1/2 h-1 bg-gray-100 rounded-full z-0"></div>
                  
                  <div className="flex w-full justify-between min-w-max gap-8 px-4">
                    {allTelemetry.length === 0 ? (
                      <div className="relative z-10 flex flex-col items-center flex-1">
                        <div className="w-6 h-6 rounded-full mb-3 flex items-center justify-center border-4 border-white shadow-sm bg-gray-200"></div>
                        <div className="text-xs font-semibold text-gray-400">Waiting for events...</div>
                      </div>
                    ) : (
                      allTelemetry.map((msg: any, i: number) => (
                        <div key={i} className="relative z-10 flex flex-col items-center flex-1">
                          <div className={`w-6 h-6 rounded-full mb-3 flex items-center justify-center border-4 border-white shadow-sm transition-colors duration-500 ${
                            msg.severity === 'high' ? 'bg-red-500' : 'bg-[#7fb827]'
                          }`}>
                            <div className="w-1.5 h-1.5 bg-white rounded-full"></div>
                          </div>
                          <div className="text-xs font-semibold text-gray-900 truncate max-w-[120px]" title={msg.type}>{msg.type}</div>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              </div>

              {/* Process Tree */}
              <div className="ui-panel p-6">
                <h3 className="text-sm font-bold text-gray-900 mb-4">Process Ancestry</h3>
                <div className="bg-gray-50 rounded-xl border border-gray-100 p-4 font-mono text-xs overflow-auto max-h-[300px]">
                  <div className="flex items-center text-gray-700 font-semibold mb-2"><Activity className="w-4 h-4 mr-2 text-gray-400" /> [1000] python.exe (sandbox_runner)</div>
                  {allTelemetry.filter((m: any) => m.type === 'PROCESS_CREATE').map((m: any, i: number) => (
                    <div key={i} className="pl-6 flex items-center border-l-2 border-gray-200 ml-2 py-1.5 group hover:bg-white hover:shadow-sm rounded transition-all">
                      <div className="w-4 h-px bg-gray-300 mr-2"></div>
                      <TerminalSquare className="w-3.5 h-3.5 mr-2 text-red-500" /> 
                      <span className="text-red-600 font-bold mr-2 bg-red-50 px-1 rounded">[{m.data.pid || 'NEW'}]</span> 
                      <span className="text-gray-800">{m.data.cmdline}</span>
                    </div>
                  ))}
                  {allTelemetry.filter((m: any) => m.type === 'PROCESS_CREATE').length === 0 && (
                     <div className="pl-6 text-gray-400 italic py-2">No child processes observed.</div>
                  )}
                </div>
              </div>

              {/* Network Graph */}
              <div className="ui-panel p-6">
                <h3 className="text-sm font-bold text-gray-900 mb-4">Network Communications</h3>
                <div className="bg-gray-50 rounded-xl border border-gray-100 p-4 font-mono text-xs overflow-auto max-h-[300px]">
                  {allTelemetry.filter((m: any) => m.type === 'DNS_QUERY' || m.type === 'SOCKET_CONNECT' || m.type === 'HTTP_REQUEST').length === 0 ? (
                    <div className="text-gray-500 italic py-2 text-center">No network activity recorded.</div>
                  ) : (
                    <>
                      <div className="flex items-center text-gray-700 font-semibold mb-2">
                        <Activity className="w-4 h-4 mr-2 text-gray-400" /> [1000] python.exe (sandbox_runner)
                      </div>
                      <div className="ml-2 border-l-2 border-gray-200">
                        {allTelemetry.filter((m: any) => m.type === 'DNS_QUERY').map((dns: any, i: number) => (
                           <div key={`dns-${i}`} className="pl-6 flex items-center py-1.5 group hover:bg-white hover:shadow-sm rounded transition-all">
                             <div className="w-4 h-px bg-gray-300 mr-2 -ml-6"></div>
                             <span className="text-blue-600 font-bold mr-2 bg-blue-50 px-1 rounded text-[10px]">DNS</span>
                             <span className="text-gray-800 font-semibold">{dns.data.query}</span>
                           </div>
                        ))}
                        <div className={allTelemetry.some((m: any) => m.type === 'DNS_QUERY') ? "ml-8 border-l-2 border-gray-200" : ""}>
                          {allTelemetry.filter((m: any) => m.type === 'SOCKET_CONNECT' || m.type === 'HTTP_REQUEST').map((sock: any, i: number) => (
                             <div key={`sock-${i}`} className="pl-6 flex items-center py-1.5 group hover:bg-white hover:shadow-sm rounded transition-all">
                               <div className="w-4 h-px bg-gray-300 mr-2 -ml-6"></div>
                               <span className="text-green-600 font-bold mr-2 bg-green-50 px-1 rounded text-[10px]">CONN</span>
                               <span className="text-gray-800">{sock.data.dest_ip || sock.data.url}:{sock.data.dest_port || 80}</span>
                             </div>
                          ))}
                        </div>
                      </div>
                    </>
                  )}
                </div>
              </div>
            </motion.div>
          )}

          {activeTab === 'debug' && (
            <motion.div key="debug" className="ui-panel h-[600px] flex flex-col p-4 bg-[#0d1117] text-gray-100 font-mono text-xs shadow-inner" variants={tabVariants} initial="enter" animate="center" exit="exit" transition={{ duration: 0.3 }}>
              <div className="flex items-center justify-between border-b border-gray-800 pb-3 mb-3">
                <div className="flex items-center text-gray-400 uppercase tracking-widest font-semibold">
                  <TerminalSquare className="w-4 h-4 mr-2" />
                  Backend Debug Console
                </div>
                <div className="text-gray-600">syslog // {jobId}</div>
              </div>
              <div className="flex-1 overflow-auto space-y-1 p-2 rounded bg-[#010409]">
                {(!analysis?.logs || analysis.logs.length === 0) ? (
                  <div className="text-gray-500 italic p-4 text-center">No logs recorded yet...</div>
                ) : (
                  analysis.logs.map((log: any, idx: number) => (
                    <div key={idx} className="flex hover:bg-gray-800/40 px-2 py-0.5 rounded transition-colors">
                      <span className="text-gray-500 mr-4 whitespace-nowrap">
                        [{log.ts ? new Date(log.ts).toISOString().split('T')[1].split('Z')[0] : '00:00:00.000'}]
                      </span>
                      <span className={`${log.message.includes('ERROR') ? 'text-red-400 font-bold' : log.message.includes('Orchestrator') ? 'text-blue-300' : 'text-gray-300'}`}>
                        {log.message}
                      </span>
                    </div>
                  ))
                )}
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </motion.div>
  );
};

export default AnalysisDetail;
