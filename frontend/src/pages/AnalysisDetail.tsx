import React, { useState } from 'react';
import { useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import gsap from 'gsap';
import { useGSAP } from '@gsap/react';
import api from '../api/client';
import { Activity, ShieldAlert, TerminalSquare, AlertTriangle, FileText, Loader2 } from 'lucide-react';
import { useWebSocket } from '../hooks/useWebSocket';
import ThreatGraph from '../components/threat/ThreatGraph';

gsap.registerPlugin(useGSAP);

const tabVariants = {
  enter: { opacity: 0, y: 12 },
  center: { opacity: 1, y: 0 },
  exit: { opacity: 0, y: -8 },
};

const AnalysisDetail: React.FC = () => {
  const container = React.useRef<HTMLDivElement>(null);
  const { jobId } = useParams<{ jobId: string }>();
  const [activeTab, setActiveTab] = useState<'overview' | 'telemetry' | 'iocs' | 'visualization' | 'debug'>('overview');

  const { data: analysis, isLoading, error } = useQuery({
    queryKey: ['analysis', jobId],
    queryFn: async () => {
      const res = await api.get(`/analysis/${jobId}`);
      return res.data;
    },
    refetchInterval: (query) => {
      const data = query.state.data as any;
      return (data?.status?.toLowerCase() === 'completed' || data?.status?.toLowerCase() === 'failed' ? false : 3000);
    },
  });

  const actualJobId = analysis?.file_id || jobId;
  const { messages, isConnected } = useWebSocket(actualJobId !== 'latest' ? `/ws/jobs/${actualJobId}/telemetry` : '');
  
  const allTelemetry = analysis?.status?.toLowerCase() === 'completed'
    ? (analysis?.telemetry_events || [])
    : messages;

  useGSAP(() => {
    if (!isLoading && !error) {
      gsap.fromTo(".gsap-header", 
        { opacity: 0, y: -20 },
        { opacity: 1, y: 0, duration: 0.8, ease: "power3.out" }
      );
    }
  }, { dependencies: [isLoading, error], scope: container });

  useGSAP(() => {
    if (!isLoading && !error) {
      gsap.fromTo(".gsap-tab-content",
        { opacity: 0, y: 20 },
        { opacity: 1, y: 0, duration: 0.6, stagger: 0.1, ease: "power3.out" }
      );
    }
  }, { dependencies: [activeTab, isLoading, error], scope: container });

  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center h-full p-8 font-mono">
        <div className="flex items-center gap-3 text-[#ffffff] text-sm font-bold tracking-widest mb-10 uppercase">
          <Loader2 className="w-5 h-5 animate-spin text-[#888888]" />
          INITIALIZING...
        </div>
        
        <div className="w-full max-w-2xl bg-[#000000] border border-[#333333] p-6 text-xs text-[#888888]">
           <div className="flex justify-between items-center mb-6 border-b border-[#333333] pb-4">
             <span className="text-[#ffffff] font-bold uppercase tracking-widest">SYSTEM_CONSOLE</span>
           </div>
           <div className="space-y-2 h-40 overflow-hidden flex flex-col justify-end">
             {[
               { t: '0.000s', text: 'SYSTEM: Booting sandbox orchestrator...', dim: true },
               { t: '0.125s', text: 'SYSTEM: Uploading artifact to secure vault...', dim: true },
               { t: '0.450s', text: 'INIT: Spawning isolation microVM...' },
               { t: '0.820s', text: 'NETWORK: Applying zero-trust egress filters...' },
               { t: '1.050s', text: 'STATIC: Extracting hashes and metadata...' },
               { t: '1.240s', text: 'RUNTIME: Hooking syscalls (eBPF)...' },
             ].map((line, i) => (
               <div key={i} className={line.dim ? 'text-[#444444]' : 'text-[#ffffff]'}>
                 <span className="text-[#666666]">[{line.t}]</span> {line.text}
               </div>
             ))}
           </div>
        </div>
      </div>
    );
  }

  if (error) return <div className="text-[#ffffff] bg-[#000000] border border-[#ffffff] p-8 font-mono font-bold text-sm uppercase">ERROR LOADING ANALYSIS DATA.</div>;

  return (
    <div ref={container} className="space-y-8 flex flex-col max-w-[1400px] mx-auto">
      {/* Header Panel */}
      <div className="gsap-header p-8 border border-[#333333] bg-[#000000] flex flex-col md:flex-row items-start md:items-center justify-between gap-6 shrink-0">
        <div>
          <div className="flex items-center gap-4 mb-2">
             <div className="w-12 h-12 border border-[#ffffff] flex items-center justify-center text-[#ffffff]">
               <ShieldAlert className="w-6 h-6" />
             </div>
             <h2 className="text-3xl font-heading font-bold tracking-tighter uppercase">{analysis?.filename}</h2>
          </div>
          <div className="flex items-center gap-3 text-[11px] font-mono font-bold text-[#888888] ml-16 mt-3 uppercase tracking-widest">
            <span>ID: {jobId}</span>
          </div>
        </div>
        
        <div className="flex items-center space-x-10 ml-16 md:ml-0 border-t md:border-t-0 border-[#333333] pt-6 md:pt-0 w-full md:w-auto">
          <div className="text-right">
            <div className="text-[10px] font-mono font-bold text-[#888888] uppercase tracking-widest mb-2">Risk Score</div>
            <div className={`text-5xl font-heading font-bold tracking-tighter ${(analysis?.risk_score || 0) >= 50 ? 'text-red-500' : 'text-emerald-500'}`}>
              {analysis?.risk_score || '--'}<span className="text-lg text-[#666666] font-normal no-underline">/100</span>
            </div>
          </div>
          <div className="h-16 w-px bg-[#333333]"></div>
          <div>
            <div className="text-[10px] font-mono font-bold text-[#888888] uppercase tracking-widest mb-2">Status</div>
            <div className={`text-sm font-mono font-bold px-4 py-2 border uppercase tracking-widest ${
              analysis?.status?.toLowerCase() === 'analyzing' ? 'bg-[#ffffff] text-[#000000] border-[#ffffff]' :
              analysis?.status?.toLowerCase() === 'completed' ? 'bg-transparent text-[#ffffff] border-[#888888]' :
              'bg-transparent text-[#ffffff] border-[#ffffff]'
            }`}>
              {analysis?.status || 'UNKNOWN'}
            </div>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-[#333333] shrink-0">
        {['overview', 'telemetry', 'iocs', 'visualization', 'debug'].map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab as any)}
            className={`relative px-8 py-4 text-xs font-mono font-bold uppercase tracking-widest transition-colors ${
              activeTab === tab ? 'text-[#ffffff]' : 'text-[#666666] hover:text-[#ffffff] hover:bg-[#111111]'
            }`}
          >
            {tab}
            {activeTab === tab && (
              <div className="absolute bottom-0 left-0 right-0 h-1 bg-[#ffffff]" />
            )}
          </button>
        ))}
      </div>

      {/* Content Area */}
      <div className="flex-1 pb-8">
          {activeTab === 'overview' && (
            <div key="overview" className="grid grid-cols-1 lg:grid-cols-3 gap-8">
              
              <div className="lg:col-span-2 space-y-8">
                <div className="gsap-tab-content p-8 border border-[#333333] bg-[#000000]">
                  <h3 className={`text-sm font-heading font-bold uppercase tracking-widest mb-6 flex items-center gap-3 ${
                    (analysis?.risk_score || 0) >= 50 ? 'text-red-500' : 'text-emerald-500'
                  }`}>
                    <Activity size={18} />
                    AI Threat Summary
                  </h3>
                  <p className="text-[#cccccc] leading-relaxed text-sm font-sans">
                    {analysis?.ai_summary || 'WAITING FOR AI ANALYSIS TO COMPLETE...'}
                  </p>
                </div>

                <div className="gsap-tab-content p-8 border border-[#333333] bg-[#000000]">
                  <h3 className="text-sm font-heading font-bold uppercase tracking-widest text-[#ffffff] mb-6 flex items-center gap-3">
                    <ShieldAlert size={18} />
                    MITRE ATT&CK Mappings
                  </h3>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                     {analysis?.mitre_tactics?.length > 0 ? analysis.mitre_tactics.map((tactic: any, idx: number) => (
                       <div key={idx} className="border border-[#222222] bg-[#111111] p-4 flex items-center gap-4 transition-colors hover:border-[#ffffff]">
                         <div className="text-[#ffffff] font-mono text-xs font-bold shrink-0">{tactic.id}</div>
                         <div className="text-sm text-[#888888] font-sans">{tactic.name}</div>
                       </div>
                     )) : (
                       <div className="text-[#666666] font-mono text-xs uppercase italic col-span-2 p-6 border border-[#222222] text-center">NO TACTICS MAPPED YET.</div>
                     )}
                  </div>
                </div>
              </div>
              
              <div className="space-y-8">
                <div className="gsap-tab-content p-8 border border-[#333333] bg-[#000000]">
                  <h3 className="text-sm font-heading font-bold uppercase tracking-widest text-[#ffffff] mb-6 flex items-center gap-3">
                    <FileText size={18} />
                    File Metadata
                  </h3>
                  <div className="space-y-6">
                    {[
                      { label: 'SHA256', value: analysis?.metadata?.artifact_sha256 },
                      { label: 'MD5', value: analysis?.metadata?.md5 },
                      { label: 'File Size', value: analysis?.metadata?.size_bytes ? `${(analysis.metadata.size_bytes / 1024).toFixed(2)} KB` : null },
                      { label: 'Entropy', value: analysis?.metadata?.entropy ? analysis.metadata.entropy.toFixed(2) : null },
                    ].map((item, i) => (
                      <div key={item.label} className="flex flex-col">
                        <span className="text-[10px] font-mono font-bold text-[#666666] uppercase tracking-widest mb-2">{item.label}</span>
                        <span className="text-xs text-[#ffffff] font-mono break-all">
                          {item.value || 'N/A'}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

            </div>
          )}

          {activeTab === 'telemetry' && (
            <div key="telemetry" className="gsap-tab-content h-[700px] flex flex-col p-6 border border-[#333333] bg-[#000000]">
              <div className="flex justify-between items-center mb-6 border-b border-[#333333] pb-4 shrink-0">
                <h3 className="font-mono font-bold text-xs flex items-center text-[#ffffff] uppercase tracking-widest">
                  <TerminalSquare className="w-5 h-5 mr-3" />
                  LIVE EVENT STREAM
                </h3>
                <div className="text-xs font-mono font-bold uppercase tracking-widest">
                  {isConnected ? <span className="text-[#ffffff]">CONNECTED</span> : <span className="text-[#666666]">CONNECTING...</span>}
                </div>
              </div>
              <div className="flex-1 overflow-auto font-mono text-[11px] space-y-2 p-4 border border-[#222222] bg-[#111111] custom-scrollbar">
                {allTelemetry.length === 0 && (
                  <div className="text-[#666666] uppercase text-center py-10">WAITING FOR TELEMETRY DATA STREAM...</div>
                )}
                {allTelemetry.map((msg: any, i: number) => {
                  const formatTelemetryData = (data: any) => {
                    if (typeof data === 'object' && data !== null) {
                      if (typeof data.output === 'string' && data.output.includes('<Objs Version=')) {
                        try {
                          const textNodes = data.output.match(/>([^<]+)</g);
                          if (textNodes) {
                             let extracted = textNodes.map((n: string) => n.slice(1, -1)).join('');
                             extracted = extracted.replace(/_x([0-9A-Fa-f]{4})_/g, (_: any, hex: string) => String.fromCharCode(parseInt(hex, 16)));
                             // Clean up the object prefixes
                             extracted = extracted.replace(/System\.Management\.Automation\.PSCustomObjectSystem\.Object.*?Preparing modules for first use\./g, '');
                             return JSON.stringify({ ...data, output: `[PowerShell CLIXML] ${extracted.trim()}` });
                          }
                        } catch (e) {}
                      }
                      return JSON.stringify(data);
                    }
                    return String(data);
                  };

                  return (
                    <div key={i} className="flex items-start hover:bg-[#222222] transition-colors p-1" >
                      <span className="text-[#666666] mr-4 shrink-0">[{msg.timestamp ? new Date(msg.timestamp).toISOString().split('T')[1].split('.')[0] : new Date().toISOString().split('T')[1].split('.')[0]}]</span>
                      <span className={`font-bold mr-4 shrink-0 w-[140px] ${msg.severity === 'high' ? 'text-[#ffffff] underline' : 'text-[#ffffff]'}`}>{msg.type}</span>
                      <span className="text-[#aaaaaa] break-all">{formatTelemetryData(msg.data)}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {activeTab === 'iocs' && (
            <div key="iocs" className="gsap-tab-content grid grid-cols-1 lg:grid-cols-3 gap-8">
              <div className="lg:col-span-2 p-8 border border-[#333333] bg-[#000000]">
                <h3 className="text-sm font-heading font-bold uppercase tracking-widest text-[#ffffff] mb-6 flex items-center gap-3">
                  <ShieldAlert size={18} />
                  Indicators of Compromise
                </h3>
                <div className="overflow-x-auto border border-[#333333]">
                  <table className="w-full text-left border-collapse font-mono">
                    <thead className="bg-[#111111] text-[#888888]">
                      <tr>
                        <th className="py-4 px-6 font-bold uppercase tracking-widest text-[10px]">Type</th>
                        <th className="py-4 px-6 font-bold uppercase tracking-widest text-[10px]">Value</th>
                        <th className="py-4 px-6 font-bold uppercase tracking-widest text-[10px]">Source</th>
                        <th className="py-4 px-6 font-bold uppercase tracking-widest text-[10px] text-right">Confidence</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#222222] text-xs">
                      {analysis?.iocs?.length > 0 ? analysis.iocs.map((ioc: any, idx: number) => (
                        <tr key={idx} className="hover:bg-[#111111] transition-colors">
                          <td className="py-4 px-6 font-bold text-[#ffffff] uppercase">{ioc.type}</td>
                          <td className="py-4 px-6 text-[#cccccc] break-all">{ioc.value}</td>
                          <td className="py-4 px-6 text-[#666666]">{ioc.source}</td>
                          <td className="py-4 px-6 text-right">
                             <span className={`px-3 py-1 font-bold uppercase tracking-widest border ${
                               ioc.confidence === 'High' ? 'border-[#ffffff] text-[#000000] bg-[#ffffff]' :
                               'border-[#444444] text-[#ffffff] bg-transparent'
                             }`}>
                               {ioc.confidence || 'MEDIUM'}
                             </span>
                          </td>
                        </tr>
                      )) : (
                        <tr><td colSpan={4} className="py-12 text-center text-[#666666] uppercase tracking-widest">No indicators extracted yet.</td></tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

              <div className="p-8 border border-[#333333] bg-[#000000]">
                <h3 className="text-sm font-heading font-bold uppercase tracking-widest text-[#ffffff] mb-6 flex items-center gap-3">
                  <AlertTriangle size={18} />
                  YARA Matches
                </h3>
                <div className="space-y-4">
                  {analysis?.yara_matches?.length > 0 ? analysis.yara_matches.map((yara: string, idx: number) => (
                    <div key={idx} className="bg-[#111111] p-4 border border-[#333333] font-mono text-[11px] text-[#ffffff] font-bold">
                      {yara}
                    </div>
                  )) : (
                    <div className="text-[#666666] font-mono text-xs uppercase p-6 border border-[#222222] text-center">No YARA matches found.</div>
                  )}
                </div>
              </div>
            </div>
          )}

          {activeTab === 'visualization' && (
             <div className="gsap-tab-content border border-[#333333]">
                <ThreatGraph jobId={actualJobId} />
             </div>
          )}

          {activeTab === 'debug' && (
            <div key="debug" className="gsap-tab-content h-[700px] flex flex-col p-6 border border-[#333333] bg-[#000000]">
              <div className="flex items-center justify-between border-b border-[#333333] pb-4 mb-4 shrink-0">
                <div className="flex items-center text-[#ffffff] font-mono font-bold uppercase tracking-widest text-xs">
                  <TerminalSquare className="w-5 h-5 mr-3" />
                  BACKEND DEBUG CONSOLE
                </div>
                <div className="text-[#666666] font-mono text-[10px] uppercase">syslog // {jobId}</div>
              </div>
              <div className="flex-1 overflow-auto space-y-2 p-4 border border-[#222222] bg-[#111111] font-mono text-[11px] custom-scrollbar">
                {(!analysis?.logs || analysis.logs.length === 0) ? (
                  <div className="text-[#666666] uppercase text-center py-10">NO LOGS RECORDED YET...</div>
                ) : (
                  analysis.logs.map((log: any, idx: number) => (
                    <div key={idx} className="flex hover:bg-[#222222] px-2 py-1 transition-colors">
                      <span className="text-[#666666] mr-6 whitespace-nowrap shrink-0">
                        [{log.ts ? new Date(log.ts).toISOString().split('T')[1].split('Z')[0] : '00:00:00.000'}]
                      </span>
                      <span className={`${log.message.includes('ERROR') ? 'text-[#ffffff] font-bold underline' : 'text-[#aaaaaa]'}`}>
                        {log.message}
                      </span>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}
      </div>
    </div>
  );
};

export default AnalysisDetail;
