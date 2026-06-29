import React, { useState, useEffect, useRef } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import gsap from 'gsap';
import { useGSAP } from '@gsap/react';
import Lenis from 'lenis';
import { Briefcase, FileText, Pin, Plus, Upload, Search, ShieldAlert, Activity, ExternalLink, Loader2 } from 'lucide-react';
import api from '../api/client';

gsap.registerPlugin(useGSAP);

interface AnalysisJob {
  id: string;
  filename: string;
  status: string;
  risk_score: number;
  created_at: string;
}

export const Workspace: React.FC = () => {
  const container = useRef<HTMLDivElement>(null);
  const detailContainer = useRef<HTMLDivElement>(null);
  
  const [jobs, setJobs] = useState<AnalysisJob[]>([]);
  const [selectedJob, setSelectedJob] = useState<any | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const [isLoadingJobs, setIsLoadingJobs] = useState(true);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();
  const location = useLocation();

  const searchParams = new URLSearchParams(location.search);
  const searchQuery = searchParams.get('q') || '';
  const [localSearch, setLocalSearch] = useState(searchQuery);

  const listScrollRef = useRef<HTMLDivElement>(null);
  const detailScrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    // Initialize Lenis for the left panel
    let lenisList: Lenis | null = null;
    if (listScrollRef.current) {
      lenisList = new Lenis({
        wrapper: listScrollRef.current,
        content: listScrollRef.current.firstElementChild as HTMLElement,
        duration: 1.2,
        easing: (t) => Math.min(1, 1.001 - Math.pow(2, -10 * t)),
      });
      const rafList = (time: number) => { lenisList?.raf(time); requestAnimationFrame(rafList); };
      requestAnimationFrame(rafList);
    }

    // Initialize Lenis for the right panel
    let lenisDetail: Lenis | null = null;
    if (detailScrollRef.current) {
      lenisDetail = new Lenis({
        wrapper: detailScrollRef.current,
        content: detailScrollRef.current.firstElementChild as HTMLElement,
        duration: 1.2,
        easing: (t) => Math.min(1, 1.001 - Math.pow(2, -10 * t)),
      });
      const rafDetail = (time: number) => { lenisDetail?.raf(time); requestAnimationFrame(rafDetail); };
      requestAnimationFrame(rafDetail);
    }

    return () => {
      lenisList?.destroy();
      lenisDetail?.destroy();
    };
  }, [selectedJob, jobs.length]);

  const fetchJobs = async () => {
    setIsLoadingJobs(true);
    try {
      const endpoint = searchQuery ? `/workspace/jobs?q=${encodeURIComponent(searchQuery)}` : '/workspace/jobs';
      const response = await api.get(endpoint);
      setJobs(response.data || []);
    } catch (error) {
      console.error("Failed to fetch jobs", error);
    } finally {
      setIsLoadingJobs(false);
    }
  };

  useEffect(() => {
    fetchJobs();
  }, [searchQuery]);

  useGSAP(() => {
    if (!isLoadingJobs && jobs.length > 0) {
      gsap.fromTo(".gsap-job-item",
        { opacity: 0, x: -20 },
        { opacity: 1, x: 0, duration: 0.6, stagger: 0.05, ease: "power2.out" }
      );
    }
  }, { dependencies: [isLoadingJobs, jobs.length], scope: container });

  useGSAP(() => {
    if (selectedJob) {
      gsap.fromTo(".gsap-detail-header",
        { opacity: 0, y: -20 },
        { opacity: 1, y: 0, duration: 0.6, ease: "power3.out" }
      );
      gsap.fromTo(".gsap-detail-panel",
        { opacity: 0, y: 20 },
        { opacity: 1, y: 0, duration: 0.6, stagger: 0.1, ease: "power3.out" }
      );
    }
  }, { dependencies: [selectedJob], scope: detailContainer });

  const loadJobDetail = async (jobId: string) => {
    try {
      const response = await api.get(`/analysis/${jobId}`);
      setSelectedJob(response.data);
    } catch (error) {
      console.error("Failed to load analysis details", error);
    }
  };

  const handleUploadClick = () => {
    fileInputRef.current?.click();
  };

  const handleFileChange = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const files = event.target.files;
    if (!files || files.length === 0) return;

    setIsUploading(true);
    
    try {
      const uploadPromises = Array.from(files).map(async (file) => {
        const formData = new FormData();
        formData.append('file', file);
        return api.post('/upload', formData, {
          headers: {
            'Content-Type': 'multipart/form-data',
          },
        });
      });

      const results = await Promise.allSettled(uploadPromises);
      await fetchJobs();
      
      const fulfilled = results.filter(r => r.status === 'fulfilled') as PromiseFulfilledResult<any>[];
      const rejected = results.filter(r => r.status === 'rejected') as PromiseRejectedResult[];

      if (fulfilled.length > 0 && fulfilled[0].value.data.file_id) {
        await loadJobDetail(fulfilled[0].value.data.file_id);
      }

      if (rejected.length > 0) {
        console.error('Some uploads failed', rejected);
        alert(`Failed to upload ${rejected.length} file(s). They might be unsupported types or too large.`);
      }
    } catch (error) {
      console.error('Upload failed', error);
      alert('An unexpected error occurred during upload.');
    } finally {
      setIsUploading(false);
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  return (
    <div ref={container} className="flex h-[calc(100vh-88px-80px)] bg-[#000000] border border-[#333333] overflow-hidden">
      {/* ── Job List Sidebar ───────────────────────────────────── */}
      <div className="w-[340px] bg-[#000000] border-r border-[#333333] flex flex-col shrink-0 h-full">
        <div className="p-6 border-b border-[#333333] flex items-center justify-between">
          <h2 className="text-sm font-heading font-bold text-[#ffffff] uppercase tracking-widest">
            Investigations
          </h2>
          <input 
            type="file" 
            ref={fileInputRef} 
            onChange={handleFileChange} 
            className="hidden" 
            accept=".py,.exe,.js,.bat"
            multiple
          />
          <button 
            onClick={handleUploadClick}
            disabled={isUploading}
            className={`p-2 border transition-all ${
              isUploading 
                ? 'bg-[#111111] text-[#666666] border-[#333333] cursor-not-allowed' 
                : 'bg-[#ffffff] text-[#000000] border-[#ffffff] hover:bg-[#000000] hover:text-[#ffffff]'
            }`}
            title="Upload New Artifact"
          >
             {isUploading ? (
               <div className="animate-spin w-4 h-4 border-2 border-black border-t-transparent rounded-full" />
             ) : (
               <Plus size={16} />
             )}
          </button>
        </div>

        <div ref={listScrollRef} className="flex-1 overflow-y-auto p-5 custom-scrollbar min-h-0" data-lenis-prevent>
          <div className="flex flex-col min-h-full">
            {searchQuery && (
              <div className="flex items-center justify-between mb-4 px-2">
                <span className="text-xs font-mono text-[#888888]">SEARCH: <strong className="text-[#ffffff]">{searchQuery}</strong></span>
                <button 
                  onClick={() => navigate('/workspace')} 
                  className="text-[10px] uppercase tracking-widest text-[#888888] hover:text-[#ffffff] border border-[#333333] px-2 py-1"
                >
                  Clear
                </button>
              </div>
            )}
            
            {isLoadingJobs ? (
              <div className="flex items-center justify-center gap-4 text-[#888888] font-mono text-xs uppercase tracking-widest py-10">
                <Loader2 className="w-4 h-4 animate-spin text-[#ffffff]" />
                SCANNING...
              </div>
          ) : jobs.length === 0 ? (
            <div className="text-center py-16 border border-dashed border-[#333333] m-2">
              <Search className="w-6 h-6 text-[#444444] mx-auto mb-4" />
              <p className="text-[#ffffff] font-heading font-bold text-sm uppercase tracking-widest mb-2">No artifacts</p>
              <p className="text-[#666666] font-mono text-[10px] uppercase">Upload file to begin</p>
            </div>
          ) : (
            <div className="space-y-3">
              {jobs.map((job, i) => (
                <div 
                  key={job.id || i}
                  onClick={() => loadJobDetail(job.id)}
                  className={`gsap-job-item p-4 cursor-pointer transition-all duration-200 border ${
                    selectedJob?.file_id === job.id 
                      ? 'bg-[#111111] border-[#ffffff]' 
                      : 'bg-[#000000] border-[#333333] hover:border-[#888888]'
                  }`}
                >
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="font-bold text-[#ffffff] text-sm truncate flex-1 mr-4">{job.filename}</h3>
                    <span className={`text-[10px] font-mono font-bold px-2 py-1 uppercase tracking-widest border ${
                      job.status === 'completed' ? 'border-[#ffffff] text-[#000000] bg-[#ffffff]' :
                      job.status === 'analyzing' ? 'border-[#ffffff] text-[#ffffff] bg-transparent' :
                      'border-[#666666] text-[#666666] bg-transparent'
                    }`}>
                      {job.status}
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-mono text-[#888888]">{job.id.substring(0, 8)}</span>
                    <div className="flex items-center gap-3">
                      {job.risk_score > 0 && (
                        <span className={`font-mono font-bold ${job.risk_score >= 50 ? 'text-red-500' : 'text-emerald-500'}`}>
                          RISK: {job.risk_score}
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
            )}
          </div>
        </div>
      </div>

      {/* ── Detail Area ────────────────────────────────────────── */}
      <div ref={detailScrollRef} className="flex-1 bg-[#000000] relative h-full overflow-y-auto custom-scrollbar min-h-0" data-lenis-prevent>
        <div className="min-h-full flex flex-col">
          {selectedJob ? (
          <div key={selectedJob.file_id} className="p-10 max-w-5xl mx-auto">
            {/* Header */}
            <div className="gsap-detail-header flex items-start justify-between mb-10 pb-8 border-b border-[#333333]">
              <div>
                <h1 className="text-4xl font-heading font-black text-[#ffffff] mb-3 tracking-tighter uppercase">{selectedJob.filename}</h1>
                <p className="text-[#888888] font-mono text-xs uppercase tracking-widest">ID: {selectedJob.file_id}</p>
              </div>
              <div className="flex items-center gap-10">
                <div className="text-right border-r border-[#333333] pr-10">
                  <div className="text-[10px] font-mono font-bold text-[#888888] mb-2 uppercase tracking-widest">Risk Score</div>
                  <div className={`text-5xl font-heading font-black tracking-tighter ${
                    (selectedJob.risk_score || 0) >= 50 ? 'text-red-500' : 'text-emerald-500'
                  }`}>
                    {selectedJob.risk_score || 0}
                  </div>
                </div>
                <button
                  onClick={() => navigate(`/analysis/${selectedJob.file_id}`)}
                  className="flex items-center gap-3 px-6 py-4 bg-[#ffffff] text-[#000000] font-heading font-bold text-sm uppercase tracking-widest hover:bg-[#000000] hover:text-[#ffffff] border border-[#ffffff] transition-colors"
                >
                  <ExternalLink size={16} />
                  FULL REPORT
                </button>
              </div>
            </div>

            {/* Content Grid */}
            <div className="grid grid-cols-2 gap-8">
              {/* AI Summary */}
              <div className="gsap-detail-panel col-span-2 p-8 border border-[#333333] bg-[#000000]">
                <h3 className="text-sm font-heading font-bold uppercase tracking-widest text-[#ffffff] mb-6 flex items-center gap-3">
                  <Activity size={18} />
                  AI Threat Summary
                </h3>
                <p className="text-[#cccccc] text-sm leading-relaxed font-sans max-w-4xl">
                  {selectedJob.ai_summary || 'ANALYSIS IN PROGRESS...'}
                </p>
              </div>

              {/* MITRE Tactics */}
              <div className="gsap-detail-panel p-8 border border-[#333333] bg-[#000000]">
                <h3 className="text-sm font-heading font-bold uppercase tracking-widest text-[#ffffff] mb-6 flex items-center gap-3">
                  <ShieldAlert size={18} />
                  MITRE ATT&CK
                </h3>
                <div className="space-y-3">
                  {(selectedJob.mitre_tactics || []).length === 0 ? (
                    <p className="text-xs font-mono text-[#666666] uppercase">No tactics detected.</p>
                  ) : (
                    selectedJob.mitre_tactics.map((t: any, i: number) => (
                      <div key={i} className="flex items-center justify-between px-4 py-3 border border-[#222222] bg-[#111111]">
                        <span className="text-[#ffffff] font-mono font-bold text-xs">{t.id}</span>
                        <span className="text-[#888888] text-sm font-sans">{t.name}</span>
                      </div>
                    ))
                  )}
                </div>
              </div>

              {/* File Metadata */}
              <div className="gsap-detail-panel p-8 border border-[#333333] bg-[#000000]">
                <h3 className="text-sm font-heading font-bold uppercase tracking-widest text-[#ffffff] mb-6 flex items-center gap-3">
                  <FileText size={18} />
                  File Metadata
                </h3>
                <div className="space-y-5">
                  {[
                    { label: 'SHA256', value: selectedJob.metadata?.artifact_sha256 },
                    { label: 'MD5', value: selectedJob.metadata?.md5 },
                    { label: 'Size', value: selectedJob.metadata?.size ? `${(selectedJob.metadata.size / 1024).toFixed(2)} KB` : null },
                    { label: 'Entropy', value: selectedJob.metadata?.entropy?.toFixed(2) },
                  ].map((item, i) => (
                    <div key={item.label} className="flex flex-col">
                      <span className="text-[#666666] text-[10px] font-mono font-bold uppercase tracking-widest mb-1.5">{item.label}</span>
                      <span className="text-[#ffffff] break-all font-mono text-xs">
                        {item.value || 'N/A'}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* IOCs */}
              {(selectedJob.iocs || []).length > 0 && (
                <div className="gsap-detail-panel col-span-2 p-8 border border-[#333333] bg-[#000000]">
                  <h3 className="text-sm font-heading font-bold uppercase tracking-widest text-[#ffffff] mb-6 flex items-center gap-3">
                    <Pin size={18} />
                    Indicators of Compromise
                  </h3>
                  <div className="grid grid-cols-2 gap-4">
                    {selectedJob.iocs.map((ioc: any, i: number) => (
                      <div key={i} className="flex items-center justify-between p-4 border border-[#222222] bg-[#111111]">
                        <span className="text-[#ffffff] font-mono font-bold text-[10px] uppercase tracking-widest">{ioc.type}</span>
                        <span className="text-[#888888] truncate ml-4 font-mono text-xs">{ioc.value}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
          ) : (
            <div className="flex-1 flex flex-col items-center justify-center">
              <div className="w-24 h-24 border border-[#333333] flex items-center justify-center mb-6">
                <Search className="w-10 h-10 text-[#666666]" />
              </div>
              <span className="text-2xl font-heading font-bold text-[#ffffff] mb-2 tracking-widest uppercase">No Selection</span>
              <span className="text-xs font-mono text-[#666666] uppercase">Select item or upload artifact</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Workspace;
