import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { Briefcase, FileText, Pin, Plus, Upload, Search, ShieldAlert, Activity, ExternalLink } from 'lucide-react';
import api from '../api/client';
import { staggerContainer, fadeInUp } from '../components/ui/animations';

interface AnalysisJob {
  id: string;
  filename: string;
  status: string;
  risk_score: number;
  created_at: string;
}

export const Workspace: React.FC = () => {
  const [jobs, setJobs] = useState<AnalysisJob[]>([]);
  const [selectedJob, setSelectedJob] = useState<any | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const [isLoadingJobs, setIsLoadingJobs] = useState(true);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();

  const fetchJobs = async () => {
    setIsLoadingJobs(true);
    try {
      const response = await api.get('/workspace/jobs');
      setJobs(response.data || []);
    } catch (error) {
      console.error("Failed to fetch jobs", error);
    } finally {
      setIsLoadingJobs(false);
    }
  };

  useEffect(() => {
    fetchJobs();
  }, []);

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
    const file = event.target.files?.[0];
    if (!file) return;

    setIsUploading(true);
    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await api.post('/upload', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });
      await fetchJobs();
      if (response.data.file_id) {
        await loadJobDetail(response.data.file_id);
      }
    } catch (error) {
      console.error('Upload failed', error);
      alert('Upload failed. Please try again.');
    } finally {
      setIsUploading(false);
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return 'text-gray-900 bg-[#c5f37d]/60';
      case 'analyzing': return 'text-yellow-700 bg-yellow-100';
      case 'failed': return 'text-red-700 bg-red-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const getRiskColor = (score: number) => {
    if (score >= 70) return 'text-red-600';
    if (score >= 40) return 'text-orange-500';
    if (score > 0) return 'text-gray-900';
    return 'text-gray-500';
  };

  return (
    <motion.div
      className="flex h-[calc(100vh-8rem)] rounded-2xl bg-white border border-gray-100 overflow-hidden shadow-sm"
      initial={{ opacity: 0, y: 18 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -12 }}
      transition={{ duration: 0.4, ease: [0.25, 0.46, 0.45, 0.94] }}
    >
      {/* Job List Sidebar */}
      <div className="w-[320px] bg-gray-50 border-r border-gray-100 flex flex-col">
        <div className="p-5 border-b border-gray-100 flex items-center justify-between bg-white">
          <h2 className="text-lg font-bold text-gray-900 flex items-center gap-2">
            Investigations
          </h2>
          <input 
            type="file" 
            ref={fileInputRef} 
            onChange={handleFileChange} 
            className="hidden" 
          />
          <button 
            onClick={handleUploadClick}
            disabled={isUploading}
            className={`p-2 rounded-xl transition-all ${
              isUploading ? 'bg-gray-100 text-gray-400 cursor-not-allowed' : 'bg-gray-900 text-white hover:bg-gray-800 hover:shadow-md'
            }`}
            title="Upload New Artifact"
          >
             {isUploading ? (
               <motion.div animate={{ rotate: 360 }} transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}>
                 <Upload size={18} />
               </motion.div>
             ) : (
               <Plus size={18} />
             )}
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-4">
          {isLoadingJobs ? (
            <motion.div className="flex items-center justify-center gap-2 text-gray-400 text-sm py-10" animate={{ opacity: [0.4, 0.8, 0.4] }} transition={{ duration: 1.5, repeat: Infinity }}>
              <div className="w-4 h-4 border-2 border-gray-400 border-t-transparent rounded-full animate-spin" />
              Scanning...
            </motion.div>
          ) : jobs.length === 0 ? (
            <div className="text-center py-12">
              <Search className="w-10 h-10 text-gray-300 mx-auto mb-4" />
              <p className="text-gray-500 font-medium text-sm mb-2">No artifacts found</p>
              <p className="text-gray-400 text-xs">Upload a file using the + button</p>
            </div>
          ) : (
            <div className="space-y-3">
              {jobs.map((job, i) => (
                <motion.div 
                  key={job.id || i}
                  onClick={() => loadJobDetail(job.id)}
                  className={`p-4 rounded-xl cursor-pointer transition-all duration-200 border ${
                    selectedJob?.file_id === job.id 
                      ? 'bg-white border-[#c5f37d] shadow-sm ring-1 ring-[#c5f37d]' 
                      : 'bg-white border-transparent shadow-sm hover:border-gray-200'
                  }`}
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ duration: 0.3, delay: i * 0.05 }}
                  whileHover={{ y: -2 }}
                >
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="font-semibold text-gray-900 text-sm truncate flex-1 mr-2">{job.filename}</h3>
                    <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full whitespace-nowrap ${getStatusColor(job.status)}`}>
                      {job.status?.toUpperCase()}
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-xs text-gray-500">
                    <span className="font-mono text-[10px] bg-gray-100 px-1.5 py-0.5 rounded text-gray-400">{job.id.substring(0, 8)}</span>
                    <div className="flex items-center gap-3">
                      {job.risk_score > 0 && (
                        <span className={`font-bold ${getRiskColor(job.risk_score)}`}>
                          Risk: {job.risk_score}
                        </span>
                      )}
                    </div>
                  </div>
                </motion.div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Detail Area */}
      <div className="flex-1 overflow-y-auto bg-gray-50">
        <AnimatePresence mode="wait">
          {selectedJob ? (
            <motion.div
              key={selectedJob.file_id}
              className="p-8"
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -12 }}
              transition={{ duration: 0.35, ease: [0.25, 0.46, 0.45, 0.94] }}
            >
              {/* Header */}
              <div className="flex items-start justify-between mb-8 pb-6 border-b border-gray-200">
                <div>
                  <h1 className="text-2xl font-bold text-gray-900 mb-2">{selectedJob.filename}</h1>
                  <p className="text-gray-400 font-mono text-xs bg-white px-2 py-1 rounded inline-block border border-gray-100">ID: {selectedJob.file_id}</p>
                </div>
                <div className="flex items-center gap-6">
                  <motion.div className="text-right" initial={{ scale: 0.8 }} animate={{ scale: 1 }} transition={{ type: 'spring', stiffness: 200, delay: 0.2 }}>
                    <div className="text-xs font-semibold text-gray-400 mb-1 uppercase">Risk Score</div>
                    <div className={`text-3xl font-bold ${getRiskColor(selectedJob.risk_score || 0)}`}>
                      {selectedJob.risk_score || 0}
                    </div>
                  </motion.div>
                  <motion.button
                    onClick={() => navigate(`/analysis/${selectedJob.file_id}`)}
                    className="flex items-center gap-2 px-5 py-2.5 bg-gray-900 text-white rounded-xl font-medium text-sm hover:bg-gray-800 transition-colors shadow-sm"
                    whileHover={{ scale: 1.02 }}
                    whileTap={{ scale: 0.98 }}
                  >
                    <ExternalLink size={16} />
                    Full Report
                  </motion.button>
                </div>
              </div>

              {/* Content Grid */}
              <div className="grid grid-cols-2 gap-6">
                {/* AI Summary */}
                <motion.div className="col-span-2 ui-panel p-6" variants={fadeInUp}>
                  <h3 className="text-sm font-bold text-gray-900 mb-4 flex items-center gap-2">
                    <div className="w-6 h-6 rounded bg-[#c5f37d]/30 flex items-center justify-center text-[#7fb827]">
                      <Activity size={14} />
                    </div>
                    AI Threat Summary
                  </h3>
                  <p className="text-gray-600 text-sm leading-relaxed">
                    {selectedJob.ai_summary || 'Analysis in progress...'}
                  </p>
                </motion.div>

                {/* MITRE Tactics */}
                <motion.div className="ui-panel p-6" variants={fadeInUp}>
                  <h3 className="text-sm font-bold text-gray-900 mb-4 flex items-center gap-2">
                    <div className="w-6 h-6 rounded bg-red-50 flex items-center justify-center text-red-500">
                      <ShieldAlert size={14} />
                    </div>
                    MITRE ATT&CK Tactics
                  </h3>
                  <div className="space-y-3">
                    {(selectedJob.mitre_tactics || []).length === 0 ? (
                      <p className="text-sm text-gray-400 italic">No tactics detected.</p>
                    ) : (
                      selectedJob.mitre_tactics.map((t: any, i: number) => (
                        <div key={i} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg text-sm border border-gray-100">
                          <span className="text-red-600 font-medium">{t.id}</span>
                          <span className="text-gray-700">{t.name}</span>
                        </div>
                      ))
                    )}
                  </div>
                </motion.div>

                {/* File Metadata */}
                <motion.div className="ui-panel p-6" variants={fadeInUp}>
                  <h3 className="text-sm font-bold text-gray-900 mb-4 flex items-center gap-2">
                    <div className="w-6 h-6 rounded bg-gray-100 flex items-center justify-center text-gray-600">
                      <FileText size={14} />
                    </div>
                    File Metadata
                  </h3>
                  <div className="space-y-4 text-sm">
                    {[
                      { label: 'SHA256', value: selectedJob.metadata?.artifact_sha256 },
                      { label: 'MD5', value: selectedJob.metadata?.md5 },
                      { label: 'Size', value: selectedJob.metadata?.size ? `${(selectedJob.metadata.size / 1024).toFixed(2)} KB` : null },
                      { label: 'Entropy', value: selectedJob.metadata?.entropy?.toFixed(2) },
                    ].map((item, i) => (
                      <div key={item.label} className="flex flex-col">
                        <span className="text-gray-400 text-xs font-medium uppercase">{item.label}</span>
                        <span className="text-gray-900 break-all font-mono text-xs mt-1 bg-gray-50 p-1.5 rounded border border-gray-100">{item.value || 'N/A'}</span>
                      </div>
                    ))}
                  </div>
                </motion.div>

                {/* IOCs */}
                {(selectedJob.iocs || []).length > 0 && (
                  <motion.div className="col-span-2 ui-panel p-6" variants={fadeInUp}>
                    <h3 className="text-sm font-bold text-gray-900 mb-4 flex items-center gap-2">
                      <div className="w-6 h-6 rounded bg-orange-50 flex items-center justify-center text-orange-500">
                        <Pin size={14} />
                      </div>
                      Indicators of Compromise
                    </h3>
                    <div className="grid grid-cols-2 gap-3">
                      {selectedJob.iocs.map((ioc: any, i: number) => (
                        <div key={i} className="flex items-center justify-between p-3 bg-gray-50 border border-gray-100 rounded-lg text-sm">
                          <span className="text-orange-600 font-semibold text-xs uppercase">{ioc.type}</span>
                          <span className="text-gray-700 truncate ml-2 font-mono text-xs">{ioc.value}</span>
                        </div>
                      ))}
                    </div>
                  </motion.div>
                )}
              </div>
            </motion.div>
          ) : (
            <motion.div
              key="empty"
              className="h-full flex flex-col items-center justify-center text-gray-400"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.3 }}
            >
              <Search className="w-16 h-16 text-gray-200 mb-6" />
              <span className="text-lg font-medium text-gray-500 mb-2">No Analysis Selected</span>
              <span className="text-sm">Select an item from the left or upload a new artifact</span>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </motion.div>
  );
};

export default Workspace;
