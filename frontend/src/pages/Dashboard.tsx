import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import api from '../api/client';
import { StatCard } from '../components/dashboard/StatCard';
import { Activity, ShieldAlert, Cpu, Database, ChevronDown, Calendar, FileSearch } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import { staggerContainer, fadeInUp } from '../components/ui/animations';

const Dashboard: React.FC = () => {
  const { data, isLoading, error } = useQuery({
    queryKey: ['dashboardOverview'],
    queryFn: async () => {
      const res = await api.get('/dashboard/overview');
      return res.data;
    },
    refetchInterval: 5000,
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full text-gray-400">
        <div className="w-6 h-6 border-2 border-[#c5f37d] border-t-transparent rounded-full animate-spin mr-3" />
        Loading...
      </div>
    );
  }

  if (error) {
    return <div className="text-red-500 p-6">Error loading dashboard data.</div>;
  }

  const {
    active_sandboxes = 0,
    total_threats = 0,
    stored_artifacts = 0,
    recent_activity = [],
    chart_data = []
  } = data || {};

  const mappedChartData = chart_data.map((d: any) => ({
    name: d.time,
    Scans: d.scans || 0,
    Threats: d.detections || 0
  }));

  // Threat feed from backend
  const threatFeed = data?.threat_feed || [];

  return (
    <motion.div
      className="max-w-7xl mx-auto space-y-6"
      initial={{ opacity: 0, y: 18 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -12 }}
      transition={{ duration: 0.4, ease: [0.25, 0.46, 0.45, 0.94] }}
    >
      <div className="flex justify-between items-end mb-2">
        <h2 className="text-2xl font-bold text-gray-900 tracking-tight">Overview</h2>
      </div>

      {/* Stat Cards */}
      <motion.div
        className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6"
        variants={staggerContainer}
        initial="hidden"
        animate="visible"
      >
        <motion.div variants={fadeInUp}><StatCard title="Active Scans" value={active_sandboxes.toString()} icon={Cpu} color="accent" trend={{ value: 12, isUp: true }} /></motion.div>
        <motion.div variants={fadeInUp}><StatCard title="Threats Detected" value={total_threats.toString()} icon={ShieldAlert} color="alert" trend={{ value: 5, isUp: false }} /></motion.div>
        <motion.div variants={fadeInUp}><StatCard title="Stored Artifacts" value={stored_artifacts.toString()} icon={Database} color="green" trend={{ value: 100, isUp: true }} /></motion.div>
        <motion.div variants={fadeInUp}><StatCard title="System Health" value="99.9%" icon={Activity} color="default" trend={{ value: 0.1, isUp: true }} /></motion.div>
      </motion.div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main Chart Area */}
        <motion.div className="lg:col-span-2 ui-panel p-6 flex flex-col" variants={fadeInUp}>
          <div className="flex justify-between items-start mb-8">
            <div>
              <h3 className="text-xl font-bold text-gray-900 mb-1">Scan Volume</h3>
              <div className="flex items-center gap-4 text-sm">
                <div>
                  <span className="text-gray-500 mr-2">Scans</span>
                  <span className="font-semibold">{stored_artifacts}</span>
                </div>
                <div>
                  <span className="text-gray-500 mr-2">Threats</span>
                  <span className="font-semibold">{total_threats}</span>
                </div>
              </div>
            </div>
            <button className="flex items-center gap-2 border border-gray-200 px-3 py-1.5 rounded-lg text-sm text-gray-600 hover:bg-gray-50">
              Weekly <ChevronDown className="w-4 h-4" />
            </button>
          </div>
          
          <div className="h-[280px]" style={{ minWidth: 0, minHeight: 200 }}>
            <ResponsiveContainer width="100%" height="100%" minWidth={100} minHeight={200}>
              <BarChart data={mappedChartData} barGap={8}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#f3f4f6" />
                <XAxis dataKey="name" axisLine={false} tickLine={false} tick={{ fill: '#9ca3af', fontSize: 12 }} dy={10} />
                <YAxis axisLine={false} tickLine={false} tick={{ fill: '#9ca3af', fontSize: 12 }} dx={-10} />
                <Tooltip 
                  cursor={{ fill: '#f9fafb' }}
                  contentStyle={{ borderRadius: '12px', border: 'none', boxShadow: '0 4px 12px rgba(0,0,0,0.05)' }}
                />
                <Legend iconType="circle" wrapperStyle={{ paddingTop: '20px' }} />
                <Bar dataKey="Scans" fill="#c5f37d" radius={[4, 4, 0, 0]} barSize={32} />
                <Bar dataKey="Threats" fill="#e5e7eb" radius={[4, 4, 0, 0]} barSize={32} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </motion.div>

        {/* Right Side Panel (Threat Feed / Stock Ticker equivalent) */}
        <motion.div className="ui-panel p-6" variants={fadeInUp}>
          <div className="flex justify-between items-center mb-6">
            <h3 className="font-bold text-gray-900">Live Threats</h3>
            <span className="text-xs text-gray-500">Sentinel Network</span>
          </div>
          <div className="space-y-6">
            <div className="flex items-baseline justify-between border-b border-gray-100 pb-4">
              <span className="text-3xl font-bold">{total_threats}</span>
              <span className="text-red-500 text-sm font-medium">Active</span>
            </div>
            
            <div className="flex justify-between text-xs font-medium text-gray-400 mb-2">
              <span className="bg-[#c5f37d] text-gray-900 px-2 py-1 rounded-md">1D</span>
              <span className="px-2 py-1">1W</span>
              <span className="px-2 py-1">1M</span>
              <span className="px-2 py-1">3M</span>
              <span className="px-2 py-1">1Y</span>
              <span className="px-2 py-1">ALL</span>
            </div>
            
            <div className="mt-6 space-y-5">
              {threatFeed.map((threat, idx) => (
                <div key={idx} className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="w-8 h-8 rounded-full bg-gray-50 flex items-center justify-center text-red-500 font-bold text-xs border border-gray-100">
                      {threat.name.charAt(0)}
                    </div>
                    <div>
                      <div className="font-bold text-gray-900 text-sm">{threat.name}</div>
                      <div className="text-xs text-gray-500">{threat.id}</div>
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="font-bold text-gray-900 text-sm">{threat.score}</div>
                    <div className={`text-xs ${parseFloat(threat.trend) > 0 ? 'text-red-500' : 'text-[#7fb827]'}`}>
                      {threat.trend}
                    </div>
                  </div>
                </div>
              ))}
              {threatFeed.length === 0 && (
                <div className="text-gray-400 text-sm italic text-center py-4">No recent threats detected.</div>
              )}
            </div>
          </div>
        </motion.div>
      </div>

      {/* Transaction History / Recent Activity */}
      <motion.div className="ui-panel p-6" variants={fadeInUp}>
        <div className="flex justify-between items-center mb-6">
          <h3 className="font-bold text-gray-900 text-lg">Recent Investigations</h3>
          <button className="flex items-center gap-2 border border-gray-200 px-3 py-1.5 rounded-lg text-sm text-gray-600 hover:bg-gray-50">
            <Calendar className="w-4 h-4" /> Select dates
          </button>
        </div>
        
        <div className="overflow-x-auto">
          <table className="w-full text-sm text-left">
            <thead className="text-gray-400 font-normal border-b border-gray-100">
              <tr>
                <th className="pb-3 font-medium">Investigation</th>
                <th className="pb-3 font-medium">Date</th>
                <th className="pb-3 font-medium">Status</th>
                <th className="pb-3 font-medium">Artifact</th>
                <th className="pb-3 font-medium text-right">Risk Score</th>
              </tr>
            </thead>
            <tbody>
              {recent_activity.length === 0 && (
                <tr>
                  <td colSpan={5} className="py-8 text-center text-gray-500">No recent activity.</td>
                </tr>
              )}
              {recent_activity.map((job: any) => (
                <tr key={job.id} className="border-b border-gray-50 last:border-0 hover:bg-gray-50/50 transition-colors">
                  <td className="py-4">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded-full bg-blue-50 flex items-center justify-center text-blue-600">
                        <FileSearch className="w-4 h-4" />
                      </div>
                      <span className="font-medium text-gray-900">{job.id.substring(0, 8)}</span>
                    </div>
                  </td>
                  <td className="py-4 text-gray-500">{new Date(job.created_at).toLocaleDateString()} {new Date(job.created_at).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}</td>
                  <td className="py-4">
                    <span className={`px-2.5 py-1 rounded-md text-xs font-medium ${
                      job.status === 'analyzing' ? 'bg-yellow-50 text-yellow-700' :
                      job.status === 'completed' ? 'bg-[#c5f37d]/30 text-gray-800' :
                      'bg-red-50 text-red-700'
                    }`}>
                      {job.status.charAt(0).toUpperCase() + job.status.slice(1)}
                    </span>
                  </td>
                  <td className="py-4 text-gray-700 max-w-[200px] truncate" title={job.filename}>{job.filename}</td>
                  <td className="py-4 text-right font-medium text-gray-900">{job.risk_score || 0}/100</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </motion.div>
    </motion.div>
  );
};

export default Dashboard;
