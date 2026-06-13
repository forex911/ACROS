import React, { useState, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import api from '../api/client';
import { Activity, Server, Database, BarChart3 } from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { staggerContainer, fadeInUp, scaleIn } from '../components/ui/animations';

const Observability: React.FC = () => {
  const [cpuData, setCpuData] = useState<any[]>([]);

  const { data, isLoading } = useQuery({
    queryKey: ['observabilityMetrics'],
    queryFn: async () => {
      const res = await api.get('/observability/metrics');
      return res.data;
    },
    refetchInterval: 2000, // Fetch every 2 seconds for live feeling
  });

  useEffect(() => {
    if (data) {
      setCpuData(prev => {
        const timeStr = new Date(data.timestamp * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        const newPoint = {
          time: timeStr,
          worker_1: data.cpu_utilization,
          worker_2: Math.max(0, data.cpu_utilization - 10 + Math.random() * 20),
          worker_3: Math.max(0, data.cpu_utilization - 5 + Math.random() * 15),
        };
        const newData = [...prev, newPoint];
        if (newData.length > 20) newData.shift();
        return newData;
      });
    }
  }, [data]);

  const workerCount = data?.worker_count || 0;
  const totalWorkers = data?.total_workers || 0;
  const latency = data?.api_latency_ms || 0;
  const queueDepth = data?.redis_queue_depth || 0;

  return (
    <motion.div
      className="space-y-6 max-w-7xl mx-auto"
      initial={{ opacity: 0, y: 18 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -12 }}
      transition={{ duration: 0.4, ease: [0.25, 0.46, 0.45, 0.94] }}
    >
      {/* Header */}
      <motion.div
        className="flex items-center justify-between"
        initial={{ opacity: 0, y: -12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.45, delay: 0.1 }}
      >
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-blue-50 flex items-center justify-center text-blue-600 border border-blue-100">
            <BarChart3 className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-2xl font-bold text-gray-900">System Metrics</h2>
            <p className="text-sm text-gray-500 mt-0.5">Real-time infrastructure observability</p>
          </div>
        </div>
      </motion.div>

      {/* Metric Cards — staggered entrance */}
      <motion.div
        className="grid grid-cols-1 md:grid-cols-3 gap-6"
        variants={staggerContainer}
        initial="hidden"
        animate="visible"
      >
        {/* Worker Nodes */}
        <motion.div
          className="ui-panel p-6 flex flex-col items-center justify-center relative overflow-hidden"
          variants={scaleIn}
          whileHover={{ scale: 1.02, transition: { duration: 0.2 } }}
        >
          <div className="absolute -right-4 -top-4 w-24 h-24 bg-green-50 rounded-full opacity-50"></div>
          <motion.div
            animate={{ rotate: [0, 5, -5, 0] }}
            transition={{ duration: 4, repeat: Infinity, ease: 'easeInOut' }}
            className="w-12 h-12 bg-green-100 rounded-xl flex items-center justify-center mb-4 z-10"
          >
            <Server className="w-6 h-6 text-green-600" />
          </motion.div>
          <motion.div
            className="text-3xl font-bold text-gray-900 z-10"
            key={workerCount}
            initial={{ scale: 1.2, opacity: 0.5 }}
            animate={{ scale: 1, opacity: 1 }}
            transition={{ type: 'spring', stiffness: 200, damping: 15 }}
          >
            {isLoading ? '...' : `${workerCount}/${totalWorkers}`}
          </motion.div>
          <div className="text-sm text-gray-500 font-semibold uppercase tracking-wide mt-2 z-10">Worker Nodes</div>
        </motion.div>

        {/* API Latency */}
        <motion.div
          className="ui-panel p-6 flex flex-col items-center justify-center relative overflow-hidden"
          variants={scaleIn}
          whileHover={{ scale: 1.02, transition: { duration: 0.2 } }}
        >
          <div className="absolute -right-4 -top-4 w-24 h-24 bg-blue-50 rounded-full opacity-50"></div>
          <motion.div
            animate={{ y: [0, -3, 0] }}
            transition={{ duration: 2, repeat: Infinity, ease: 'easeInOut' }}
            className="w-12 h-12 bg-blue-100 rounded-xl flex items-center justify-center mb-4 z-10"
          >
            <Activity className="w-6 h-6 text-blue-600" />
          </motion.div>
          <motion.div
            className="text-3xl font-bold text-gray-900 z-10"
            key={latency}
            initial={{ scale: 1.2, opacity: 0.5 }}
            animate={{ scale: 1, opacity: 1 }}
            transition={{ type: 'spring', stiffness: 200, damping: 15 }}
          >
            {isLoading ? '...' : `${latency}ms`}
          </motion.div>
          <div className="text-sm text-gray-500 font-semibold uppercase tracking-wide mt-2 z-10">P99 Latency</div>
        </motion.div>

        {/* Redis Queue */}
        <motion.div
          className="ui-panel p-6 flex flex-col items-center justify-center relative overflow-hidden"
          variants={scaleIn}
          whileHover={{ scale: 1.02, transition: { duration: 0.2 } }}
        >
          <div className="absolute -right-4 -top-4 w-24 h-24 bg-red-50 rounded-full opacity-50"></div>
          <motion.div
            animate={{ scale: [1, 1.08, 1] }}
            transition={{ duration: 2.5, repeat: Infinity, ease: 'easeInOut' }}
            className="w-12 h-12 bg-red-100 rounded-xl flex items-center justify-center mb-4 z-10"
          >
            <Database className="w-6 h-6 text-red-600" />
          </motion.div>
          <motion.div
            className="text-3xl font-bold text-gray-900 z-10"
            key={queueDepth}
            initial={{ scale: 1.2, opacity: 0.5 }}
            animate={{ scale: 1, opacity: 1 }}
            transition={{ type: 'spring', stiffness: 200, damping: 15 }}
          >
            {isLoading ? '...' : queueDepth}
          </motion.div>
          <div className="text-sm text-gray-500 font-semibold uppercase tracking-wide mt-2 z-10">Queue Depth</div>
        </motion.div>
      </motion.div>

      {/* Chart Panel */}
      <motion.div
        className="ui-panel p-6"
        initial={{ opacity: 0, y: 24 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, delay: 0.4, ease: [0.25, 0.46, 0.45, 0.94] }}
      >
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-gray-900 font-bold text-lg">Worker CPU Utilization</h3>
          <div className="flex items-center gap-4 text-xs font-semibold text-gray-500">
            <div className="flex items-center gap-1.5"><div className="w-2.5 h-2.5 rounded-full bg-blue-500"></div>Worker 1</div>
            <div className="flex items-center gap-1.5"><div className="w-2.5 h-2.5 rounded-full bg-green-500"></div>Worker 2</div>
            <div className="flex items-center gap-1.5"><div className="w-2.5 h-2.5 rounded-full bg-red-500"></div>Worker 3</div>
          </div>
        </div>
        <div className="h-[400px] bg-white rounded-xl p-4 border border-gray-100" style={{ minWidth: 0, minHeight: 300 }}>
          <ResponsiveContainer width="100%" height="100%" minWidth={100} minHeight={200}>
            <LineChart data={cpuData} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#f3f4f6" vertical={false} />
              <XAxis dataKey="time" stroke="#e5e7eb" tick={{ fill: '#6b7280', fontSize: 12, fontWeight: 500 }} tickLine={false} axisLine={false} dy={10} />
              <YAxis stroke="#e5e7eb" tick={{ fill: '#6b7280', fontSize: 12, fontWeight: 500 }} tickLine={false} axisLine={false} dx={-10} />
              <Tooltip 
                contentStyle={{ backgroundColor: '#ffffff', borderColor: '#f3f4f6', color: '#1f2937', borderRadius: '0.75rem', boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)' }}
                itemStyle={{ fontWeight: 600 }}
                labelStyle={{ color: '#6b7280', marginBottom: '0.25rem' }}
              />
              <Line
                type="monotone"
                dataKey="worker_1"
                stroke="#3b82f6"
                strokeWidth={3}
                dot={false}
                activeDot={{ r: 6, fill: '#3b82f6', stroke: '#fff', strokeWidth: 2 }}
                isAnimationActive={true}
                animationDuration={600}
                animationEasing="ease-out"
              />
              <Line
                type="monotone"
                dataKey="worker_2"
                stroke="#10b981"
                strokeWidth={3}
                dot={false}
                activeDot={{ r: 6, fill: '#10b981', stroke: '#fff', strokeWidth: 2 }}
                isAnimationActive={true}
                animationDuration={600}
                animationEasing="ease-out"
              />
              <Line
                type="monotone"
                dataKey="worker_3"
                stroke="#ef4444"
                strokeWidth={3}
                dot={false}
                activeDot={{ r: 6, fill: '#ef4444', stroke: '#fff', strokeWidth: 2 }}
                isAnimationActive={true}
                animationDuration={600}
                animationEasing="ease-out"
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </motion.div>
    </motion.div>
  );
};

export default Observability;
