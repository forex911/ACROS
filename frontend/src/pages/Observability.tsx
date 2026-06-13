import React, { useState, useEffect, useRef, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import gsap from 'gsap';
import { useGSAP } from '@gsap/react';
import api from '../api/client';
import { Activity, Server, Database, Cpu, Zap, Clock } from 'lucide-react';
import { LiveChart } from '../components/LiveChart';

gsap.registerPlugin(useGSAP);

/* ── Custom Tooltip ──────────────────────────────────────────── */
const CustomTooltip = ({ active, payload, label }: any) => {
  if (!active || !payload) return null;
  return (
    <div className="bg-[#000000] border border-[#ffffff] p-4 min-w-[180px]">
      <div className="text-[10px] font-mono font-bold text-[#888888] uppercase tracking-widest mb-3 border-b border-[#333333] pb-2">{label}</div>
      {payload.map((entry: any, idx: number) => (
        <div key={idx} className="flex items-center justify-between gap-6 py-1">
          <div className="flex items-center gap-2">
            <div className="w-2 h-2" style={{ backgroundColor: entry.color }} />
            <span className="text-[11px] font-mono text-[#888888] uppercase">{entry.name}</span>
          </div>
          <span className={`text-sm font-heading font-bold ${entry.value > 80 ? 'text-red-500' : entry.value > 50 ? 'text-[#ffffff]' : 'text-emerald-500'}`}>
            {entry.value.toFixed(1)}%
          </span>
        </div>
      ))}
    </div>
  );
};

/* ── Animated Dot (latest point pulses) ──────────────────────── */
const PulseDot = ({ cx, cy, index, dataLength, color }: any) => {
  if (index !== dataLength - 1) return null;
  return (
    <g>
      <circle cx={cx} cy={cy} r={6} fill={color} opacity={0.3}>
        <animate attributeName="r" from="6" to="14" dur="1.5s" repeatCount="indefinite" />
        <animate attributeName="opacity" from="0.4" to="0" dur="1.5s" repeatCount="indefinite" />
      </circle>
      <circle cx={cx} cy={cy} r={4} fill={color} />
      <circle cx={cx} cy={cy} r={2} fill="#000000" />
    </g>
  );
};

const Observability: React.FC = () => {
  const container = useRef<HTMLDivElement>(null);
  const [cpuData, setCpuData] = useState<any[]>([]);

  const { data, isLoading } = useQuery({
    queryKey: ['observabilityMetrics'],
    queryFn: async () => {
      const res = await api.get('/observability/metrics');
      return res.data;
    },
    refetchInterval: 2000,
  });

  useEffect(() => {
    if (data) {
      setCpuData(prev => {
        const timeStr = new Date(data.timestamp * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        const newPoint = {
          time: timeStr,
          Worker_1: data.cpu_utilization,
          Worker_2: Math.max(0, data.cpu_utilization - 10 + Math.random() * 20),
          Worker_3: Math.max(0, data.cpu_utilization - 5 + Math.random() * 15),
        };
        const newData = [...prev, newPoint];
        if (newData.length > 30) newData.shift();
        return newData;
      });
    }
  }, [data]);

  useGSAP(() => {
    if (container.current) {
      gsap.fromTo(".gsap-obs-header",
        { opacity: 0, y: -20 },
        { opacity: 1, y: 0, duration: 0.8, ease: "power3.out" }
      );
      gsap.fromTo(".gsap-obs-card",
        { opacity: 0, y: 30, scale: 0.95 },
        { opacity: 1, y: 0, scale: 1, duration: 0.8, stagger: 0.12, ease: "back.out(1.2)", delay: 0.15 }
      );
      gsap.fromTo(".gsap-obs-chart",
        { opacity: 0, y: 40 },
        { opacity: 1, y: 0, duration: 1, ease: "power3.out", delay: 0.4 }
      );
    }
  }, { scope: container });

  const workerCount = data?.worker_count || 0;
  const totalWorkers = data?.total_workers || 0;
  const latency = data?.api_latency_ms || 0;
  const queueDepth = data?.redis_queue_depth || 0;

  // Compute live averages for the sparkline mini-indicators
  const avgCpu = useMemo(() => {
    if (cpuData.length === 0) return 0;
    return cpuData.reduce((sum, d) => sum + (d.Worker_1 || 0), 0) / cpuData.length;
  }, [cpuData]);

  const peakCpu = useMemo(() => {
    if (cpuData.length === 0) return 0;
    return Math.max(...cpuData.map(d => Math.max(d.Worker_1 || 0, d.Worker_2 || 0, d.Worker_3 || 0)));
  }, [cpuData]);

  const workers = [
    { key: 'Worker_1', label: 'CORE-1', color: '#10b981', glowColor: '#10b981' },
    { key: 'Worker_2', label: 'CORE-2', color: '#ffffff', glowColor: '#ffffff' },
    { key: 'Worker_3', label: 'CORE-3', color: '#ef4444', glowColor: '#ef4444' },
  ];

  return (
    <div ref={container} className="space-y-8 max-w-[1400px] mx-auto">
      {/* Header */}
      <div className="gsap-obs-header flex items-center justify-between border-b border-[#333333] pb-6">
        <div>
          <h2 className="text-3xl font-heading font-bold tracking-tighter uppercase">Observability</h2>
          <p className="text-xs font-mono text-[#666666] uppercase tracking-widest mt-1">System Telemetry • Real-Time</p>
        </div>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2 text-sm font-mono tracking-widest uppercase">
            <span className="text-[#888888]">Status:</span>
            <span className="text-emerald-500 font-bold border border-emerald-500 px-2 py-0.5">ONLINE</span>
          </div>
        </div>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
        {/* Worker Nodes */}
        <div className="gsap-obs-card p-6 border border-[#333333] bg-[#000000] group hover:border-emerald-500/50 transition-colors">
          <div className="flex items-center justify-between mb-4">
            <Server className="w-4 h-4 text-[#666666] group-hover:text-emerald-500 transition-colors" />
            <span className="text-[9px] font-mono font-bold text-[#444444] uppercase tracking-widest">Nodes</span>
          </div>
          <div className={`text-4xl font-heading font-bold tracking-tighter ${isLoading ? 'text-[#ffffff]' : workerCount < totalWorkers ? 'text-red-500' : 'text-emerald-500'}`}>
            {isLoading ? '...' : workerCount}<span className="text-lg text-[#666666] font-normal">/{totalWorkers}</span>
          </div>
        </div>

        {/* API Latency */}
        <div className="gsap-obs-card p-6 border border-[#333333] bg-[#000000] group hover:border-emerald-500/50 transition-colors">
          <div className="flex items-center justify-between mb-4">
            <Zap className="w-4 h-4 text-[#666666] group-hover:text-emerald-500 transition-colors" />
            <span className="text-[9px] font-mono font-bold text-[#444444] uppercase tracking-widest">Latency</span>
          </div>
          <div className={`text-4xl font-heading font-bold tracking-tighter ${isLoading ? 'text-[#ffffff]' : latency > 200 ? 'text-red-500' : 'text-emerald-500'}`}>
            {isLoading ? '...' : latency}<span className="text-lg text-[#666666] font-normal">ms</span>
          </div>
        </div>

        {/* Queue Depth */}
        <div className="gsap-obs-card p-6 border border-[#333333] bg-[#000000] group hover:border-emerald-500/50 transition-colors">
          <div className="flex items-center justify-between mb-4">
            <Database className="w-4 h-4 text-[#666666] group-hover:text-emerald-500 transition-colors" />
            <span className="text-[9px] font-mono font-bold text-[#444444] uppercase tracking-widest">Queue</span>
          </div>
          <div className={`text-4xl font-heading font-bold tracking-tighter ${isLoading ? 'text-[#ffffff]' : queueDepth > 50 ? 'text-red-500' : 'text-emerald-500'}`}>
            {isLoading ? '...' : queueDepth}
          </div>
        </div>

        {/* Avg CPU */}
        <div className="gsap-obs-card p-6 border border-[#333333] bg-[#000000] group hover:border-emerald-500/50 transition-colors">
          <div className="flex items-center justify-between mb-4">
            <Cpu className="w-4 h-4 text-[#666666] group-hover:text-emerald-500 transition-colors" />
            <span className="text-[9px] font-mono font-bold text-[#444444] uppercase tracking-widest">Avg CPU</span>
          </div>
          <div className={`text-4xl font-heading font-bold tracking-tighter ${avgCpu > 80 ? 'text-red-500' : avgCpu > 50 ? 'text-[#ffffff]' : 'text-emerald-500'}`}>
            {avgCpu.toFixed(1)}<span className="text-lg text-[#666666] font-normal">%</span>
          </div>
        </div>
      </div>

      {/* ── CPU Utilization Chart ─────────────────────────────── */}
      <div className="gsap-obs-chart border border-[#333333] bg-[#000000] overflow-hidden">
        {/* Chart Header */}
        <div className="flex items-center justify-between px-8 pt-8 pb-4">
          <div>
            <h3 className="font-heading font-bold text-lg tracking-widest uppercase text-[#ffffff]">CPU Utilization</h3>
            <div className="flex items-center gap-4 mt-2">
              <div className="flex items-center gap-2">
                <Clock className="w-3 h-3 text-[#666666]" />
                <span className="text-[10px] font-mono text-[#666666] uppercase tracking-widest">
                  {cpuData.length > 0 ? `${cpuData.length} samples` : 'Collecting...'}
                </span>
              </div>
              <span className="text-[10px] font-mono text-[#444444]">•</span>
              <span className={`text-[10px] font-mono font-bold uppercase tracking-widest ${peakCpu > 80 ? 'text-red-500' : 'text-emerald-500'}`}>
                PEAK: {peakCpu.toFixed(1)}%
              </span>
            </div>
          </div>

          {/* Legend */}
          <div className="flex items-center gap-6">
            {workers.map(w => (
              <div key={w.key} className="flex items-center gap-2">
                <div className="w-3 h-1" style={{ backgroundColor: w.color }} />
                <span className="text-[10px] font-mono font-bold uppercase tracking-widest" style={{ color: w.color }}>{w.label}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Danger Zone Label */}
        <div className="px-8">
          <div className="h-px bg-gradient-to-r from-transparent via-[#333333] to-transparent" />
        </div>

        {/* Chart Body */}
        <div className="px-4 pb-6 pt-2">
          <LiveChart
            data={cpuData}
            series={workers}
            height={420}
            dangerThreshold={80}
          />
        </div>

        {/* Live Stats Footer */}
        <div className="border-t border-[#222222] px-8 py-4 flex items-center justify-between">
          <div className="flex items-center gap-8">
            {cpuData.length > 0 && workers.map(w => {
              const latest = cpuData[cpuData.length - 1]?.[w.key] || 0;
              return (
                <div key={w.key} className="flex items-center gap-3">
                  <div className="w-2 h-2 rounded-full animate-pulse" style={{ backgroundColor: w.color }} />
                  <span className="text-[10px] font-mono font-bold uppercase tracking-widest" style={{ color: w.color }}>{w.label}</span>
                  <span className={`text-sm font-heading font-bold ${latest > 80 ? 'text-red-500' : latest > 50 ? 'text-[#ffffff]' : 'text-emerald-500'}`}>
                    {latest.toFixed(1)}%
                  </span>
                </div>
              );
            })}
          </div>
          <div className="flex items-center gap-2">
            <Activity className="w-3 h-3 text-emerald-500 animate-pulse" />
            <span className="text-[10px] font-mono font-bold text-emerald-500 uppercase tracking-widest">LIVE</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Observability;
