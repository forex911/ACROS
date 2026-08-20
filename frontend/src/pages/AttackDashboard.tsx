import React from 'react';
import { motion } from 'framer-motion';
import { Target, Activity, Zap } from 'lucide-react';
import { AttackMatrix } from '../components/threat/AttackMatrix';
import { useQuery } from '@tanstack/react-query';
import api from '../api/client';

const AttackDashboard: React.FC = () => {
  const { data: tactics = [] } = useQuery({
    queryKey: ['attackMatrix'],
    queryFn: async () => {
      const res = await api.get('/threats/matrix');
      return res.data;
    },
    refetchInterval: 5000,
  });

  const numTechniques = tactics.reduce((acc: number, tactic: any) => acc + (tactic.techniques?.length || 0), 0);

  return (
    <motion.div
      className="flex flex-col w-full overflow-hidden"
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, ease: "easeOut" }}
    >
      {/* Header */}
      <div className="sticky top-[88px] z-30 p-8 border border-[#333333] bg-[#000000] flex items-center justify-between">
        <div className="flex items-center gap-6">
          <div className="w-12 h-12 border border-[#ffffff] flex items-center justify-center text-[#ffffff]">
            <Target className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-3xl font-heading font-bold text-[#ffffff] tracking-tighter uppercase">ATT&CK Matrix</h1>
            <p className="text-[#888888] font-mono text-xs uppercase tracking-widest mt-1">Real-time Sandbox Correlation</p>
          </div>
        </div>
        <div className="flex gap-4">
          <div className="flex items-center gap-3 px-4 py-2 border border-red-500 bg-red-500/10">
            <motion.div animate={{ scale: [1, 1.2, 1] }} transition={{ duration: 2, repeat: Infinity, ease: 'easeInOut' }}>
              <Activity size={14} className="text-red-500" />
            </motion.div>
            <span className="text-xs font-mono font-bold uppercase tracking-widest text-red-500">LIVE: ACTIVE</span>
          </div>
          <div className="flex items-center gap-3 px-4 py-2 border border-[#333333] bg-[#000000]">
            <Zap size={14} className="text-[#888888]" />
            <span className="text-xs font-mono font-bold uppercase tracking-widest text-[#888888]">TECHNIQUES: {numTechniques}</span>
          </div>
        </div>
      </div>

      {/* Matrix */}
      <motion.div
        className="border border-[#333333] bg-[#000000] mt-12 p-6 overflow-x-auto overflow-y-auto custom-scrollbar"
        initial={{ opacity: 0, scale: 0.98 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ delay: 0.2, duration: 0.4, ease: "easeOut" }}
        data-lenis-prevent
      >
        <AttackMatrix />
      </motion.div>
    </motion.div>
  );
};

export default AttackDashboard;
