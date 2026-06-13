import React from 'react';
import { motion } from 'framer-motion';
import type { LucideIcon } from 'lucide-react';
import { TrendingUp, TrendingDown } from 'lucide-react';

interface StatCardProps {
  title: string;
  value: string | number;
  icon: LucideIcon;
  trend?: {
    value: number;
    isUp: boolean;
    color?: 'red' | 'emerald';
  };
  color?: 'accent' | 'green' | 'alert' | 'default';
}

export const StatCard: React.FC<StatCardProps> = ({ title, value, icon: Icon, trend }) => {
  return (
    <motion.div
      className="p-8 border border-[#333333] bg-[#000000] flex flex-col cursor-default hover:border-[#ffffff] transition-colors"
      whileHover={{ y: -2 }}
    >
      <div className="flex items-center justify-between mb-8">
        <h3 className="font-heading font-bold text-sm text-[#888888] uppercase tracking-widest">{title}</h3>
        <Icon className="w-5 h-5 text-[#ffffff]" />
      </div>

      <div className="flex justify-between items-end">
        <span className="text-4xl font-heading font-bold text-[#ffffff] tracking-tighter">{value}</span>

        {trend && (
          <div className="mt-4 flex items-center text-xs font-mono font-bold uppercase tracking-widest">
            {trend.isUp ? <TrendingUp size={14} className="mr-2" /> : <TrendingDown size={14} className="mr-2" />}
            <span className={trend.color === 'red' ? 'text-red-500' : trend.color === 'emerald' ? 'text-emerald-500' : trend.isUp ? 'text-[#ffffff]' : 'text-[#888888]'}>
              {trend.isUp ? '+' : '-'}{trend.value}%
            </span>
          </div>
        )}
      </div>
    </motion.div>
  );
};
