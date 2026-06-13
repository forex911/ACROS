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
  };
  color?: 'accent' | 'green' | 'alert' | 'default';
}

export const StatCard: React.FC<StatCardProps> = ({ title, value, icon: Icon, trend, color = 'default' }) => {
  // Map our internal states to the new light theme colors
  const colorConfig = {
    accent: { bg: 'bg-[#c5f37d]', text: 'text-gray-900', iconBg: 'bg-gray-900', iconText: 'text-white' },
    green: { bg: 'bg-white', text: 'text-gray-900', iconBg: 'bg-[#c5f37d]', iconText: 'text-gray-900' },
    alert: { bg: 'bg-white', text: 'text-gray-900', iconBg: 'bg-red-100', iconText: 'text-red-600' },
    default: { bg: 'bg-white', text: 'text-gray-900', iconBg: 'bg-gray-100', iconText: 'text-gray-600' },
  };

  const currentStyle = colorConfig[color];

  return (
    <motion.div
      className={`p-6 rounded-[1.25rem] border border-gray-100 flex flex-col relative overflow-hidden group cursor-default shadow-[0_4px_20px_-2px_rgba(0,0,0,0.03)] ${currentStyle.bg}`}
      whileHover={{
        scale: 1.02,
        y: -4,
        boxShadow: `0 12px 24px -4px rgba(0,0,0,0.06)`,
        transition: { duration: 0.3, ease: 'easeOut' },
      }}
      whileTap={{ scale: 0.98 }}
    >
      <div className="flex items-center space-x-3 mb-6">
        <div className={`w-8 h-8 rounded-full flex items-center justify-center ${currentStyle.iconBg}`}>
          <Icon className={`w-4 h-4 ${currentStyle.iconText}`} />
        </div>
        <h3 className="text-gray-500 font-medium text-sm tracking-wide">{title}</h3>
      </div>
      
      <div className="flex justify-between items-end">
        <div className="flex items-baseline space-x-2">
          <span className={`text-2xl font-bold ${currentStyle.text}`}>{value}</span>
        </div>
        
        {trend && (
          <motion.div
            className={`text-xs font-medium flex items-center gap-1 ${trend.isUp ? 'text-[#7fb827]' : 'text-red-500'}`}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
          >
            {trend.isUp ? <TrendingUp className="w-3 h-3" /> : <TrendingDown className="w-3 h-3" />}
            <span>{Math.abs(trend.value)}%</span>
            <span className="text-gray-400 font-normal ml-1 hidden sm:inline">vs last</span>
          </motion.div>
        )}
      </div>
    </motion.div>
  );
};
