import React from 'react';
import { LucideIcon } from 'lucide-react';

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
  const colorClasses = {
    accent: 'text-cyber-accent bg-cyber-accent',
    green: 'text-cyber-green bg-cyber-green',
    alert: 'text-cyber-alert bg-cyber-alert',
    default: 'text-gray-400 bg-gray-400',
  };

  const textColor = colorClasses[color].split(' ')[0];
  const bgColor = colorClasses[color].split(' ')[1];

  return (
    <div className="cyber-panel p-6 flex flex-col relative overflow-hidden group">
      <div className={`absolute top-0 right-0 w-32 h-32 ${bgColor} opacity-5 rounded-full -mr-16 -mt-16 transition-transform group-hover:scale-110`}></div>
      <div className="flex justify-between items-start mb-4">
        <h3 className="text-gray-400 font-mono text-sm tracking-wider">{title}</h3>
        <Icon className={`w-5 h-5 ${textColor}`} />
      </div>
      <div className="flex items-baseline space-x-2">
        <span className={`text-4xl font-bold ${textColor}`}>{value}</span>
      </div>
      {trend && (
        <div className={`mt-4 text-xs font-mono flex items-center ${trend.isUp ? 'text-cyber-alert' : 'text-cyber-green'}`}>
          {trend.isUp ? '▲' : '▼'} {Math.abs(trend.value)}% from last week
        </div>
      )}
    </div>
  );
};
