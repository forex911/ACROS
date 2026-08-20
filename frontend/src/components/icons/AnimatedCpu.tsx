import React from 'react';
import { motion } from 'framer-motion';

export const AnimatedCpu = ({ className }: { className?: string }) => {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <rect x="4" y="4" width="16" height="16" rx="2" ry="2" />
      <motion.rect x="9" y="9" width="6" height="6" variants={{ hover: { scale: [1, 1.2, 1], transition: { duration: 0.8 } } }} />
      <motion.g variants={{ hover: { opacity: [0.3, 1, 0.3, 1], transition: { duration: 0.8 } } }}>
        <line x1="9" y1="1" x2="9" y2="4" /><line x1="15" y1="1" x2="15" y2="4" />
        <line x1="9" y1="20" x2="9" y2="23" /><line x1="15" y1="20" x2="15" y2="23" />
        <line x1="20" y1="9" x2="23" y2="9" /><line x1="20" y1="14" x2="23" y2="14" />
        <line x1="1" y1="9" x2="4" y2="9" /><line x1="1" y1="14" x2="4" y2="14" />
      </motion.g>
    </svg>
  );
};
