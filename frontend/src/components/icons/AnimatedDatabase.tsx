import React from 'react';
import { motion } from 'framer-motion';

export const AnimatedDatabase = ({ className }: { className?: string }) => {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <motion.ellipse cx="12" cy="5" rx="9" ry="3" variants={{ hover: { y: [-3, 0], transition: { duration: 0.6 } } }} />
      <motion.path d="M3 5V19A9 3 0 0 0 21 19V5" variants={{ hover: { y: [3, 0], transition: { duration: 0.6 } } }} />
      <path d="M3 12A9 3 0 0 0 21 12" />
    </svg>
  );
};
