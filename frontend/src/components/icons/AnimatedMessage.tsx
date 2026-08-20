import React from 'react';
import { motion } from 'framer-motion';

export const AnimatedMessage = ({ className }: { className?: string }) => {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <motion.path 
        d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" 
        variants={{ hover: { scale: [1, 1.05, 1], transition: { duration: 0.6 } } }}
      />
      <motion.g variants={{ hover: { opacity: [0, 1, 0, 1], transition: { duration: 0.8 } } }}>
        <circle cx="8" cy="12" r="1" fill="currentColor"/>
        <circle cx="12" cy="12" r="1" fill="currentColor"/>
        <circle cx="16" cy="12" r="1" fill="currentColor"/>
      </motion.g>
    </svg>
  );
};
