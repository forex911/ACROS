import React from 'react';
import { motion } from 'framer-motion';

export const AnimatedTerminal = ({ className }: { className?: string }) => {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <motion.polyline 
        points="4 17 10 11 4 5" 
        variants={{ hover: { x: [0, 2, 0], transition: { duration: 0.6 } } }}
      />
      <motion.line 
        x1="12" x2="20" y1="19" y2="19" 
        variants={{ rest: { opacity: 1 }, hover: { opacity: [1, 0, 1, 0, 1], transition: { duration: 0.8, ease: "linear" } } }}
      />
    </svg>
  );
};
