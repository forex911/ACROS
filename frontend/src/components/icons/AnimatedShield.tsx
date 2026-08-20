import React from 'react';
import { motion } from 'framer-motion';

export const AnimatedShield = ({ className }: { className?: string }) => {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2-1 4-2 7-2 2.5 0 5 1 7 2a1 1 0 0 1 1 1z" />
      <motion.line 
        x1="5" y1="12" x2="19" y2="12" 
        stroke="#ffffff" 
        strokeWidth="1.5"
        variants={{ rest: { opacity: 0, y: -4 }, hover: { opacity: [0, 1, 0], y: [-5, 7], transition: { duration: 1.2, ease: "linear" } } }} 
      />
    </svg>
  );
};
