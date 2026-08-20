import React from 'react';
import { motion } from 'framer-motion';

export const AnimatedBell = ({ className }: { className?: string }) => {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <motion.g style={{ transformOrigin: 'top center' }} variants={{ hover: { rotate: [0, 15, -10, 5, 0], transition: { duration: 0.8 } } }}>
        <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
        <motion.path d="M13.73 21a2 2 0 0 1-3.46 0" variants={{ hover: { x: [0, -3, 3, -1, 0], transition: { duration: 0.8 } } }} />
      </motion.g>
    </svg>
  );
};
