import React from 'react';
import { motion } from 'framer-motion';

export const AnimatedPlus = ({ className }: { className?: string }) => {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <motion.g variants={{ hover: { rotate: [0, 90], scale: [1, 1.2, 1], transition: { duration: 0.6, ease: "easeInOut" } } }} style={{ transformOrigin: "12px 12px" }}>
        <line x1="12" y1="5" x2="12" y2="19" />
        <line x1="5" y1="12" x2="19" y2="12" />
      </motion.g>
    </svg>
  );
};
