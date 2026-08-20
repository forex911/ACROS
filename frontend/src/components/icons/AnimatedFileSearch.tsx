import React from 'react';
import { motion } from 'framer-motion';

export const AnimatedFileSearch = ({ className }: { className?: string }) => {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <path d="M14 2v4a2 2 0 0 0 2 2h4" />
      <path d="M4.268 21a2 2 0 0 0 1.727 1H18a2 2 0 0 0 2-2V7l-5-5H6a2 2 0 0 0-2 2v3" />
      <motion.g variants={{ rest: { x: 0 }, hover: { x: [0, 6, -2, 0], transition: { duration: 1.2, ease: "easeInOut" } } }}>
        <circle cx="5" cy="14" r="3" />
        <path d="m9 18-1.5 1.5" />
      </motion.g>
    </svg>
  );
};
