import React from 'react';
import { motion } from 'framer-motion';

export const AnimatedSearch = ({ className }: { className?: string }) => {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <motion.circle cx="11" cy="11" r="8" variants={{ hover: { scale: [1, 1.15, 1], transition: { duration: 0.6 } } }} />
      <line x1="21" y1="21" x2="16.65" y2="16.65" />
    </svg>
  );
};
