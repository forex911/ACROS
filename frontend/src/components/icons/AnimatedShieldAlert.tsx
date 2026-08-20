import React from 'react';
import { motion } from 'framer-motion';

export const AnimatedShieldAlert = ({ className }: { className?: string }) => {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10" />
      <motion.line x1="12" y1="8" x2="12" y2="12" variants={{ hover: { opacity: [1, 0, 1, 0, 1], transition: { duration: 0.8 } } }} />
      <motion.line x1="12" y1="16" x2="12.01" y2="16" variants={{ hover: { opacity: [1, 0, 1, 0, 1], transition: { duration: 0.8 } } }} />
    </svg>
  );
};
