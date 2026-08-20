import React from 'react';
import { motion } from 'framer-motion';

export const AnimatedBriefcase = ({ className }: { className?: string }) => {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <rect width="20" height="14" x="2" y="7" rx="2" ry="2" />
      <motion.path 
        d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16" 
        variants={{
          rest: { y: 0 },
          hover: { y: [-3, 0, -3, 0], transition: { duration: 0.8, ease: "easeInOut" } }
        }}
      />
    </svg>
  );
};
