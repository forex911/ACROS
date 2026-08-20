import React from 'react';
import { motion } from 'framer-motion';

export const AnimatedChevron = ({ className }: { className?: string }) => {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <motion.polyline 
        points="6 9 12 15 18 9" 
        variants={{ hover: { y: [0, 4, 0], transition: { duration: 0.6 } } }}
      />
    </svg>
  );
};
