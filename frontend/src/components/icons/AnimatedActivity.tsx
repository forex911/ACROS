import React from 'react';
import { motion } from 'framer-motion';

export const AnimatedActivity = ({ className }: { className?: string }) => {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <motion.path 
        d="M22 12h-4l-3 9L9 3l-3 9H2"
        variants={{
          rest: { pathLength: 1, opacity: 1 },
          hover: { pathLength: [0, 1], opacity: [0, 1, 1], transition: { duration: 1.2, ease: "easeInOut" } }
        }}
      />
    </svg>
  );
};
