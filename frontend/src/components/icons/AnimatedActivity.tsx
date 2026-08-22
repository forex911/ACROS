import React from 'react';
import { motion } from 'framer-motion';

export const AnimatedActivity = ({ className }: { className?: string }) => {
  return (
    <motion.svg 
      xmlns="http://www.w3.org/2000/svg" 
      viewBox="0 0 24 24" 
      fill="none" 
      stroke="currentColor" 
      strokeWidth="2" 
      strokeLinecap="round" 
      strokeLinejoin="round" 
      className={className}

    >
      <motion.g transform="translate(12, 12)">
        <motion.path 
          d="M-10,0 L-5,0 L-3.5,4.5 L-0.5,-7.5 L1.5,4.5 L2.5,0 L10,0"
          variants={{
            rest: { pathLength: 1, opacity: 1, strokeDasharray: "none" },
            hover: { 
              pathLength: [0, 1, 1],
              opacity: [1, 1, 0],
              transition: { 
                duration: 1.5, 
                ease: "easeInOut", 
                repeat: Infinity 
              } 
            }
          }}
        />
      </motion.g>
    </motion.svg>
  );
};
