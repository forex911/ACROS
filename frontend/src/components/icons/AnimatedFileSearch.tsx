import React from 'react';
import { motion } from 'framer-motion';

export const AnimatedFileSearch = ({ className }: { className?: string }) => {
  return (
    <svg 
      xmlns="http://www.w3.org/2000/svg" 
      viewBox="0 0 24 24" 
      fill="none" 
      stroke="currentColor" 
      strokeWidth="2" 
      strokeLinecap="round" 
      strokeLinejoin="round" 
      className={className}
    >
      <motion.g 

      >
        {/* Document Outline */}
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
        
        {/* Folded Corner */}
        <polyline points="14 2 14 8 20 8" />
        
        {/* Top Line */}
        <motion.line 
          x1="8" y1="13" x2="16" y2="13" 
          variants={{
            rest: { pathLength: 1, opacity: 1 },
            hover: { 
              pathLength: [0, 1, 1], 
              opacity: [1, 1, 0], 
              transition: { duration: 1.5, repeat: Infinity, ease: "easeInOut" } 
            }
          }}
        />
        
        {/* Bottom Line */}
        <motion.line 
          x1="8" y1="17" x2="12" y2="17" 
          variants={{
            rest: { pathLength: 1, opacity: 1 },
            hover: { 
              pathLength: [0, 1, 1], 
              opacity: [1, 1, 0], 
              transition: { duration: 1.5, repeat: Infinity, ease: "easeInOut", delay: 0.2 } 
            }
          }}
        />
      </motion.g>
    </svg>
  );
};
