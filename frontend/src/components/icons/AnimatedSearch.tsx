import React from 'react';
import { motion } from 'framer-motion';

export const AnimatedSearch = ({ className }: { className?: string }) => {
  return (
    <motion.svg 
      xmlns="http://www.w3.org/2000/svg" 
      viewBox="0 0 24 24" 
      fill="currentColor" 
      className={className}
      initial="rest"
      whileHover="hover"
    >
      <motion.path 
        d="M20.4,18.25 C20.4,18.25 16.61,14.49 16.61,14.49 C17.48,13.21 18,11.66 18,10 C18,5.58 14.41,2 10,2 C5.58,2 2,5.58 2,10 C2,14.41 5.58,18 10,18 C11.66,18 13.21,17.48 14.49,16.61 C14.49,16.61 18.28,20.37 18.28,20.37 C18.57,20.66 18.96,20.81 19.34,20.81 C19.73,20.81 20.11,20.66 20.4,20.37 C20.99,19.78 20.99,18.83 20.4,18.25z M5,10 C5,7.24 7.24,5 10,5 C12.75,5 15,7.24 15,10 C15,12.75 12.75,15 10,15 C7.24,15 5,12.75 5,10z"
        variants={{
          rest: { rotate: 0 },
          hover: { 
            rotate: [0, -10, 10, 0], 
            scale: [1, 1.1, 1],
            transition: { duration: 1.5, repeat: Infinity, ease: "easeInOut" } 
          }
        }}
        style={{ transformOrigin: "10px 10px" }}
      />
    </motion.svg>
  );
};
