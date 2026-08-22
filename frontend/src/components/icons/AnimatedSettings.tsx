import React from 'react';
import { motion } from 'framer-motion';

export const AnimatedSettings = ({ className }: { className?: string }) => {
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
        transform="translate(12, 12) scale(0.6)"
        variants={{
          rest: { rotate: 0 },
          hover: { rotate: 90, transition: { duration: 2, repeat: Infinity, ease: "linear" } }
        }}
      >
        {/* Inner Circle */}
        <circle cx="0" cy="0" r="6.5" />
        
        {/* Outer Gear */}
        <path d="M4.53,15.1 C4.68,13.67 5.51,12.41 6.75,11.69 C7.99,10.97 9.5,10.89 10.81,11.47 L13.48,12.64 C15.4,10.6 16.87,8.12 17.7,5.36 L15.34,3.63 C14.18,2.78 13.5,1.43 13.5,0 C13.5,-1.43 14.18,-2.78 15.34,-3.63 L17.7,-5.36 C16.87,-8.12 15.4,-10.6 13.48,-12.64 L10.81,-11.47 C9.5,-10.89 7.99,-10.97 6.75,-11.69 C5.51,-12.41 4.68,-13.67 4.53,-15.1 L4.21,-18 C2.86,-18.32 1.45,-18.5 0,-18.5 C-1.45,-18.5 -2.86,-18.32 -4.21,-18 L-4.53,-15.1 C-4.68,-13.67 -5.51,-12.41 -6.75,-11.69 C-7.99,-10.97 -9.5,-10.89 -10.81,-11.47 L-13.48,-12.64 C-15.4,-10.6 -16.87,-8.12 -17.7,-5.36 L-15.34,-3.63 C-14.18,-2.78 -13.5,-1.43 -13.5,0 C-13.5,1.43 -14.18,2.78 -15.34,3.63 L-17.7,5.36 C-16.87,8.12 -15.4,10.6 -13.48,12.64 L-10.81,11.47 C-9.5,10.89 -7.99,10.97 -6.75,11.69 C-5.51,12.41 -4.68,13.67 -4.53,15.1 L-4.21,18 C-2.86,18.32 -1.45,18.5 0,18.5 C1.45,18.5 2.86,18.32 4.21,18 L4.53,15.1z" />
      </motion.g>
    </svg>
  );
};
