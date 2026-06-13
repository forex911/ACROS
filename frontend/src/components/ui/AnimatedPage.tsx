import React from 'react';
import { motion } from 'framer-motion';

/**
 * Wraps a page-level component with a smooth fade + upward slide entrance.
 * Use this as the outermost wrapper for each route page.
 */
export const AnimatedPage: React.FC<{ children: React.ReactNode; className?: string }> = ({ children, className = '' }) => {
  return (
    <motion.div
      className={className}
      initial={{ opacity: 0, y: 18 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -12 }}
      transition={{
        duration: 0.4,
        ease: "easeOut", // ease-out-quad
      }}
    >
      {children}
    </motion.div>
  );
};
