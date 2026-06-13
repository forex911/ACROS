import React from 'react';
import { motion } from 'framer-motion';

// ─── Container variants for staggering children ───────────────────────────
export const staggerContainer = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.08,
      delayChildren: 0.1,
    },
  },
};

// ─── Individual item that fades + slides up ────────────────────────────────
export const fadeInUp = {
  hidden: { opacity: 0, y: 20 },
  visible: {
    opacity: 1,
    y: 0,
    transition: {
      duration: 0.45,
      ease: "easeOut",
    },
  },
};

// ─── Fade in from the side (left) ─────────────────────────────────────────
export const fadeInLeft = {
  hidden: { opacity: 0, x: -24 },
  visible: {
    opacity: 1,
    x: 0,
    transition: {
      duration: 0.45,
      ease: "easeOut",
    },
  },
};

// ─── Fade in from the side (right) ────────────────────────────────────────
export const fadeInRight = {
  hidden: { opacity: 0, x: 24 },
  visible: {
    opacity: 1,
    x: 0,
    transition: {
      duration: 0.45,
      ease: "easeOut",
    },
  },
};

// ─── Scale in (for cards, modals) ─────────────────────────────────────────
export const scaleIn = {
  hidden: { opacity: 0, scale: 0.92 },
  visible: {
    opacity: 1,
    scale: 1,
    transition: {
      duration: 0.35,
      ease: "easeOut",
    },
  },
};

// ─── Glowing pulse for cyber elements ─────────────────────────────────────
export const glowPulse = {
  initial: { boxShadow: '0 0 0px rgba(88,166,255,0)' },
  animate: {
    boxShadow: [
      '0 0 4px rgba(88,166,255,0.15)',
      '0 0 12px rgba(88,166,255,0.3)',
      '0 0 4px rgba(88,166,255,0.15)',
    ],
    transition: {
      duration: 3,
      repeat: Infinity,
      ease: 'easeInOut',
    },
  },
};

// ─── Helper component: Stagger Container ──────────────────────────────────
export const StaggerContainer: React.FC<{
  children: React.ReactNode;
  className?: string;
  delay?: number;
}> = ({ children, className = '', delay = 0.1 }) => {
  return (
    <motion.div
      className={className}
      variants={{
        hidden: { opacity: 0 },
        visible: {
          opacity: 1,
          transition: {
            staggerChildren: 0.08,
            delayChildren: delay,
          },
        },
      }}
      initial="hidden"
      animate="visible"
    >
      {children}
    </motion.div>
  );
};

// ─── Helper component: Fade Up Item ───────────────────────────────────────
export const FadeInItem: React.FC<{
  children: React.ReactNode;
  className?: string;
}> = ({ children, className = '' }) => {
  return (
    <motion.div className={className} variants={fadeInUp}>
      {children}
    </motion.div>
  );
};
