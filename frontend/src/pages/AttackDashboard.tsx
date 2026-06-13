import React from 'react';
import { motion } from 'framer-motion';
import { Target, Activity, Zap } from 'lucide-react';
import { AttackMatrix } from '../components/threat/AttackMatrix';

const AttackDashboard: React.FC = () => {
  return (
    <motion.div
      className="flex flex-col h-full space-y-6 max-w-full"
      initial={{ opacity: 0, y: 18 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -12 }}
      transition={{ duration: 0.4, ease: [0.25, 0.46, 0.45, 0.94] }}
    >
      {/* Header */}
      <motion.div
        className="flex items-center justify-between bg-white p-6 rounded-xl border border-gray-100 shadow-sm"
        initial={{ opacity: 0, y: -12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.45, delay: 0.1 }}
      >
        <div>
          <h1 className="text-2xl font-bold text-gray-900 flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-purple-50 flex items-center justify-center text-purple-600 border border-purple-100">
              <Target className="w-5 h-5" />
            </div>
            ATT&CK Intelligence Matrix
          </h1>
          <p className="text-gray-500 text-sm mt-1 ml-13">Real-time correlation of sandbox telemetry to MITRE ATT&CK techniques.</p>
        </div>
        <motion.div
          className="flex gap-4"
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.25, duration: 0.4 }}
        >
           <motion.div
             className="flex items-center gap-2 px-4 py-2 bg-gray-50 border border-gray-200 rounded-lg shadow-sm"
             whileHover={{ scale: 1.02, transition: { duration: 0.2 } }}
           >
              <motion.div
                animate={{ scale: [1, 1.2, 1] }}
                transition={{ duration: 2, repeat: Infinity, ease: 'easeInOut' }}
              >
                <Activity size={16} className="text-green-600" />
              </motion.div>
              <span className="text-sm text-gray-700">Live Telemetry: <strong className="text-green-700">Active</strong></span>
           </motion.div>
           <motion.div
             className="flex items-center gap-2 px-4 py-2 bg-red-50 border border-red-200 rounded-lg shadow-sm"
             whileHover={{ scale: 1.02, transition: { duration: 0.2 } }}
           >
              <Zap size={16} className="text-red-600" />
              <span className="text-sm text-red-700">Techniques Detected: <strong>4</strong></span>
           </motion.div>
        </motion.div>
      </motion.div>

      {/* Main Matrix Area */}
      <motion.div
        className="flex-1 min-h-[600px] border border-gray-200 rounded-xl overflow-hidden bg-white shadow-sm relative flex flex-col"
        initial={{ opacity: 0, scale: 0.97 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ delay: 0.3, duration: 0.5, ease: [0.25, 0.46, 0.45, 0.94] }}
      >
          <div className="flex-1 w-full h-full p-4 overflow-hidden">
             <AttackMatrix />
          </div>
      </motion.div>
    </motion.div>
  );
};

export default AttackDashboard;
