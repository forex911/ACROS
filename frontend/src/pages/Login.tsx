import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { useAuth } from '../hooks/useAuth';
import api from '../api/client';
import { Lock, User as UserIcon, Shield } from 'lucide-react';

export const Login: React.FC = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [isLoggingIn, setIsLoggingIn] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();

  const DEMO_USER = { username: 'admin', roles: ['admin', 'analyst'] };
  const DEMO_TOKEN = 'demo-token-sentinel-ai';

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsLoggingIn(true);

    // Authentication logic proceeds via backend

    try {
      const res = await api.post('/auth/login', {
        username,
        password
      });

      const { access_token } = res.data;
      const userRes = await api.get('/auth/me', {
        headers: { Authorization: `Bearer ${access_token}` }
      });

      login(access_token, userRes.data);
      navigate('/');
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Authentication failed. Use admin / sentinel123 for demo.');
      setIsLoggingIn(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#f4f6f8] relative overflow-hidden font-sans">
      {/* Abstract background shapes */}
      <motion.div
        className="absolute top-[-10%] left-[-10%] w-[600px] h-[600px] rounded-full bg-[#c5f37d]/20 blur-[100px]"
        animate={{ scale: [1, 1.05, 1] }}
        transition={{ duration: 10, repeat: Infinity, ease: 'easeInOut' }}
      />
      <motion.div
        className="absolute bottom-[-10%] right-[-10%] w-[500px] h-[500px] rounded-full bg-blue-500/10 blur-[100px]"
        animate={{ scale: [1, 1.1, 1] }}
        transition={{ duration: 8, repeat: Infinity, ease: 'easeInOut' }}
      />

      <motion.div
        className="bg-white p-10 w-full max-w-md relative z-10 rounded-2xl shadow-[0_8px_30px_rgb(0,0,0,0.04)] border border-gray-100"
        initial={{ opacity: 0, y: 24 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, ease: [0.25, 0.46, 0.45, 0.94] }}
      >
        {/* Logo + Title */}
        <motion.div
          className="flex flex-col items-center mb-8"
          initial={{ opacity: 0, y: -16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1, duration: 0.4 }}
        >
          <div className="w-16 h-16 bg-green-50 rounded-2xl flex items-center justify-center mb-5 border border-green-100 shadow-sm">
            <Shield className="w-8 h-8 text-green-600" />
          </div>
          <h2 className="text-2xl font-extrabold text-gray-900 tracking-tight">Sentinel<span className="text-green-600">AI</span></h2>
          <p className="text-gray-500 text-sm mt-1 font-medium">Enterprise Threat Intelligence</p>
        </motion.div>

        {/* Error message */}
        <AnimatePresence>
          {error && (
            <motion.div
              className="bg-red-50 border border-red-100 text-red-600 px-4 py-3 rounded-xl mb-6 text-sm font-medium flex items-center gap-2"
              initial={{ opacity: 0, height: 0, marginBottom: 0 }}
              animate={{ opacity: 1, height: 'auto', marginBottom: 24 }}
              exit={{ opacity: 0, height: 0, marginBottom: 0 }}
              transition={{ duration: 0.3 }}
            >
              <div className="w-1.5 h-1.5 bg-red-600 rounded-full"></div>
              {error}
            </motion.div>
          )}
        </AnimatePresence>

        {/* Form */}
        <motion.form
          onSubmit={handleLogin}
          className="space-y-5"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.2, duration: 0.4 }}
        >
          <div>
            <label className="block text-gray-700 text-xs font-bold uppercase tracking-wide mb-2">Username</label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
                <UserIcon className="h-4 w-4 text-gray-400" />
              </div>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full bg-gray-50 border border-gray-200 rounded-xl pl-10 pr-4 py-2.5 text-gray-900 font-medium focus:outline-none focus:border-green-500 focus:ring-2 focus:ring-green-500/20 transition-all duration-200"
                placeholder="Enter username"
                required
              />
            </div>
          </div>
          
          <div>
            <label className="block text-gray-700 text-xs font-bold uppercase tracking-wide mb-2">Password</label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
                <Lock className="h-4 w-4 text-gray-400" />
              </div>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full bg-gray-50 border border-gray-200 rounded-xl pl-10 pr-4 py-2.5 text-gray-900 font-medium focus:outline-none focus:border-green-500 focus:ring-2 focus:ring-green-500/20 transition-all duration-200"
                placeholder="••••••••"
                required
              />
            </div>
          </div>

          <motion.button
            type="submit"
            disabled={isLoggingIn}
            className="w-full bg-gray-900 text-white font-bold py-3 rounded-xl mt-6 flex items-center justify-center gap-2 disabled:opacity-70 hover:bg-gray-800 transition-colors shadow-sm"
            whileHover={{ scale: 1.01 }}
            whileTap={{ scale: 0.98 }}
          >
            {isLoggingIn ? (
              <>
                <motion.div
                  className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full"
                  animate={{ rotate: 360 }}
                  transition={{ duration: 0.8, repeat: Infinity, ease: 'linear' }}
                />
                Authenticating...
              </>
            ) : (
              'Sign In'
            )}
          </motion.button>
        </motion.form>

        {/* Demo credentials hint */}
        <motion.div
          className="mt-8 p-4 bg-gray-50 border border-gray-100 rounded-xl text-center"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.4, duration: 0.4 }}
        >
          <p className="text-xs font-bold text-gray-400 mb-2 uppercase tracking-wide">Demo Access</p>
          <div className="text-sm flex items-center justify-center gap-3">
            <div className="bg-white px-2 py-1 rounded border border-gray-200 shadow-sm text-gray-600 font-medium">admin</div>
            <span className="text-gray-300">•</span>
            <div className="bg-white px-2 py-1 rounded border border-gray-200 shadow-sm text-gray-600 font-medium">sentinel123</div>
          </div>
        </motion.div>
      </motion.div>
    </div>
  );
};
