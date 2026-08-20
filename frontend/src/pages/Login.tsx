import React, { useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import gsap from 'gsap';
import { useGSAP } from '@gsap/react';
import { useAuth } from '../hooks/useAuth';
import api from '../api/client';
import axios from 'axios';
import { Lock, User as UserIcon, UserPlus, LogIn } from 'lucide-react';

gsap.registerPlugin(useGSAP);

export const Login: React.FC = () => {
  const container = useRef<HTMLDivElement>(null);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [isSignUp, setIsSignUp] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();

  useGSAP(() => {
    const tl = gsap.timeline();
    
    tl.fromTo('.gsap-bg-grid', 
      { opacity: 0, scale: 1.1 },
      { opacity: 1, scale: 1, duration: 2, ease: 'power2.out' }
    )
    .fromTo('.gsap-card',
      { opacity: 0, y: 40 },
      { opacity: 1, y: 0, duration: 1, ease: 'power3.out' },
      '-=1.5'
    )
    .fromTo('.gsap-element',
      { opacity: 0, y: 20 },
      { opacity: 1, y: 0, duration: 0.8, stagger: 0.1, ease: 'power3.out' },
      '-=0.8'
    );
  }, { scope: container });

  const toggleMode = () => {
    setIsSignUp(!isSignUp);
    setError('');
    setSuccess('');
    setConfirmPassword('');

    gsap.fromTo('.gsap-card',
      { rotateY: 3, scale: 0.98 },
      { rotateY: 0, scale: 1, duration: 0.4, ease: 'power2.out' }
    );
  };

  const shakeCard = () => {
    gsap.fromTo('.gsap-card',
      { x: -10 },
      { x: 0, duration: 0.4, ease: 'elastic.out(1, 0.3)' }
    );
  };

  const API_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000';

  const handleSignUp = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    if (password !== confirmPassword) {
      setError('Passwords do not match');
      shakeCard();
      return;
    }

    if (password.length < 8) {
      setError('Password must be at least 8 characters');
      shakeCard();
      return;
    }

    if (username.length < 3) {
      setError('Username must be at least 3 characters');
      shakeCard();
      return;
    }

    setIsLoading(true);

    try {
      await axios.post(API_URL + '/auth/register', { username, password }, {
        headers: { 'Content-Type': 'application/json' },
      });

      setSuccess('Account created — signing you in...');

      // Auto-login after registration
      const res = await axios.post(API_URL + '/auth/login', { username, password }, {
        headers: { 'Content-Type': 'application/json' },
        withCredentials: true,
      });
      const { access_token } = res.data;
      const userRes = await axios.get(API_URL + '/auth/me', {
        headers: { Authorization: 'Bearer ' + access_token }
      });
      login(access_token, userRes.data);
      navigate('/');
    } catch (err: any) {
      const detail = err.response?.data?.detail;
      if (detail === 'user_exists') {
        setError('Username already taken');
      } else {
        setError(detail || 'Registration failed');
      }
      setIsLoading(false);
      shakeCard();
    }
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    setIsLoading(true);

    localStorage.removeItem('access_token');
    delete api.defaults.headers.common['Authorization'];

    try {
      const res = await axios.post(API_URL + '/auth/login', { username, password }, {
        headers: { 'Content-Type': 'application/json' },
        withCredentials: true,
      });
      const { access_token } = res.data;
      const userRes = await axios.get(API_URL + '/auth/me', {
        headers: { Authorization: 'Bearer ' + access_token }
      });
      login(access_token, userRes.data);
      navigate('/');
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Authentication failed. Use admin / aegis123 for demo.');
      setIsLoading(false);
      shakeCard();
    }
  };

  return (
    <div ref={container} className="min-h-screen flex items-center justify-center bg-[#000000] relative overflow-hidden font-sans">
      {/* Decorative Grid Lines */}
      <div className="gsap-bg-grid absolute inset-0 bg-[linear-gradient(rgba(255,255,255,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.03)_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_60%_at_50%_50%,#000_70%,transparent_100%)]"></div>

      <div className="gsap-card p-12 w-full max-w-md relative z-10 border border-[#333333] bg-[#000000]">
        {/* Logo */}
        <div className="flex flex-col items-center mb-12">
          <div className="gsap-element w-24 h-24 flex items-center justify-center mb-4">
            <img src="/aegis.png" alt="Aegis Logo" className="w-full h-full object-contain drop-shadow-md" />
          </div>
          <h2 className="gsap-element text-4xl font-heading font-black text-[#ffffff] tracking-tighter uppercase">Aegis</h2>
          <p className="gsap-element text-[#888888] font-mono text-xs mt-2 tracking-widest uppercase">
            {isSignUp ? 'Create Account' : 'Authorization Protocol'}
          </p>
        </div>

        {/* Error */}
        {error && (
          <div className="bg-[#111111] border border-[#ffffff] text-[#ffffff] px-4 py-3 mb-6 text-xs font-mono font-bold flex items-center gap-3 uppercase tracking-wider">
            <div className="w-2 h-2 bg-[#ffffff] shrink-0" />
            {error}
          </div>
        )}

        {/* Success */}
        {success && (
          <div className="bg-[#111111] border border-[#22c55e] text-[#22c55e] px-4 py-3 mb-6 text-xs font-mono font-bold flex items-center gap-3 uppercase tracking-wider">
            <div className="w-2 h-2 bg-[#22c55e] shrink-0" />
            {success}
          </div>
        )}

        {/* Form */}
        <form onSubmit={isSignUp ? handleSignUp : handleLogin} className="space-y-6">
          <div className="gsap-element">
            <label className="block text-[#888888] text-[11px] font-mono font-bold uppercase tracking-widest mb-2">Username</label>
            <div className="relative">
              <UserIcon className="h-4 w-4 absolute left-4 top-1/2 -translate-y-1/2 text-[#666666]" />
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full bg-[#000000] border border-[#333333] pl-12 pr-4 py-3.5 text-sm font-mono text-[#ffffff] placeholder:text-[#444444] focus:border-[#ffffff] transition-colors"
                placeholder="USER_ID"
                required
              />
            </div>
          </div>

          <div className="gsap-element">
            <label className="block text-[#888888] text-[11px] font-mono font-bold uppercase tracking-widest mb-2">Password</label>
            <div className="relative">
              <Lock className="h-4 w-4 absolute left-4 top-1/2 -translate-y-1/2 text-[#666666]" />
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full bg-[#000000] border border-[#333333] pl-12 pr-4 py-3.5 text-sm font-mono text-[#ffffff] placeholder:text-[#444444] focus:border-[#ffffff] transition-colors"
                placeholder="••••••••"
                required
              />
            </div>
          </div>

          {isSignUp && (
            <div className="gsap-element">
              <label className="block text-[#888888] text-[11px] font-mono font-bold uppercase tracking-widest mb-2">Confirm Password</label>
              <div className="relative">
                <Lock className="h-4 w-4 absolute left-4 top-1/2 -translate-y-1/2 text-[#666666]" />
                <input
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  className="w-full bg-[#000000] border border-[#333333] pl-12 pr-4 py-3.5 text-sm font-mono text-[#ffffff] placeholder:text-[#444444] focus:border-[#ffffff] transition-colors"
                  placeholder="••••••••"
                  required
                />
              </div>
            </div>
          )}

          <button
            type="submit"
            disabled={isLoading}
            className="gsap-element w-full bg-[#ffffff] text-[#000000] font-heading font-bold uppercase tracking-widest py-4 mt-8 flex items-center justify-center gap-3 disabled:opacity-50 hover:bg-[#000000] hover:text-[#ffffff] border border-[#ffffff] transition-colors active:scale-95"
          >
            {isLoading ? (
              <>
                <div className="w-4 h-4 border-2 border-[#000000] border-t-transparent rounded-full animate-spin" />
                {isSignUp ? 'CREATING ACCOUNT...' : 'AUTHENTICATING...'}
              </>
            ) : (
              <>
                {isSignUp ? <UserPlus className="w-4 h-4" /> : <LogIn className="w-4 h-4" />}
                {isSignUp ? 'CREATE ACCOUNT' : 'INITIALIZE SESSION'}
              </>
            )}
          </button>
        </form>

        {/* Toggle Sign In / Sign Up */}
        <div className="gsap-element mt-8 pt-6 border-t border-[#222222] text-center">
          <p className="text-[11px] font-mono text-[#666666] tracking-wider">
            {isSignUp ? 'Already have an account?' : "Don't have an account?"}
          </p>
          <button
            onClick={toggleMode}
            type="button"
            className="mt-2 text-xs font-mono font-bold text-[#ffffff] uppercase tracking-widest hover:text-[#888888] transition-colors"
          >
            {isSignUp ? '← SIGN IN' : 'SIGN UP →'}
          </button>
        </div>

        {/* Demo hint - only show on login mode */}
        {!isSignUp && (
          <div className="gsap-element mt-6 pt-6 border-t border-[#222222] text-center">
            <p className="text-[10px] font-mono font-bold text-[#666666] mb-3 uppercase tracking-widest">Demo Access</p>
            <div className="text-xs font-mono flex items-center justify-center gap-3">
              <code className="text-[#ffffff]">admin</code>
              <span className="text-[#444444]">/</span>
              <code className="text-[#ffffff]">aegis123</code>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
