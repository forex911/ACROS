import React, { useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import gsap from 'gsap';
import { useGSAP } from '@gsap/react';
import { useAuth } from '../hooks/useAuth';
import api from '../api/client';
import { Lock, Mail, User as UserIcon, UserPlus, LogIn, KeyRound } from 'lucide-react';
import { OTPVerification } from '../components/OTPVerification';

gsap.registerPlugin(useGSAP);

type AuthStep = 'credentials' | 'otp' | 'forgot-password' | 'reset-password';

export const Login: React.FC = () => {
  const container = useRef<HTMLDivElement>(null);
  const [identifier, setIdentifier] = useState(''); // email OR username
  const [email, setEmail] = useState(''); // Just to store email explicitly for OTP/Reset
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [otp, setOtp] = useState('');
  
  const [error, setError] = useState('');
  const [otpError, setOtpError] = useState('');
  const [success, setSuccess] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [isSignUp, setIsSignUp] = useState(false);
  
  const [step, setStep] = useState<AuthStep>('credentials');
  
  const { checkAuth } = useAuth();
  const navigate = useNavigate();


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

  const switchStep = (newStep: AuthStep) => {
    setError('');
    setSuccess('');
    gsap.to('.gsap-card', {
      rotateY: 3, scale: 0.98, opacity: 0.5, duration: 0.2, ease: 'power2.in',
      onComplete: () => {
        setStep(newStep);
        gsap.fromTo('.gsap-card',
          { rotateY: -3, scale: 0.98, opacity: 0.5 },
          { rotateY: 0, scale: 1, opacity: 1, duration: 0.4, ease: 'power2.out' }
        );
      }
    });
  };

  const shakeCard = () => {
    gsap.fromTo('.gsap-card',
      { x: -10 },
      { x: 0, duration: 0.4, ease: 'elastic.out(1, 0.3)' }
    );
  };

  // ── SIGN UP ────────────────────────────────────────
  const handleSignUp = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    if (!identifier || !identifier.includes('@')) {
      setError('Please enter a valid email address');
      shakeCard();
      return;
    }
    if (username.length < 3) {
      setError('Username must be at least 3 characters');
      shakeCard();
      return;
    }
    if (password.length < 8) {
      setError('Password must be at least 8 characters');
      shakeCard();
      return;
    }
    if (password !== confirmPassword) {
      setError('Passwords do not match');
      shakeCard();
      return;
    }

    setIsLoading(true);
    setEmail(identifier); // Save email for OTP step
    try {
      const res = await api.post('/auth/register', { username, email: identifier, password });
      setIsLoading(false);
      if (res.data.requiresOTP) {
        switchStep('otp');
      }
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Registration failed');
      shakeCard();
      setIsLoading(false);
    }
  };

  // ── LOG IN ─────────────────────────────────────────
  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    setIsLoading(true);

    try {
      // If identifier is not an email, resolve it
      let resolvedEmail = identifier;
      if (!identifier.includes('@')) {
        try {
          const res = await api.get(`/auth/resolve-username?username=${identifier}`);
          resolvedEmail = res.data.email;
        } catch (err) {
          setError('Username not found');
          shakeCard();
          setIsLoading(false);
          return;
        }
      }
      setEmail(resolvedEmail);

      const res = await api.post('/auth/login', { username: resolvedEmail, password });
      setIsLoading(false);
      
      if (res.data.requiresOTP) {
        switchStep('otp');
      } else if (res.data.access_token) {
        // Logged in directly
        localStorage.setItem('token', res.data.access_token);
        await checkAuth();
        navigate('/dashboard');
      }
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Login failed');
      shakeCard();
      setIsLoading(false);
    }
  };

  // ── OTP VERIFY (for new users or unverified) ──────
  const handleOTPVerify = async (code: string) => {
    setOtpError('');
    try {
      const res = await api.post('/auth/verify-otp', {
        email: email,
        otp: code
      });
      if (res.data.access_token) {
        localStorage.setItem('token', res.data.access_token);
        await checkAuth();
        navigate('/dashboard');
      }
    } catch (err: any) {
      throw new Error(err.response?.data?.detail || 'Invalid verification code');
    }
  };

  const handleOTPResend = async () => {
    try {
      await api.post('/auth/resend-otp', { email: email });
    } catch (err: any) {
      throw new Error(err.response?.data?.detail || 'Failed to resend code');
    }
  };

  const handleOTPBack = () => {
    switchStep('credentials');
  };

  // ── FORGOT PASSWORD ────────────────────────────────
  const handleForgotPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    if (!identifier || !identifier.includes('@')) {
      setError('Please enter a valid email address');
      shakeCard();
      return;
    }
    setEmail(identifier);
    setIsLoading(true);
    try {
      await api.post('/auth/forgot-password', { email: identifier });
      setIsLoading(false);
      switchStep('reset-password');
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Request failed');
      shakeCard();
      setIsLoading(false);
    }
  };

  // ── RESET PASSWORD ─────────────────────────────────
  const handleResetPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
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
    if (!otp) {
      setError('Please enter the OTP');
      shakeCard();
      return;
    }

    setIsLoading(true);
    try {
      await api.post('/auth/reset-password', { email, otp, new_password: password });
      setIsLoading(false);
      setSuccess('Password updated successfully. Please log in.');
      setPassword('');
      setConfirmPassword('');
      setOtp('');
      switchStep('credentials');
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to reset password');
      shakeCard();
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#050505] bg-[url('/background-auth.webp')] bg-cover bg-center bg-no-repeat flex items-center justify-center p-4 overflow-hidden relative" ref={container}>
      {/* Dynamic Grid Background */}
      <div className="absolute inset-0 z-0">
        <div className="absolute inset-0 bg-black/60"></div>
        <div className="gsap-bg-grid absolute inset-0 bg-[url('https://grainy-gradients.vercel.app/noise.svg')] opacity-20 mix-blend-overlay"></div>
        <div className="absolute inset-0 bg-[linear-gradient(rgba(255,255,255,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.03)_1px,transparent_1px)] bg-[size:40px_40px] [mask-image:radial-gradient(ellipse_80%_80%_at_50%_50%,#000_20%,transparent_100%)]"></div>
      </div>

      <div className="gsap-card p-8 w-full max-w-sm relative z-10 border border-[#333333] bg-[#000000]">
        
        {/* === OTP STEP === */}
        {step === 'otp' && (
          <>
            <div className="flex flex-col items-center mb-6">
              <div className="gsap-element w-12 h-12 flex items-center justify-center mb-3">
                <img src="/acros.png" alt="ACROS Logo" className="w-full h-full object-contain drop-shadow-md" />
              </div>
            </div>
            <OTPVerification
              email={email}
              onVerify={handleOTPVerify}
              onResend={handleOTPResend}
              onBack={handleOTPBack}
              error={otpError}
              clearError={() => setOtpError('')}
            />
          </>
        )}

        {/* === FORGOT PASSWORD STEP === */}
        {step === 'forgot-password' && (
          <>
            <div className="flex flex-col items-center mb-8">
              <div className="gsap-element w-16 h-16 flex items-center justify-center mb-4">
                <img src="/acros.png" alt="ACROS Logo" className="w-full h-full object-contain drop-shadow-md" />
              </div>
              <h2 className="gsap-element text-2xl font-heading font-black text-[#ffffff] tracking-tighter uppercase">RESET PASSWORD</h2>
              <p className="gsap-element text-[#888888] font-mono text-xs mt-2 tracking-widest text-center uppercase">
                Enter your email to receive a code.
              </p>
            </div>
            {error && (
              <div className="bg-[#111111] border border-[#ffffff] text-[#ffffff] px-4 py-3 mb-6 text-xs font-mono font-bold flex items-center gap-3 uppercase tracking-wider">
                <div className="w-2 h-2 bg-[#ffffff] shrink-0" />
                {error}
              </div>
            )}
            <form onSubmit={handleForgotPassword} className="space-y-4">
              <div className="gsap-element">
                <label className="block text-[#888888] text-[11px] font-mono font-bold uppercase tracking-widest mb-2">Email</label>
                <div className="relative">
                  <Mail className="h-4 w-4 absolute left-4 top-1/2 -translate-y-1/2 text-[#666666]" />
                  <input
                    type="text"
                    value={identifier}
                    onChange={(e) => setIdentifier(e.target.value)}
                    className="w-full bg-[#000000] border border-[#333333] pl-12 pr-4 py-3 text-sm font-mono text-[#ffffff] placeholder:text-[#444444] focus:border-[#ffffff] transition-colors"
                    placeholder="operator@acros.io"
                    required
                  />
                </div>
              </div>
              <button
                type="submit"
                disabled={isLoading}
                className="gsap-element w-full bg-[#ffffff] text-[#000000] font-heading font-bold uppercase tracking-widest py-3 mt-6 flex items-center justify-center gap-3 disabled:opacity-50 hover:bg-[#000000] hover:text-[#ffffff] border border-[#ffffff] transition-colors active:scale-95"
              >
                {isLoading ? 'SENDING...' : 'SEND RESET CODE'}
              </button>
              <button
                onClick={() => switchStep('credentials')}
                type="button"
                className="gsap-element mt-4 w-full text-xs font-mono font-bold text-[#666666] uppercase tracking-widest hover:text-[#ffffff] transition-colors"
              >
                Back to Login
              </button>
            </form>
          </>
        )}

        {/* === RESET PASSWORD STEP === */}
        {step === 'reset-password' && (
          <>
            <div className="flex flex-col items-center mb-8">
              <div className="gsap-element w-16 h-16 flex items-center justify-center mb-4">
                <img src="/acros.png" alt="ACROS Logo" className="w-full h-full object-contain drop-shadow-md" />
              </div>
              <h2 className="gsap-element text-2xl font-heading font-black text-[#ffffff] tracking-tighter uppercase">NEW PASSWORD</h2>
            </div>
            {error && (
              <div className="bg-[#111111] border border-[#ffffff] text-[#ffffff] px-4 py-3 mb-6 text-xs font-mono font-bold flex items-center gap-3 uppercase tracking-wider">
                <div className="w-2 h-2 bg-[#ffffff] shrink-0" />
                {error}
              </div>
            )}
            <form onSubmit={handleResetPassword} className="space-y-4">
              <div className="gsap-element">
                <label className="block text-[#888888] text-[11px] font-mono font-bold uppercase tracking-widest mb-2">OTP Code</label>
                <div className="relative">
                  <KeyRound className="h-4 w-4 absolute left-4 top-1/2 -translate-y-1/2 text-[#666666]" />
                  <input
                    type="text"
                    value={otp}
                    onChange={(e) => setOtp(e.target.value)}
                    className="w-full bg-[#000000] border border-[#333333] pl-12 pr-4 py-3 text-sm font-mono text-[#ffffff] placeholder:text-[#444444] focus:border-[#ffffff] transition-colors"
                    placeholder="6-Digit Code"
                    required
                  />
                </div>
              </div>
              <div className="gsap-element">
                <label className="block text-[#888888] text-[11px] font-mono font-bold uppercase tracking-widest mb-2">New Password</label>
                <div className="relative">
                  <Lock className="h-4 w-4 absolute left-4 top-1/2 -translate-y-1/2 text-[#666666]" />
                  <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="w-full bg-[#000000] border border-[#333333] pl-12 pr-4 py-3 text-sm font-mono text-[#ffffff] placeholder:text-[#444444] focus:border-[#ffffff] transition-colors"
                    placeholder="••••••••"
                    required
                  />
                </div>
              </div>
              <div className="gsap-element">
                <label className="block text-[#888888] text-[11px] font-mono font-bold uppercase tracking-widest mb-2">Confirm New Password</label>
                <div className="relative">
                  <Lock className="h-4 w-4 absolute left-4 top-1/2 -translate-y-1/2 text-[#666666]" />
                  <input
                    type="password"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    className="w-full bg-[#000000] border border-[#333333] pl-12 pr-4 py-3 text-sm font-mono text-[#ffffff] placeholder:text-[#444444] focus:border-[#ffffff] transition-colors"
                    placeholder="••••••••"
                    required
                  />
                </div>
              </div>
              <button
                type="submit"
                disabled={isLoading}
                className="gsap-element w-full bg-[#ffffff] text-[#000000] font-heading font-bold uppercase tracking-widest py-3 mt-6 flex items-center justify-center gap-3 disabled:opacity-50 hover:bg-[#000000] hover:text-[#ffffff] border border-[#ffffff] transition-colors active:scale-95"
              >
                {isLoading ? 'UPDATING...' : 'UPDATE PASSWORD'}
              </button>
              <button
                onClick={() => switchStep('credentials')}
                type="button"
                className="gsap-element mt-4 w-full text-xs font-mono font-bold text-[#666666] uppercase tracking-widest hover:text-[#ffffff] transition-colors"
              >
                Back to Login
              </button>
            </form>
          </>
        )}

        {/* === CREDENTIALS STEP === */}
        {step === 'credentials' && (
          <>
            <div className="flex flex-col items-center mb-8">
              <div className="gsap-element w-16 h-16 flex items-center justify-center mb-4">
                <img src="/acros.png" alt="ACROS Logo" className="w-full h-full object-contain drop-shadow-md" />
              </div>
              <h2 className="gsap-element text-2xl font-heading font-black text-[#ffffff] tracking-tighter uppercase">ACROS</h2>
              <p className="gsap-element text-[#888888] font-mono text-xs mt-2 tracking-widest uppercase">
                {isSignUp ? 'Create Account' : 'Authorization Protocol'}
              </p>
            </div>

            {error && (
              <div className="bg-[#111111] border border-[#ffffff] text-[#ffffff] px-4 py-3 mb-6 text-xs font-mono font-bold flex items-center gap-3 uppercase tracking-wider">
                <div className="w-2 h-2 bg-[#ffffff] shrink-0" />
                {error}
              </div>
            )}
            
            {success && (
              <div className="bg-[#111111] border border-[#22c55e] text-[#22c55e] px-4 py-3 mb-6 text-xs font-mono font-bold flex items-center gap-3 uppercase tracking-wider">
                <div className="w-2 h-2 bg-[#22c55e] shrink-0" />
                {success}
              </div>
            )}

            <form onSubmit={isSignUp ? handleSignUp : handleLogin} className="space-y-4">
              <div className="gsap-element">
                <label className="block text-[#888888] text-[11px] font-mono font-bold uppercase tracking-widest mb-2">
                  {isSignUp ? 'Email' : 'Email or Username'}
                </label>
                <div className="relative">
                  <Mail className="h-4 w-4 absolute left-4 top-1/2 -translate-y-1/2 text-[#666666]" />
                  <input
                    type="text"
                    value={identifier}
                    onChange={(e) => setIdentifier(e.target.value)}
                    className="w-full bg-[#000000] border border-[#333333] pl-12 pr-4 py-3 text-sm font-mono text-[#ffffff] placeholder:text-[#444444] focus:border-[#ffffff] transition-colors"
                    placeholder={isSignUp ? "operator@acros.io" : "email or username"}
                    required
                  />
                </div>
              </div>

              {isSignUp && (
                <div className="gsap-element">
                  <label className="block text-[#888888] text-[11px] font-mono font-bold uppercase tracking-widest mb-2">Username</label>
                  <div className="relative">
                    <UserIcon className="h-4 w-4 absolute left-4 top-1/2 -translate-y-1/2 text-[#666666]" />
                    <input
                      type="text"
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      className="w-full bg-[#000000] border border-[#333333] pl-12 pr-4 py-3 text-sm font-mono text-[#ffffff] placeholder:text-[#444444] focus:border-[#ffffff] transition-colors"
                      placeholder="USER_ID"
                      required
                    />
                  </div>
                </div>
              )}

              <div className="gsap-element">
                <div className="flex justify-between items-center mb-2">
                  <label className="block text-[#888888] text-[11px] font-mono font-bold uppercase tracking-widest">Password</label>
                  {!isSignUp && (
                    <button 
                      type="button" 
                      onClick={() => switchStep('forgot-password')}
                      className="text-[#666666] hover:text-[#ffffff] text-[10px] font-mono uppercase tracking-widest transition-colors"
                    >
                      Forgot?
                    </button>
                  )}
                </div>
                <div className="relative">
                  <Lock className="h-4 w-4 absolute left-4 top-1/2 -translate-y-1/2 text-[#666666]" />
                  <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="w-full bg-[#000000] border border-[#333333] pl-12 pr-4 py-3 text-sm font-mono text-[#ffffff] placeholder:text-[#444444] focus:border-[#ffffff] transition-colors"
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
                      className="w-full bg-[#000000] border border-[#333333] pl-12 pr-4 py-3 text-sm font-mono text-[#ffffff] placeholder:text-[#444444] focus:border-[#ffffff] transition-colors"
                      placeholder="••••••••"
                      required
                    />
                  </div>
                </div>
              )}

              <button
                type="submit"
                disabled={isLoading}
                className="gsap-element w-full bg-[#ffffff] text-[#000000] font-heading font-bold uppercase tracking-widest py-3 mt-6 flex items-center justify-center gap-3 disabled:opacity-50 hover:bg-[#000000] hover:text-[#ffffff] border border-[#ffffff] transition-colors active:scale-95"
              >
                {isLoading ? (
                  <>
                    <div className="w-4 h-4 border-2 border-[#000000] border-t-transparent rounded-full animate-spin" />
                    {isSignUp ? 'CREATING...' : 'AUTHENTICATING...'}
                  </>
                ) : (
                  <>
                    {isSignUp ? <UserPlus className="w-4 h-4" /> : <LogIn className="w-4 h-4" />}
                    {isSignUp ? 'CREATE ACCOUNT' : 'CONTINUE'}
                  </>
                )}
              </button>
            </form>

            <div className="gsap-element mt-8 pt-6 border-t border-[#222222] text-center">
              <p className="text-[11px] font-mono text-[#666666] tracking-wider">
                {isSignUp ? 'Already have an account?' : "Don't have an account?"}
              </p>
              <button
                onClick={toggleMode}
                type="button"
                className="mt-2 text-xs font-mono font-bold text-[#ffffff] uppercase tracking-widest hover:text-[#888888] transition-colors"
              >
                {isSignUp ? 'SIGN IN' : 'SIGN UP'}
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
};
