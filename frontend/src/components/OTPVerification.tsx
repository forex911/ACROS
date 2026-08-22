import React, { useState, useRef, useEffect, useCallback } from 'react';
import { ShieldCheck, Loader2, AlertTriangle, RotateCcw, ArrowLeft } from 'lucide-react';

interface OTPVerificationProps {
  email: string;
  onVerify: (otp: string) => Promise<void>;
  onResend: () => Promise<void>;
  onBack: () => void;
  error?: string;
  clearError?: () => void;
}

const OTP_LENGTH = 6;
const RESEND_COOLDOWN = 60;
const OTP_EXPIRY = 300; // 5 minutes

export const OTPVerification: React.FC<OTPVerificationProps> = ({
  email,
  onVerify,
  onResend,
  onBack,
  error,
  clearError,
}) => {
  const [otp, setOtp] = useState<string[]>(Array(OTP_LENGTH).fill(''));
  const [isVerifying, setIsVerifying] = useState(false);
  const [isResending, setIsResending] = useState(false);
  const [resendCooldown, setResendCooldown] = useState(RESEND_COOLDOWN);
  const [expiryCountdown, setExpiryCountdown] = useState(OTP_EXPIRY);
  const [localError, setLocalError] = useState('');
  const [success, setSuccess] = useState(false);
  const inputRefs = useRef<(HTMLInputElement | null)[]>([]);

  // Mask email: u***@gmail.com
  const maskedEmail = email.replace(
    /(.{1})(.*)(@.*)/,
    (_, a, b, c) => a + '\u2022'.repeat(Math.min(b.length, 6)) + c
  );

  // Countdown timers
  useEffect(() => {
    const resendTimer = setInterval(() => {
      setResendCooldown((prev) => (prev > 0 ? prev - 1 : 0));
    }, 1000);
    return () => clearInterval(resendTimer);
  }, []);

  useEffect(() => {
    const expiryTimer = setInterval(() => {
      setExpiryCountdown((prev) => (prev > 0 ? prev - 1 : 0));
    }, 1000);
    return () => clearInterval(expiryTimer);
  }, []);

  // Auto-focus first input
  useEffect(() => {
    inputRefs.current[0]?.focus();
  }, []);

  const formatTime = (seconds: number) => {
    const m = Math.floor(seconds / 60);
    const s = seconds % 60;
    return `${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
  };

  // Input handlers
  const handleChange = (index: number, value: string) => {
    if (!/^\d*$/.test(value)) return;
    const newOtp = [...otp];
    newOtp[index] = value.slice(-1);
    setOtp(newOtp);
    setLocalError('');
    clearError?.();
    if (value && index < OTP_LENGTH - 1) {
      inputRefs.current[index + 1]?.focus();
    }
  };

  const handleKeyDown = (index: number, e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Backspace' && !otp[index] && index > 0) {
      inputRefs.current[index - 1]?.focus();
      const newOtp = [...otp];
      newOtp[index - 1] = '';
      setOtp(newOtp);
    }
    if (e.key === 'ArrowLeft' && index > 0) {
      inputRefs.current[index - 1]?.focus();
    }
    if (e.key === 'ArrowRight' && index < OTP_LENGTH - 1) {
      inputRefs.current[index + 1]?.focus();
    }
  };

  const handlePaste = useCallback(
    (e: React.ClipboardEvent) => {
      e.preventDefault();
      const pastedData = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, OTP_LENGTH);
      if (pastedData.length === 0) return;
      const newOtp = [...otp];
      for (let i = 0; i < pastedData.length; i++) {
        newOtp[i] = pastedData[i];
      }
      setOtp(newOtp);
      setLocalError('');
      clearError?.();
      const focusIndex = Math.min(pastedData.length, OTP_LENGTH - 1);
      inputRefs.current[focusIndex]?.focus();
    },
    [otp, clearError]
  );

  // Verify
  const handleVerify = async () => {
    const code = otp.join('');
    if (code.length !== OTP_LENGTH) {
      setLocalError('Please enter the complete 6-digit code');
      return;
    }
    if (expiryCountdown === 0) {
      setLocalError('This OTP has expired. Please request a new code.');
      return;
    }
    setIsVerifying(true);
    setLocalError('');
    try {
      await onVerify(code);
      setSuccess(true);
    } catch (err: any) {
      setLocalError(err.message || 'Verification failed');
      setOtp(Array(OTP_LENGTH).fill(''));
      inputRefs.current[0]?.focus();
    } finally {
      setIsVerifying(false);
    }
  };

  // Resend
  const handleResend = async () => {
    if (resendCooldown > 0 || isResending) return;
    setIsResending(true);
    setLocalError('');
    try {
      await onResend();
      setResendCooldown(RESEND_COOLDOWN);
      setExpiryCountdown(OTP_EXPIRY);
      setOtp(Array(OTP_LENGTH).fill(''));
      inputRefs.current[0]?.focus();
    } catch (err: any) {
      setLocalError(err.message || 'Failed to resend OTP');
    } finally {
      setIsResending(false);
    }
  };

  const displayError = error || localError;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="text-center space-y-3">
        <div className="w-14 h-14 mx-auto border border-[#333333] bg-[#111111] flex items-center justify-center">
          <ShieldCheck className="w-7 h-7 text-[#ffffff]" />
        </div>
        <div>
          <h2 className="text-xl font-heading font-black text-[#ffffff] tracking-tighter uppercase">
            Verify Your Email
          </h2>
          <p className="text-[11px] font-mono text-[#666666] mt-2 tracking-wider">OTP SENT TO</p>
          <p className="text-xs font-mono text-[#888888] mt-1">{maskedEmail}</p>
        </div>
      </div>

      {/* Error */}
      {displayError && (
        <div className="bg-[#111111] border border-[#ffffff] text-[#ffffff] px-4 py-3 text-xs font-mono font-bold flex items-center gap-3 uppercase tracking-wider">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          {displayError}
        </div>
      )}

      {/* Success */}
      {success && (
        <div className="bg-[#111111] border border-[#22c55e] text-[#22c55e] px-4 py-3 text-xs font-mono font-bold flex items-center gap-3 uppercase tracking-wider">
          <ShieldCheck className="w-4 h-4 shrink-0" />
          VERIFIED &mdash; INITIALIZING SESSION...
        </div>
      )}

      {/* OTP Inputs */}
      <div className="flex justify-center gap-2" onPaste={handlePaste}>
        {otp.map((digit, index) => (
          <input
            key={index}
            ref={(el) => {
              inputRefs.current[index] = el;
            }}
            type="text"
            inputMode="numeric"
            maxLength={1}
            value={digit}
            onChange={(e) => handleChange(index, e.target.value)}
            onKeyDown={(e) => handleKeyDown(index, e)}
            disabled={isVerifying || success}
            className={`
              w-12 h-14 text-center text-xl font-mono font-bold
              bg-[#000000] border transition-all duration-200
              focus:outline-none focus:border-[#ffffff] focus:bg-[#0a0a0a]
              disabled:opacity-50 disabled:cursor-not-allowed
              ${digit ? 'border-[#ffffff] text-[#ffffff]' : 'border-[#333333] text-[#666666]'}
              ${displayError ? 'border-red-500/50' : ''}
            `}
            aria-label={`Digit ${index + 1}`}
          />
        ))}
      </div>

      {/* Timer */}
      <div className="text-center">
        {expiryCountdown > 0 ? (
          <p className="text-[11px] font-mono text-[#666666] tracking-widest">
            EXPIRES IN{' '}
            <span className={expiryCountdown < 60 ? 'text-red-500' : 'text-[#888888]'}>
              {formatTime(expiryCountdown)}
            </span>
          </p>
        ) : (
          <p className="text-[11px] font-mono text-red-500 tracking-widest uppercase">
            Code expired &mdash; request a new one
          </p>
        )}
      </div>

      {/* Verify Button */}
      <button
        onClick={handleVerify}
        disabled={isVerifying || success || otp.join('').length !== OTP_LENGTH}
        className="w-full bg-[#ffffff] text-[#000000] font-heading font-bold uppercase tracking-widest py-3 flex items-center justify-center gap-3 disabled:opacity-50 hover:bg-[#000000] hover:text-[#ffffff] border border-[#ffffff] transition-colors active:scale-95"
      >
        {isVerifying ? (
          <>
            <Loader2 className="w-4 h-4 animate-spin" />
            VERIFYING...
          </>
        ) : success ? (
          <>
            <ShieldCheck className="w-4 h-4" />
            VERIFIED
          </>
        ) : (
          <>
            <ShieldCheck className="w-4 h-4" />
            VERIFY OTP
          </>
        )}
      </button>

      {/* Resend & Back */}
      <div className="flex items-center justify-between pt-2 border-t border-[#222222]">
        <button
          onClick={onBack}
          disabled={isVerifying || success}
          className="text-[11px] font-mono text-[#666666] hover:text-[#ffffff] transition-colors flex items-center gap-1 tracking-wider disabled:opacity-50"
        >
          <ArrowLeft className="w-3 h-3" />
          BACK
        </button>

        <button
          onClick={handleResend}
          disabled={resendCooldown > 0 || isResending || success}
          className="text-[11px] font-mono tracking-wider flex items-center gap-1.5 transition-colors disabled:opacity-50 disabled:cursor-not-allowed text-[#666666] hover:text-[#ffffff]"
        >
          {isResending ? (
            <>
              <Loader2 className="w-3 h-3 animate-spin" />
              SENDING...
            </>
          ) : resendCooldown > 0 ? (
            <>
              <RotateCcw className="w-3 h-3" />
              RESEND IN {resendCooldown}s
            </>
          ) : (
            <>
              <RotateCcw className="w-3 h-3" />
              RESEND OTP
            </>
          )}
        </button>
      </div>
    </div>
  );
};
