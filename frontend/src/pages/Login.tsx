import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import api from '../api/client';
import { Lock, User as UserIcon } from 'lucide-react';

export const Login: React.FC = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    try {
      // Using x-www-form-urlencoded as required by FastAPI OAuth2PasswordRequestForm
      const params = new URLSearchParams();
      params.append('username', username);
      params.append('password', password);

      const res = await api.post('/auth/login', params, {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      });

      // Fetch user details immediately after token grant
      const { access_token } = res.data;
      const userRes = await api.get('/auth/me', {
        headers: { Authorization: `Bearer ${access_token}` }
      });

      login(access_token, userRes.data);
      navigate('/');
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Authentication failed');
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-cyber-dark">
      <div className="cyber-panel p-8 w-full max-w-md">
        <div className="flex flex-col items-center mb-8">
          <div className="w-16 h-16 bg-cyber-accent bg-opacity-10 rounded-full flex items-center justify-center mb-4 border border-cyber-accent shadow-[0_0_15px_rgba(88,166,255,0.3)]">
            <Lock className="w-8 h-8 text-cyber-accent" />
          </div>
          <h2 className="text-2xl font-bold text-gray-100 font-mono tracking-widest">SENTINEL_AI</h2>
          <p className="text-gray-400 text-sm mt-2">SECURE SOC ACCESS</p>
        </div>

        {error && (
          <div className="bg-cyber-alert bg-opacity-20 border border-cyber-alert text-cyber-alert px-4 py-2 rounded mb-4 text-sm font-mono">
            [ERROR]: {error}
          </div>
        )}

        <form onSubmit={handleLogin} className="space-y-4">
          <div>
            <label className="block text-gray-400 text-xs font-mono mb-1">USERNAME</label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                <UserIcon className="h-4 w-4 text-gray-500" />
              </div>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full bg-cyber-dark border border-cyber-border rounded pl-10 pr-3 py-2 text-gray-200 focus:outline-none focus:border-cyber-accent focus:ring-1 focus:ring-cyber-accent transition-colors"
                placeholder="admin"
                required
              />
            </div>
          </div>
          
          <div>
            <label className="block text-gray-400 text-xs font-mono mb-1">PASSWORD</label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                <Lock className="h-4 w-4 text-gray-500" />
              </div>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full bg-cyber-dark border border-cyber-border rounded pl-10 pr-3 py-2 text-gray-200 focus:outline-none focus:border-cyber-accent focus:ring-1 focus:ring-cyber-accent transition-colors"
                placeholder="••••••••"
                required
              />
            </div>
          </div>

          <button
            type="submit"
            className="w-full cyber-button mt-6 font-mono tracking-wider flex items-center justify-center gap-2"
          >
            INITIALIZE_SESSION
          </button>
        </form>
      </div>
    </div>
  );
};
