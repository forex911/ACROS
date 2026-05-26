import React, { createContext, useContext } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import api from '../api/client';
import type { User } from '../types';

interface AuthContextType {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (token: string, user: User) => void;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const queryClient = useQueryClient();
  const token = localStorage.getItem('access_token');

  const { data: user = null, isLoading } = useQuery<User | null>({
    queryKey: ['auth', 'me'],
    queryFn: async () => {
      const currentToken = localStorage.getItem('access_token');
      if (!currentToken) return null;
      try {
        const res = await api.get('/auth/me');
        return res.data;
      } catch (error) {
        console.error("Auth check failed", error);
        throw error;
      }
    },
    enabled: !!token,
    retry: 3,
    retryDelay: (attemptIndex) => Math.min(1000 * 2 ** attemptIndex, 10000), // Exponential backoff
    staleTime: 5 * 60 * 1000,
  });

  const login = (newToken: string, userData: User) => {
    localStorage.setItem('access_token', newToken);
    queryClient.setQueryData(['auth', 'me'], userData);
  };

  const logout = async () => {
    try {
      await api.post('/auth/logout');
    } catch (e) {
      console.error(e);
    }
    localStorage.removeItem('access_token');
    queryClient.setQueryData(['auth', 'me'], null);
    queryClient.clear();
  };

  const isAuthLoading = !!token && isLoading;

  return (
    <AuthContext.Provider value={{ user, isAuthenticated: !!user, isLoading: isAuthLoading, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
