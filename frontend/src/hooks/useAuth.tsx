import { createContext, useContext, ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import api from '../api/client';
import type { User } from '../types';

interface AuthContextType {
  user: User | null;
  isLoading: boolean;
  error: Error | null;
  logout: () => void;
  isAuthenticated: boolean;
  checkAuth: () => Promise<any>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const { data: user, isLoading, error, refetch } = useQuery({
    queryKey: ['user'],
    queryFn: async () => {
      const token = localStorage.getItem('token');
      if (!token) return null;
      try {
        const response = await api.get('/auth/me');
        return response.data;
      } catch (err) {
        localStorage.removeItem('token');
        throw err;
      }
    },
    retry: false,
    staleTime: 5 * 60 * 1000,
  });

  const logout = () => {
    localStorage.removeItem('token');
    window.location.href = '/login';
  };

  const checkAuth = async () => {
    return refetch();
  };

  return (
    <AuthContext.Provider 
      value={{ 
        user: user || null, 
        isLoading, 
        error: error as Error | null, 
        logout,
        isAuthenticated: !!user,
        checkAuth
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
