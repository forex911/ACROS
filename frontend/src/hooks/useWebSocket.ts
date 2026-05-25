import { useEffect, useRef, useState, useCallback } from 'react';
import { useAuth } from './useAuth';

const MAX_MESSAGES = 1000;

export const useWebSocket = (url: string) => {
  const [messages, setMessages] = useState<any[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const ws = useRef<WebSocket | null>(null);
  
  // Use a mutable ref to accumulate incoming messages rapidly
  // without triggering a React re-render for every single event.
  const messageBuffer = useRef<any[]>([]);
  const rafRef = useRef<number | null>(null);
  
  const { user } = useAuth();
  
  const connect = useCallback(() => {
    if (!user) return;
    
    // In production, token should be passed securely, e.g. via ticket or wss headers
    const token = localStorage.getItem('access_token');
    const wsUrl = `${import.meta.env.VITE_WS_URL || 'ws://localhost:6000'}${url}?token=${token}`;
    
    ws.current = new WebSocket(wsUrl);

    ws.current.onopen = () => {
      setIsConnected(true);
      console.log(`[WS] Connected to ${url}`);
    };

    ws.current.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        messageBuffer.current.push(data);
      } catch (e) {
        console.error('Failed to parse WS message', e);
      }
    };

    ws.current.onclose = () => {
      setIsConnected(false);
      console.log(`[WS] Disconnected from ${url}`);
      // Auto reconnect
      setTimeout(connect, 3000);
    };
  }, [url, user]);

  useEffect(() => {
    connect();
    return () => {
      if (ws.current) {
        ws.current.close();
      }
    };
  }, [connect]);

  // Request Animation Frame loop to drain the buffer into React state
  // at most once per frame (16ms), preventing UI freeze during telemetry storms.
  useEffect(() => {
    const drainBuffer = () => {
      if (messageBuffer.current.length > 0) {
        // Take a snapshot of the buffer and clear it
        const newMessages = [...messageBuffer.current];
        messageBuffer.current = [];
        
        setMessages((prev) => {
          // Keep only the latest MAX_MESSAGES to prevent DOM/memory bloat
          const combined = [...prev, ...newMessages];
          return combined.length > MAX_MESSAGES 
            ? combined.slice(combined.length - MAX_MESSAGES) 
            : combined;
        });
      }
      rafRef.current = requestAnimationFrame(drainBuffer);
    };
    
    rafRef.current = requestAnimationFrame(drainBuffer);
    
    return () => {
      if (rafRef.current) cancelAnimationFrame(rafRef.current);
    };
  }, []);

  const sendMessage = (msg: any) => {
    if (ws.current && isConnected) {
      ws.current.send(JSON.stringify(msg));
    }
  };

  return { messages, isConnected, sendMessage };
};
