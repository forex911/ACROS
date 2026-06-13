import { useCallback, useEffect, useRef, useState } from 'react';
import { useAuth } from './useAuth';

const MAX_MESSAGES = 1000;
const RECONNECT_DELAY = 3000;

type TelemetryValue = string | number | boolean | null | undefined;
type TelemetryMessage = {
  type?: string;
  severity?: string;
  timestamp?: string | number;
  data?: TelemetryValue | Record<string, TelemetryValue>;
};

export const useWebSocket = (url: string) => {
  const [messages, setMessages] = useState<TelemetryMessage[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const ws = useRef<WebSocket | null>(null);

  const messageBuffer = useRef<TelemetryMessage[]>([]);
  const rafRef = useRef<number | null>(null);
  const reconnectTimeout = useRef<ReturnType<typeof setTimeout> | null>(null);
  const isUnmounted = useRef(false);

  const { user } = useAuth();

  const closeSocket = useCallback(() => {
    if (reconnectTimeout.current) {
      clearTimeout(reconnectTimeout.current);
      reconnectTimeout.current = null;
    }

    if (ws.current) {
      ws.current.onopen = null;
      ws.current.onmessage = null;
      ws.current.onerror = null;
      ws.current.onclose = null;
      if (ws.current.readyState === WebSocket.OPEN || ws.current.readyState === WebSocket.CONNECTING) {
        ws.current.close();
      }
      ws.current = null;
    }
  }, []);

  useEffect(() => {
    isUnmounted.current = false;
    closeSocket();
    queueMicrotask(() => {
      if (!isUnmounted.current) {
        setIsConnected(false);
      }
    });

    const token = localStorage.getItem('access_token');
    if (!user || !url || !token) return;

    const connect = () => {
      if (isUnmounted.current) return;

      if (ws.current && (ws.current.readyState === WebSocket.OPEN || ws.current.readyState === WebSocket.CONNECTING)) {
        return;
      }

      const wsBaseUrl = import.meta.env.VITE_WS_URL || 'ws://localhost:8000';
      const separator = url.includes('?') ? '&' : '?';
      const wsUrl = `${wsBaseUrl}${url}${separator}token=${encodeURIComponent(token)}`;

      try {
        ws.current = new WebSocket(wsUrl);
      } catch (e) {
        console.error('[WS] Failed to create WebSocket:', e);
        if (!isUnmounted.current) {
          reconnectTimeout.current = setTimeout(connect, RECONNECT_DELAY);
        }
        return;
      }

      ws.current.onopen = () => {
        if (!isUnmounted.current) {
          setIsConnected(true);
          console.log('WS OPEN');
          console.log(`[WS] Connected to ${url}`);
        }
      };

      ws.current.onmessage = (event) => {
        console.log('WS MESSAGE', event);
        try {
          const data = JSON.parse(event.data) as TelemetryMessage;
          messageBuffer.current.push(data);
        } catch (e) {
          console.error('[WS] Failed to parse message', e);
        }
      };

      ws.current.onerror = (event) => {
        console.warn('[WS] Error on', url, event);
      };

      ws.current.onclose = () => {
        console.log('WS CLOSED');
        ws.current = null;
        if (!isUnmounted.current) {
          setIsConnected(false);
          console.log(`[WS] Disconnected from ${url}`);
          reconnectTimeout.current = setTimeout(connect, RECONNECT_DELAY);
        }
      };
    };

    connect();

    return () => {
      isUnmounted.current = true;
      closeSocket();
    };
  }, [closeSocket, url, user]);

  // RAF loop to drain message buffer into React state (max once per frame)
  useEffect(() => {
    const drainBuffer = () => {
      if (messageBuffer.current.length > 0) {
        const newMessages = [...messageBuffer.current];
        messageBuffer.current = [];

        setMessages((prev) => {
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

  const sendMessage = (msg: unknown) => {
    if (ws.current && ws.current.readyState === WebSocket.OPEN) {
      ws.current.send(JSON.stringify(msg));
    }
  };

  return { messages, isConnected, sendMessage };
};
