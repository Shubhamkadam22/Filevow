import { useEffect, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import type { LiveState } from "../api/types";

/** Subscribe to server push events and refresh cached data when anything changes. */
export function useLiveEvents(enabled: boolean): LiveState | null {
  const queryClient = useQueryClient();
  const [state, setState] = useState<LiveState | null>(null);
  const retry = useRef(1000);

  useEffect(() => {
    if (!enabled) return;
    let socket: WebSocket | null = null;
    let timer: number | undefined;
    let closed = false;

    const connect = () => {
      const scheme = window.location.protocol === "https:" ? "wss" : "ws";
      socket = new WebSocket(`${scheme}://${window.location.host}/api/v1/events`);
      socket.onopen = () => (retry.current = 1000);
      socket.onmessage = (message) => {
        const data = JSON.parse(message.data) as LiveState;
        setState((previous) => {
          if (previous && JSON.stringify(previous) !== JSON.stringify(data)) queryClient.invalidateQueries();
          return data;
        });
      };
      socket.onclose = () => {
        if (closed) return;
        timer = window.setTimeout(connect, retry.current);
        retry.current = Math.min(retry.current * 2, 30000); // back off while the server is away
      };
    };

    connect();
    return () => {
      closed = true;
      window.clearTimeout(timer);
      socket?.close();
    };
  }, [enabled, queryClient]);

  return state;
}

export function useNow(intervalMs = 1000): number {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), intervalMs);
    return () => window.clearInterval(timer);
  }, [intervalMs]);
  return now;
}
