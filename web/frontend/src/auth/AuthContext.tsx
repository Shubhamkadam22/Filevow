import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { ApiError, api } from "../api/client";
import type { Role, User } from "../api/types";

interface AuthState {
  user: User | null;
  loading: boolean;
  login: (username: string, password: string, totpCode?: string) => Promise<void>;
  register: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
  can: (minimum: Role) => boolean;
}

const RANK: Record<Role, number> = { viewer: 0, analyst: 1, user: 2, admin: 3 };
const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const queryClient = useQueryClient();

  const refreshUser = useCallback(async () => {
    try {
      setUser(await api.get<User>("/auth/me"));
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        try {
          setUser(await api.post<User>("/auth/refresh"));
          return;
        } catch {
          /* no valid refresh token either */
        }
      }
      setUser(null);
    }
  }, []);

  useEffect(() => {
    refreshUser().finally(() => setLoading(false));
  }, [refreshUser]);

  const login = useCallback(async (username: string, password: string, totpCode?: string) => {
    const signedIn = await api.post<User>("/auth/login", { username, password, totp_code: totpCode || null });
    setUser(signedIn);
  }, []);

  const register = useCallback(async (username: string, password: string) => {
    setUser(await api.post<User>("/auth/register", { username, password }));
  }, []);

  const logout = useCallback(async () => {
    await api.post("/auth/logout").catch(() => undefined);
    queryClient.clear();
    setUser(null);
  }, [queryClient]);

  const value = useMemo<AuthState>(
    () => ({
      user,
      loading,
      login,
      register,
      logout,
      refreshUser,
      can: (minimum) => (user ? RANK[user.role] >= RANK[minimum] : false),
    }),
    [user, loading, login, register, logout, refreshUser],
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const value = useContext(AuthContext);
  if (!value) throw new Error("useAuth must be used inside <AuthProvider>");
  return value;
}
