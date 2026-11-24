import { useCallback, useEffect, useState } from "react";

export type Theme = "system" | "light" | "dark";
export type Density = "comfortable" | "compact";

function read<T extends string>(key: string, fallback: T): T {
  try {
    return (localStorage.getItem(key) as T | null) ?? fallback;
  } catch {
    return fallback;
  }
}

function write(key: string, value: string) {
  try {
    localStorage.setItem(key, value);
  } catch {
    /* storage unavailable (private mode); the setting just won't persist */
  }
}

function prefersDark(theme: Theme): boolean {
  return theme === "dark" || (theme === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);
}

export function applyTheme(theme: Theme) {
  const root = document.documentElement;
  if (theme === "system") root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", theme);
  const dark = prefersDark(theme);
  document.querySelectorAll<HTMLImageElement>("img.themed-logo").forEach((img) => {
    img.src = dark ? "/logo-mark-reversed.svg" : "/logo-mark.svg";
  });
}

export function usePreferences() {
  const [theme, setThemeState] = useState<Theme>(() => read("fv-theme", "system"));
  const [density, setDensityState] = useState<Density>(() => read("fv-density", "comfortable"));

  useEffect(() => {
    applyTheme(theme);
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const onChange = () => applyTheme(theme);
    media.addEventListener("change", onChange);
    const observer = new MutationObserver(() => applyTheme(theme)); // newly rendered logos follow the theme
    observer.observe(document.body, { childList: true, subtree: true });
    return () => {
      media.removeEventListener("change", onChange);
      observer.disconnect();
    };
  }, [theme]);

  useEffect(() => {
    document.body.classList.toggle("compact", density === "compact");
  }, [density]);

  const setTheme = useCallback((value: Theme) => {
    write("fv-theme", value);
    setThemeState(value);
  }, []);
  const setDensity = useCallback((value: Density) => {
    write("fv-density", value);
    setDensityState(value);
  }, []);

  return { theme, setTheme, density, setDensity };
}
