import { createContext, useContext, useState, type ReactNode } from 'react';
import { simpleMessages as t } from './simpleMessages';

type Mode = 'simple' | 'analyst';
const key = 'north.display-mode';
const DisplayMode = createContext<{ mode: Mode; setMode: (mode: Mode) => void }>({
  mode: 'simple', setMode: () => {},
});

export function DisplayModeProvider({ children }: { children: ReactNode }) {
  const [mode, updateMode] = useState<Mode>(() => {
    try { return localStorage.getItem(key) === 'analyst' ? 'analyst' : 'simple'; } catch { return 'simple'; }
  });
  return <DisplayMode.Provider value={{ mode, setMode(value) {
    updateMode(value);
    try { localStorage.setItem(key, value); } catch { /* Keep the current session preference. */ }
  } }}>{children}</DisplayMode.Provider>;
}

export function useDisplayMode() { return useContext(DisplayMode); }

export function DisplayModeControl() {
  const { mode, setMode } = useDisplayMode();
  return <fieldset className="display-mode-control">
    <legend>{t.mode}</legend>
    {(['simple', 'analyst'] as const).map((value) => <label key={value}>
      <input type="radio" name="north-display-mode" checked={mode === value} onChange={() => setMode(value)} />
      <span><strong>{t[value]}</strong><small>{value === 'simple' ? t.simpleDescription : t.analystDescription}</small></span>
    </label>)}
  </fieldset>;
}
