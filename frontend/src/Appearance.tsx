import { useState } from 'react';

type Theme = 'system' | 'light' | 'dark';
const storageKey = 'north-appearance';

function readTheme(): Theme {
  try {
    const saved = localStorage.getItem(storageKey);
    if (saved === 'light' || saved === 'dark') return saved;
  } catch {
    // The system theme remains available when storage is disabled.
  }
  return 'system';
}

let theme = readTheme();
document.documentElement.dataset.theme = theme;

export function Appearance() {
  const [selected, setSelected] = useState(theme);

  function changeTheme(next: Theme) {
    theme = next;
    setSelected(next);
    document.documentElement.dataset.theme = next;
    try {
      localStorage.setItem(storageKey, next);
    } catch {
      // The selection still applies for the current session.
    }
  }

  return <label className="appearance-control">
    Appearance
    <select value={selected} onChange={(event) => changeTheme(event.target.value as Theme)}>
      <option value="system">System</option>
      <option value="light">Light</option>
      <option value="dark">Dark</option>
    </select>
  </label>;
}
