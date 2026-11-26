import { useState } from 'react';
import * as Menu from '@radix-ui/react-dropdown-menu';
import { ChevronRight, Monitor, Moon, Sun, SunMoon } from 'lucide-react';

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

  return <Menu.Sub>
    <Menu.SubTrigger className="shell-menu-item"><SunMoon size={16} />Appearance<ChevronRight size={14} className="menu-end" /></Menu.SubTrigger>
    <Menu.Portal><Menu.SubContent className="shell-menu" sideOffset={5} collisionPadding={8}>
      <Menu.RadioGroup value={selected} onValueChange={(value) => changeTheme(value as Theme)}>
        <Menu.RadioItem value="system" className="shell-menu-item"><Monitor size={16} />System<Menu.ItemIndicator className="menu-end">✓</Menu.ItemIndicator></Menu.RadioItem>
        <Menu.RadioItem value="light" className="shell-menu-item"><Sun size={16} />Light<Menu.ItemIndicator className="menu-end">✓</Menu.ItemIndicator></Menu.RadioItem>
        <Menu.RadioItem value="dark" className="shell-menu-item"><Moon size={16} />Dark<Menu.ItemIndicator className="menu-end">✓</Menu.ItemIndicator></Menu.RadioItem>
      </Menu.RadioGroup>
    </Menu.SubContent></Menu.Portal>
  </Menu.Sub>;
}
