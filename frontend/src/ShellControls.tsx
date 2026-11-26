import { feedbackMessages } from './messages';
import { ShellControlsMessages as strings, formatMessage } from './messages';
import { useEffect, useId, useRef, useState } from 'react';
import * as Menu from '@radix-ui/react-dropdown-menu';
import * as Popover from '@radix-ui/react-popover';
import { ChevronDown, Laptop, LogOut, Monitor, Search, Server, Settings, UserRound } from 'lucide-react';
import { Appearance } from './Appearance';
import { formatAbsolute } from './TimeDisplay';

type Collector = { id: string; label: string; updated_at?: string; platform?: 'Windows' | 'Linux' | null };
const relative = new Intl.RelativeTimeFormat(undefined, { numeric: 'always' });

function syncLabel(timestamp: string | undefined, now: number) {
  if (!timestamp) return feedbackMessages.waitingForFirstSync;
  const seconds = Math.max(0, Math.floor((now - Date.parse(timestamp)) / 1000));
  if (!Number.isFinite(seconds)) return feedbackMessages.syncTimeUnavailable;
  if (seconds < 10) return feedbackMessages.syncedJustNow;
  if (seconds < 60) return 'Synced ' + relative.format(-seconds, 'second');
  if (seconds < 3600) return 'Synced ' + relative.format(-Math.floor(seconds / 60), 'minute');
  if (seconds < 86400) return 'Synced ' + relative.format(-Math.floor(seconds / 3600), 'hour');
  return 'Synced ' + relative.format(-Math.floor(seconds / 86400), 'day');
}

function CollectorIcon({ collector }: { collector?: Collector }) {
  const Icon = collector?.platform === 'Linux' ? Server : collector?.platform === 'Windows' ? Monitor : Laptop;
  return <Icon size={16} aria-hidden="true" />;
}

export function CollectorPicker({ current, options, choose }: {
  current?: Collector;
  options: Collector[];
  choose: (id: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState('');
  const [showInactive, setShowInactive] = useState(false);
  const [focused, setFocused] = useState(-1);
  const [now, setNow] = useState(Date.now);
  const searchInput = useRef<HTMLInputElement>(null);
  const listId = useId();
  const isActive = (item?: Collector) => !!item?.updated_at && now - Date.parse(item.updated_at) < 180000;
  const matching = options.filter((item) => (showInactive || isActive(item) || item.id === current?.id) &&
    (item.label + ' ' + (item.platform ?? '')).toLowerCase().includes(search.trim().toLowerCase()));
  const enabled = matching.filter((item) => item.updated_at);
  const highlighted = enabled[focused];

  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 10000);
    return () => window.clearInterval(timer);
  }, []);
  useEffect(() => {
    if (highlighted) document.getElementById(listId + highlighted.id)?.scrollIntoView({ block: 'nearest' });
  }, [highlighted, listId]);

  function select(id: string) {
    choose(id);
    setOpen(false);
  }

  return <Popover.Root open={open} onOpenChange={(next) => {
    setOpen(next);
    if (next) { setSearch(''); setFocused(-1); setNow(Date.now()); }
  }}>
    <Popover.Trigger asChild>
      <button className="collector-trigger" type="button" aria-label={current ? formatMessage(strings.collector, current.label) : strings.chooseCollector}>
        <span className="collector-dot" data-active={isActive(current)} />
        <CollectorIcon collector={current} />
        <strong>{current?.label ?? strings.noCollector}</strong>
        {current && <small title={formatAbsolute(current.updated_at ?? '')}>{syncLabel(current.updated_at, now)}</small>}
        <ChevronDown size={14} aria-hidden="true" />
      </button>
    </Popover.Trigger>
    <Popover.Portal><Popover.Content className="collector-popover" align="start" sideOffset={7} collisionPadding={8}
      onOpenAutoFocus={(event) => { event.preventDefault(); searchInput.current?.focus(); }}>
      <label className="collector-search"><Search size={15} aria-hidden="true" /><input ref={searchInput}
        role="combobox" aria-label={strings.searchCollectors} aria-autocomplete="list" aria-expanded={open} aria-controls={listId}
        aria-activedescendant={highlighted ? listId + highlighted.id : undefined}
        placeholder={strings.searchCollectors} value={search} onChange={(event) => { setSearch(event.target.value); setFocused(-1); }}
        onKeyDown={(event) => {
          if ((event.key === 'ArrowDown' || event.key === 'ArrowUp') && enabled.length) {
            event.preventDefault();
            const delta = event.key === 'ArrowDown' ? 1 : -1;
            setFocused((index) => index < 0 ? (delta > 0 ? 0 : enabled.length - 1) :
              (index + delta + enabled.length) % enabled.length);
          }
          if (event.key === 'Enter' && (highlighted ?? enabled[0])) {
            event.preventDefault();
            select((highlighted ?? enabled[0]).id);
          }
        }} /></label>
      <div id={listId} className="collector-options" role="listbox" aria-label={strings.collectors}>
        {matching.map((item) => <div key={item.id} id={listId + item.id} role="option" aria-selected={current?.id === item.id}
          aria-disabled={!item.updated_at || undefined} data-highlighted={highlighted?.id === item.id || undefined}
          className="collector-option" onMouseDown={(event) => event.preventDefault()}
          onClick={() => { if (item.updated_at) select(item.id); }}>
          <span className="collector-dot" data-active={isActive(item)} /><CollectorIcon collector={item} />
          <span><strong>{item.label}</strong><small>{syncLabel(item.updated_at, now)}</small></span>
        </div>)}
      </div>
      {!matching.length && <p className="collector-empty" role="status">{strings.noCollectorsMatch}</p>}
      <label className="collector-inactive"><input type="checkbox" checked={showInactive}
        onChange={(event) => { setShowInactive(event.target.checked); setFocused(-1); }} />{strings.showInactive}</label>
    </Popover.Content></Popover.Portal>
  </Popover.Root>;
}

export type WorkspaceActions = { settings: () => void; collectors: () => void; signOut: () => void };

export function AccountMenu({ actions, localSettings }: { actions?: WorkspaceActions; localSettings?: () => void }) {
  useEffect(() => {
    if (!actions && !localSettings) return;
    function shortcuts(event: KeyboardEvent) {
      if (event.defaultPrevented || event.repeat || !event.altKey || !event.shiftKey || event.ctrlKey || event.metaKey ||
          document.querySelector('dialog[open]')) return;
      const action = event.code === 'KeyC' ? actions?.collectors :
        event.code === 'KeyS' ? actions?.settings ?? localSettings : undefined;
      if (action) { event.preventDefault(); action(); }
    }
    window.addEventListener('keydown', shortcuts);
    return () => window.removeEventListener('keydown', shortcuts);
  }, [actions, localSettings]);

  return <Menu.Root>
    <Menu.Trigger asChild><button type="button" className="avatar-trigger" aria-label={strings.workspaceMenu}><UserRound size={16} /></button></Menu.Trigger>
    <Menu.Portal><Menu.Content className="shell-menu" align="end" sideOffset={7} collisionPadding={8}>
      {actions && <><Menu.Group>
        <Menu.Item className="shell-menu-item" onSelect={actions.settings}><Settings size={16} />{strings.settings}<kbd>{strings.altShiftS}</kbd></Menu.Item>
        <Menu.Item className="shell-menu-item" onSelect={actions.collectors}><Server size={16} />{strings.collectors}<kbd>{strings.altShiftC}</kbd></Menu.Item>
      </Menu.Group><Menu.Separator className="menu-separator" /></>}
      {!actions && localSettings && <Menu.Item className="shell-menu-item" onSelect={localSettings}>
        <Settings size={16} />{strings.settings}<kbd>{strings.altShiftS}</kbd>
      </Menu.Item>}
      <Appearance />
      {actions && <><Menu.Separator className="menu-separator" />
        <Menu.Item className="shell-menu-item" onSelect={actions.signOut}><LogOut size={16} />{strings.signOut}</Menu.Item></>}
    </Menu.Content></Menu.Portal>
  </Menu.Root>;
}
