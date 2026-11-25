type WorkspacePreference = 'view' | 'collector' | 'section' | 'case';
const prefix = 'north-workspace-';

export function readWorkspacePreference(name: WorkspacePreference): string {
  try {
    return sessionStorage.getItem(prefix + name) ?? '';
  } catch {
    return '';
  }
}

export function writeWorkspacePreference(name: WorkspacePreference, value: string) {
  try {
    sessionStorage.setItem(prefix + name, value);
  } catch {
    // Navigation still works if the window disallows storage.
  }
}

export function clearWorkspacePreferences() {
  const names: WorkspacePreference[] = ['view', 'collector', 'section', 'case'];
  try {
    for (const name of names) sessionStorage.removeItem(prefix + name);
  } catch {
    // There is no accessible stored navigation state to remove.
  }
}
