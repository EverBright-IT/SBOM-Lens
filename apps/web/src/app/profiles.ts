import type { ComplianceProfile, SpecInfo } from '@sbomlens/core';
import { MAX_PROFILE_BYTES, NTIA_PROFILE, OCM_ESSENTIALS_PROFILE, validateProfile } from '@sbomlens/core';
import { pref } from './brand';
import { host } from '../host/adapter';
import { useAppStore } from './store';

/**
 * App-side profile management (side effects live here, mirroring catalog.ts
 * and tokens.ts — the store stays host-free). Imported profiles persist via
 * host prefs; catalog profiles are re-fetched each start by catalog.ts.
 */

export interface StoredProfile {
  /** Namespaced: `user:<name>` | `catalog:<name>` — origins never collide. */
  id: string;
  profile: ComplianceProfile;
  origin: 'imported' | 'catalog';
}

const PROFILES_KEY = pref('profiles');
const ACTIVE_KEY = pref('activeProfile');
const MAX_STORED_PROFILES = 16;
/**
 * Persisted-size ceiling. Doubly important in VS Code, where every
 * sbomlens.* pref is inlined into the webview HTML (prefsSnapshot).
 */
const MAX_PERSIST_BYTES = 262144;

export function profileId(origin: StoredProfile['origin'], name: string): string {
  return `${origin === 'imported' ? 'user' : 'catalog'}:${name}`;
}

/** Restore persisted profiles + selection. Call once at app start. */
export function initProfiles(): void {
  const { actions } = useAppStore.getState();
  const restored: StoredProfile[] = [];
  try {
    const raw: unknown = JSON.parse(host().readPref(PROFILES_KEY) ?? '[]');
    if (Array.isArray(raw)) {
      for (const entry of raw.slice(0, MAX_STORED_PROFILES)) {
        // Prefs can be stale or hand-edited — re-validate every entry.
        const result = validateProfile(entry);
        if (result.ok) {
          restored.push({
            id: profileId('imported', result.profile.name),
            profile: result.profile,
            origin: 'imported',
          });
        } else {
          console.warn('sbomlens: dropped invalid persisted profile', result.errors);
        }
      }
    }
  } catch {
    // Corrupt pref — start empty.
  }
  actions.setProfiles(restored);

  const active = host().readPref(ACTIVE_KEY);
  if (
    active &&
    (active === 'builtin:ntia' ||
      restored.some((p) => p.id === active) ||
      // Catalog profiles arrive async after this — keep the selection; the
      // UI falls back to NTIA until the profile is (re)loaded.
      active.startsWith('catalog:'))
  ) {
    actions.setActiveProfileId(active === 'builtin:ntia' ? null : active);
  }
}

export interface ProfileImportResult {
  ok: boolean;
  errors?: string[];
}

/** Parse + validate profile text; upsert by name; persist; toast. */
export function importProfileText(
  fileName: string,
  text: string,
  origin: StoredProfile['origin'],
): ProfileImportResult {
  const { actions } = useAppStore.getState();

  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return reject(fileName, ['not valid JSON']);
  }
  const result = validateProfile(raw);
  if (!result.ok) return reject(fileName, result.errors);

  const stored: StoredProfile = {
    id: profileId(origin, result.profile.name),
    profile: result.profile,
    origin,
  };
  const state = useAppStore.getState();
  const existing = state.profiles.find((p) => p.id === stored.id);
  const profiles = existing
    ? state.profiles.map((p) => (p.id === stored.id ? stored : p))
    : [...state.profiles, stored];
  actions.setProfiles(profiles);

  if (origin === 'imported') {
    actions.setActiveProfileId(stored.id);
    persistActive(stored.id);
  }
  const persisted = persistProfiles(profiles);
  // Catalog profiles reload on every start — toasting them would be noise.
  if (origin === 'imported') {
    actions.toast(
      `${existing ? 'Replaced' : 'Imported'} profile “${result.profile.name}”` +
        (persisted ? '' : ' — kept for this session only (storage full)'),
      'success',
    );
  }
  return { ok: true };
}

function reject(fileName: string, errors: string[]): ProfileImportResult {
  const { actions } = useAppStore.getState();
  actions.recordFailure({
    fileName,
    diagnostics: errors.map((message) => ({
      severity: 'error' as const,
      code: 'PROFILE_INVALID',
      message,
    })),
  });
  actions.toast(`${fileName}: invalid compliance profile (${errors.length} error${errors.length === 1 ? '' : 's'})`, 'error');
  return { ok: false, errors };
}

export function removeProfile(id: string): void {
  const state = useAppStore.getState();
  const profiles = state.profiles.filter((p) => p.id !== id);
  state.actions.setProfiles(profiles);
  if (state.activeProfileId === id) {
    state.actions.setActiveProfileId(null);
    persistActive(null);
  }
  persistProfiles(profiles);
}

export function setActiveProfile(id: string | null): void {
  useAppStore.getState().actions.setActiveProfileId(id);
  persistActive(id);
}

/** True when the serialized set fit into the persistence budget. */
function persistProfiles(profiles: StoredProfile[]): boolean {
  const imported = profiles.filter((p) => p.origin === 'imported').map((p) => p.profile);
  const json = JSON.stringify(imported);
  if (imported.length > MAX_STORED_PROFILES || json.length > MAX_PERSIST_BYTES) return false;
  host().persistPref(PROFILES_KEY, json);
  return true;
}

function persistActive(id: string | null): void {
  host().persistPref(ACTIVE_KEY, id ?? 'builtin:ntia');
}

/** The builtin default depends on the document model — NTIA framing makes no sense on a component descriptor. */
function builtinProfile(model: SpecInfo['model']): ComplianceProfile {
  return model === 'ocm' ? OCM_ESSENTIALS_PROFILE : NTIA_PROFILE;
}

export function builtinProfileName(model: SpecInfo['model']): string {
  return builtinProfile(model).name;
}

/** Resolves the active profile, falling back to the model's builtin. */
export function useActiveProfile(model: SpecInfo['model']): ComplianceProfile {
  const activeId = useAppStore((s) => s.activeProfileId);
  const profiles = useAppStore((s) => s.profiles);
  if (activeId === null) return builtinProfile(model);
  return profiles.find((p) => p.id === activeId)?.profile ?? builtinProfile(model);
}

/** Import candidate size gate shared by every path. */
export function withinProfileSizeCap(byteLength: number): boolean {
  return byteLength <= MAX_PROFILE_BYTES;
}
