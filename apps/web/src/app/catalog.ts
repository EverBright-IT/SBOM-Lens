import { MAX_PROFILE_BYTES } from '@sbomlens/core';
import { host } from '../host/adapter';
import { fetchAllReferences } from './autofetch';
import { ingestUrl } from './ingest';
import { importProfileText } from './profiles';
import { useAppStore } from './store';

/**
 * Deployment catalog: a self-hosted instance ships a `sbomlens.catalog.json`
 * next to index.html, and users get one-click access to curated SBOMs instead
 * of hunting for files.
 *
 * Security model:
 * - The catalog is only ever read from this fixed same-origin path — never
 *   from a query parameter, so a link can't inject foreign sources.
 * - It must not contain secrets. For private registries, deploy the viewer
 *   behind a reverse proxy that adds the (read-only) token server-side and
 *   exposes the SBOMs same-origin — no CORS, no tokens in the browser.
 * - Only http(s) and relative URLs are accepted.
 */

export interface CatalogSource {
  label: string;
  description?: string;
  urls: string[];
  loadOnStart?: boolean;
  /** After loading, recursively fetch every referenced document. */
  resolveRefs?: boolean;
}

export interface CatalogProfileRef {
  name: string;
  url: string;
}

export interface Catalog {
  title?: string;
  sources: CatalogSource[];
  /** Compliance profiles the deployment rolls out (never auto-activated). */
  profiles?: CatalogProfileRef[];
}

const CATALOG_PATH = 'sbomlens.catalog.json';
const MAX_SOURCES = 100;
const MAX_URLS = 50;
const MAX_PROFILE_REFS = 20;

export async function initCatalog(): Promise<void> {
  let raw: unknown;
  try {
    const response = await fetch(CATALOG_PATH, { cache: 'no-cache' });
    if (!response.ok) return; // no catalog deployed — perfectly fine
    raw = await response.json();
  } catch {
    return; // unreachable or invalid JSON — the viewer works without a catalog
  }

  const catalog = validateCatalog(raw);
  if (!catalog) {
    console.warn(`[sbomlens] ${CATALOG_PATH} exists but contains no valid sources`);
    return;
  }
  useAppStore.getState().actions.setCatalog(catalog);
  void loadCatalogProfiles(catalog);

  for (const source of catalog.sources) {
    if (source.loadOnStart) void loadCatalogSource(source);
  }
}

/**
 * Catalog-shipped profiles: fetched every start (they are deployment config,
 * not user data) and strictly validated by importProfileText. Failures only
 * warn — startup must never break on a bad profile.
 */
async function loadCatalogProfiles(catalog: Catalog): Promise<void> {
  for (const ref of catalog.profiles ?? []) {
    try {
      const result = await host().fetchDocument(ref.url);
      if (!result.ok || result.bytes.byteLength > MAX_PROFILE_BYTES) {
        console.warn(`[sbomlens] catalog profile "${ref.name}" not loadable`);
        continue;
      }
      importProfileText(ref.name, new TextDecoder().decode(result.bytes), 'catalog');
    } catch {
      console.warn(`[sbomlens] catalog profile "${ref.name}" failed`);
    }
  }
}

export async function loadCatalogSource(source: CatalogSource): Promise<void> {
  const { actions } = useAppStore.getState();
  for (const url of source.urls) {
    const result = await ingestUrl(url);
    if (!result.ok) {
      actions.toast(`${source.label}: ${result.message ?? 'failed to load'}`, 'error');
    }
  }
  if (source.resolveRefs) await fetchAllReferences();
}

function validateCatalog(raw: unknown): Catalog | null {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return null;
  const record = raw as Record<string, unknown>;
  const sourcesRaw = Array.isArray(record.sources) ? record.sources.slice(0, MAX_SOURCES) : [];

  const sources: CatalogSource[] = [];
  for (const entry of sourcesRaw) {
    if (typeof entry !== 'object' || entry === null) continue;
    const e = entry as Record<string, unknown>;
    const label = typeof e.label === 'string' ? e.label.trim() : '';
    const urls = Array.isArray(e.urls)
      ? e.urls.filter((u): u is string => typeof u === 'string' && isAllowedUrl(u)).slice(0, MAX_URLS)
      : [];
    if (!label || urls.length === 0) continue;
    sources.push({
      label,
      description: typeof e.description === 'string' ? e.description : undefined,
      urls,
      loadOnStart: e.loadOnStart === true,
      resolveRefs: e.resolveRefs === true,
    });
  }
  const profiles: CatalogProfileRef[] = [];
  for (const entry of (Array.isArray(record.profiles) ? record.profiles : []).slice(0, MAX_PROFILE_REFS)) {
    if (typeof entry !== 'object' || entry === null) continue;
    const e = entry as Record<string, unknown>;
    const name = typeof e.name === 'string' ? e.name.trim() : '';
    const url = typeof e.url === 'string' && isAllowedUrl(e.url) ? e.url : '';
    if (name && url) profiles.push({ name, url });
  }

  if (sources.length === 0 && profiles.length === 0) return null;
  return {
    title: typeof record.title === 'string' ? record.title : undefined,
    sources,
    ...(profiles.length > 0 && { profiles }),
  };
}

/** Relative or http(s) only — no javascript:, data:, file: schemes. */
function isAllowedUrl(url: string): boolean {
  const scheme = /^([a-zA-Z][a-zA-Z0-9+.-]*):/.exec(url)?.[1];
  return scheme === undefined || scheme === 'http' || scheme === 'https';
}
