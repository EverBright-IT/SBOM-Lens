import { MAX_PROFILE_BYTES } from '@sbomlens/core';
import { BRAND } from './brand';
import { host } from '../host/adapter';
import { fetchAllReferences } from './autofetch';
import { checkDeliveredFiles, ingestUrl } from './ingest';
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
  /**
   * Delivered files to check against the loaded SBOM's file checksums after
   * ingesting `urls`. Their common directory prefix is stripped so the paths
   * line up with the SBOM's relative file names. Used for the acceptance demo.
   */
  delivery?: string[];
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

const CATALOG_PATH = BRAND.catalogPath;
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
  if (source.delivery && source.delivery.length > 0) await runDeliveryCheck(source.delivery);
}

/**
 * Fetch a bundled delivered-file set and check it against the just-loaded
 * SBOM. The common directory prefix is stripped from each URL so the File
 * names match the SBOM's relative paths; the bytes go straight to the worker
 * for hashing via checkDeliveredFiles.
 */
async function runDeliveryCheck(urls: string[]): Promise<void> {
  const prefix = commonDirPrefix(urls);
  const files: File[] = [];
  for (const url of urls) {
    const result = await host().fetchDocument(url);
    if (result.ok) files.push(new File([result.bytes], url.slice(prefix.length)));
  }
  if (files.length > 0) await checkDeliveredFiles(files);
}

/** Longest shared directory prefix (ending at a slash) across the URLs. */
function commonDirPrefix(urls: readonly string[]): string {
  if (urls.length === 0) return '';
  let prefix = urls[0]!;
  for (const url of urls) while (!url.startsWith(prefix)) prefix = prefix.slice(0, -1);
  const slash = prefix.lastIndexOf('/');
  return slash === -1 ? '' : prefix.slice(0, slash + 1);
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
    const delivery = Array.isArray(e.delivery)
      ? e.delivery.filter((u): u is string => typeof u === 'string' && isAllowedUrl(u)).slice(0, MAX_URLS)
      : [];
    sources.push({
      label,
      description: typeof e.description === 'string' ? e.description : undefined,
      urls,
      loadOnStart: e.loadOnStart === true,
      resolveRefs: e.resolveRefs === true,
      ...(delivery.length > 0 ? { delivery } : {}),
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
