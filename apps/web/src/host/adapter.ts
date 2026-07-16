/**
 * The seam between the app and whatever hosts it (browser today, a VS Code
 * webview later). Everything environment-specific — network, storage,
 * secrets, workers, file export — goes through this interface so the app
 * code stays host-agnostic.
 */

export type FetchDocumentResult =
  | { ok: true; bytes: ArrayBuffer }
  | { ok: false; status?: number; statusText?: string };

export interface IngestPush {
  fileName: string;
  buffer: ArrayBuffer;
}

export interface HostAdapter {
  kind: 'web' | 'vscode';
  caps: {
    /** Whether the deployment may ship a sbomlens.catalog.json. */
    catalog: boolean;
  };

  /**
   * Fetch a document's bytes. `ok: false` without a status means the request
   * never reached a server (network error, CORS); with a status it is the
   * HTTP error. Message texts are the caller's job.
   */
  fetchDocument(url: string, headers?: Record<string, string>): Promise<FetchDocumentResult>;

  /** Small, non-sensitive UI preferences (sidebar width, minimap state). */
  readPref(key: string): string | null;
  persistPref(key: string, value: string): void;

  /** Secrets (access tokens). Never stored in prefs. */
  secretGet(key: string): Promise<string | null>;
  secretSet(key: string, value: string | null): Promise<void>;

  /** Hand a generated file (CSV/JSON export) to the user. */
  exportFile(fileName: string, mime: string, text: string): void;

  /** Open a URL outside the app. */
  openExternal(url: string): void;

  /** Create the parse worker (the web host owns the bundler-visible URL). */
  createWorker(): Worker;

  /** Host-initiated document pushes (e.g. "open with SBOM Lens" in an editor). */
  onIngestMessage(callback: (files: IngestPush[]) => void): void;
}

let current: HostAdapter | null = null;

/** Set once in the entrypoint, before anything renders or fetches. */
export function setHost(adapter: HostAdapter): void {
  current = adapter;
}

export function host(): HostAdapter {
  if (!current) throw new Error('HostAdapter not initialized: call setHost() first.');
  return current;
}
