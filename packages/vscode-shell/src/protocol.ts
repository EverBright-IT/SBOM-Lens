/**
 * Message protocol between the extension shell and the Lens webviews (SBOM
 * Lens in apps/web, OCM Lens 2.x in apps/ocm-lens). The shell owns the
 * contract; webviews import it through the `./protocol` subpath export. This
 * module has no imports and touches no VS Code API, so webview bundles can
 * depend on it.
 */

export interface PushedFile {
  fileName: string;
  /** Uint8Array survives the webview structured clone in both directions. */
  bytes: Uint8Array;
}

/** webview → extension */
export type WebviewToHostMessage =
  | { type: 'ready' }
  | { type: 'fetchUrl'; id: number; url: string; headers: Record<string, string> }
  | { type: 'secretGet'; id: number; key: string }
  | { type: 'secretSet'; key: string; value: string | null }
  | { type: 'persistPref'; key: string; value: string }
  | { type: 'exportFile'; fileName: string; mime: string; text: string }
  /** Binary-safe save (OCM Lens 2.0: artifact blobs, reports). Webviews cannot download. */
  | { type: 'exportBytes'; fileName: string; bytes: Uint8Array }
  | { type: 'openExternal'; url: string }
  // OCM registry browsing — handled only by the OCM Lens extension's extra
  // bridge handler; the SBOM flavor never sends them (its UI is compiled
  // out) and its bridge would ignore them.
  | { type: 'ocmListVersions'; id: number; registry: string; component: string }
  | { type: 'ocmResolve'; id: number; registry: string; component: string; version: string };

/** extension → webview */
export type HostToWebviewMessage =
  /**
   * `compare` asks the webview to open the Diff view over the push: exactly
   * two documents expected, first = base (A), second = candidate (B).
   */
  | { type: 'ingestFiles'; files: PushedFile[]; compare?: boolean }
  /**
   * Large files ride as webview-resource URIs instead of bytes: the webview
   * fetches them into disk-backed Blobs and the worker streams via slice(),
   * so a multi-GB delivery never exists as one buffer on either side.
   */
  | { type: 'ingestUris'; files: { fileName: string; uri: string }[] }
  | {
      type: 'fetchResult';
      id: number;
      ok: boolean;
      status?: number;
      statusText?: string;
      bytes?: Uint8Array;
    }
  | { type: 'secretValue'; id: number; value: string | null }
  | { type: 'ocmVersions'; id: number; ok: boolean; versions?: string[]; error?: string }
  /** The resolved CTF itself arrives via a separate ingestFiles push. */
  | { type: 'ocmResolved'; id: number; ok: boolean; skippedLayers?: number; error?: string };

/** Injected by buildWebviewHtml so sync pref reads work before any message. */
export const PREFS_GLOBAL = '__SBOMLENS_PREFS__';
