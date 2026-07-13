/**
 * Message protocol between the SBOM Lens webview and the VS Code extension
 * host. The extension imports these types only (type-only import via the
 * package's subpath export) — no runtime coupling in either direction.
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
  | { type: 'openExternal'; url: string };

/** extension → webview */
export type HostToWebviewMessage =
  | { type: 'ingestFiles'; files: PushedFile[] }
  | {
      type: 'fetchResult';
      id: number;
      ok: boolean;
      status?: number;
      statusText?: string;
      bytes?: Uint8Array;
    }
  | { type: 'secretValue'; id: number; value: string | null };

/** Injected by buildWebviewHtml so sync pref reads work before any message. */
export const PREFS_GLOBAL = '__SBOMLENS_PREFS__';
