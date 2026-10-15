/**
 * The seam between OCM Lens and whatever hosts it: the browser, or a VS Code
 * webview. Everything environment-specific goes through here so the app
 * stays host-agnostic.
 */

/**
 * A file the host pushed in. Pushed bytes and fetched resource URIs both
 * arrive as Blobs; a file the host could not hand over carries the reason
 * instead, so the app reports it rather than parsing an empty file.
 */
export type HostPushFile =
  | { fileName: string; blob: Blob; error?: undefined }
  | { fileName: string; blob?: undefined; error: string };

export interface Host {
  kind: 'web' | 'vscode';
  /** The bundle worker (module worker on the web, Blob-instantiated in VS Code). */
  createWorker(): Worker;
  /** Small, non-sensitive preferences (pinned public keys). Never throws. */
  readPref(key: string): string | null;
  persistPref(key: string, value: string): void;
  /** Hand a file to the user: browser download or VS Code save dialog. */
  saveFile(fileName: string, mime: string, data: Uint8Array | string): void;
  /**
   * Files the host pushes in (VS Code: custom editor, folder open, workspace
   * scan, registry fetch, deep link). Registering signals readiness.
   */
  onPush(callback: (files: HostPushFile[]) => void): void;
}
