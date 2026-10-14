import type { Host } from './types';
import { createVscodeHost } from './vscode';
import { webHost } from './web';

/**
 * Build-time constant: `vite build --mode vscode` produces the webview
 * bundle. The dead branch below folds away, so the browser build never
 * talks to acquireVsCodeApi and the webview never touches localStorage.
 */
export const IS_VSCODE = import.meta.env.MODE === 'vscode';

export const host: Host = IS_VSCODE ? createVscodeHost() : webHost;

export type { Host, HostPushFile } from './types';
