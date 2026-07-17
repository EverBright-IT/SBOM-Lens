import { randomBytes } from 'node:crypto';
import * as vscode from 'vscode';
import type { HostToWebviewMessage, WebviewToHostMessage } from '@sbomlens/web/vscode-protocol';
import type { BridgeContext } from './bridge';
import { buildWebviewHtml, createBridgeHandler, nodeFetchBytes, prefsSnapshot } from './bridge';

/**
 * Everything that differs between the Lens extension flavors. The shell owns
 * the provider/command/panel/webview lifecycle; the flavor owns its identity.
 */
export interface LensShellConfig {
  /** Custom-editor viewType, e.g. "sbomlens.viewer". */
  viewType: string;
  /** Command id prefix, e.g. "sbomlens" → sbomlens.openWith/openFolder/scanWorkspace. */
  commandPrefix: string;
  /** Product name for panel titles and user-facing messages. */
  displayName: string;
  /** findFiles glob for folder open and workspace scan. */
  fileGlob: string;
  /** Noun for "no … found" messages, e.g. "SPDX files". */
  filesNoun: string;
  /** Pref/secret namespace — must match the bundled webview flavor. */
  prefPrefix: string;
  /** Workspace directory holding a compliance profile.json, e.g. ".sbomlens". */
  profileDir: string;
  /** Fallback file name for uris without a basename. */
  defaultFileName: string;
  /**
   * Flavor-specific bridge extension, created once per webview panel with
   * that panel's post function (OCM Lens registers its registry handler).
   */
  extraBridge?: (post: (message: HostToWebviewMessage) => void) => (message: WebviewToHostMessage) => Promise<boolean>;
}

/** What activateLens hands back for flavor-specific commands. */
export interface LensShellApi {
  /** Open (or reuse) the shared panel and push in-memory files into it. */
  openFiles(files: { fileName: string; bytes: Uint8Array }[], title: string): Promise<void>;
}

const MAX_SCAN_BYTES = 50 * 1024 * 1024;
const MAX_PROFILE_BYTES = 65536;

export function activateLens(context: vscode.ExtensionContext, config: LensShellConfig): LensShellApi {
  /**
   * One shared panel for every multi-document surface (workspace scan,
   * folder, explorer multi-select); re-running replaces its content.
   */
  let sharedPanel: vscode.WebviewPanel | null = null;

  async function showDeliveryPanel(uris: readonly vscode.Uri[], title: string): Promise<void> {
    const kept: vscode.Uri[] = [];
    let skipped = 0;
    for (const uri of uris) {
      const stat = await vscode.workspace.fs.stat(uri);
      if (stat.size > MAX_SCAN_BYTES) skipped++;
      else kept.push(uri);
    }
    if (skipped > 0) {
      void vscode.window.showWarningMessage(
        `${config.displayName}: skipped ${skipped} file(s) over 50 MB.`,
      );
    }
    if (kept.length === 0) return;

    if (!sharedPanel) {
      sharedPanel = vscode.window.createWebviewPanel(config.viewType, title, {
        viewColumn: vscode.ViewColumn.Active,
      });
      sharedPanel.onDidDispose(() => (sharedPanel = null));
    } else {
      sharedPanel.title = title;
      sharedPanel.reveal();
    }
    await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: `${config.displayName}: loading ${kept.length} file(s)...`,
      },
      () => setupWebview(context, config, sharedPanel!, { uris: kept }),
    );
  }

  async function openFiles(
    files: { fileName: string; bytes: Uint8Array }[],
    title: string,
  ): Promise<void> {
    if (!sharedPanel) {
      sharedPanel = vscode.window.createWebviewPanel(config.viewType, title, {
        viewColumn: vscode.ViewColumn.Active,
      });
      sharedPanel.onDidDispose(() => (sharedPanel = null));
    } else {
      sharedPanel.title = title;
      sharedPanel.reveal();
    }
    await setupWebview(context, config, sharedPanel, { files });
  }

  /** All matching files under one folder — between one file and the whole workspace. */
  async function openFolder(folder: vscode.Uri): Promise<void> {
    const uris = await vscode.workspace.findFiles(
      new vscode.RelativePattern(folder, config.fileGlob),
      '**/node_modules/**',
    );
    if (uris.length === 0) {
      void vscode.window.showInformationMessage(
        `${config.displayName}: no ${config.filesNoun} found in this folder.`,
      );
      return;
    }
    const folderName = folder.path.split('/').pop() ?? 'folder';
    await showDeliveryPanel(uris, `${config.displayName}: ${folderName}`);
  }

  async function scanWorkspace(): Promise<void> {
    const uris = await vscode.workspace.findFiles(config.fileGlob, '**/node_modules/**');
    if (uris.length === 0) {
      void vscode.window.showInformationMessage(
        `${config.displayName}: no ${config.filesNoun} found in the workspace.`,
      );
      return;
    }
    await showDeliveryPanel(uris, `${config.displayName}: workspace`);
  }

  class LensEditorProvider implements vscode.CustomReadonlyEditorProvider {
    openCustomDocument(uri: vscode.Uri): vscode.CustomDocument {
      return { uri, dispose: () => {} };
    }

    async resolveCustomEditor(
      document: vscode.CustomDocument,
      panel: vscode.WebviewPanel,
    ): Promise<void> {
      await setupWebview(context, config, panel, { uris: [document.uri] });
    }
  }

  context.subscriptions.push(
    vscode.window.registerCustomEditorProvider(config.viewType, new LensEditorProvider(), {
      webviewOptions: { retainContextWhenHidden: true },
      supportsMultipleEditorsPerDocument: true,
    }),
    vscode.commands.registerCommand(
      `${config.commandPrefix}.openWith`,
      (uri?: vscode.Uri, uris?: vscode.Uri[]) => {
        // Explorer multi-select passes every selected uri as the 2nd arg —
        // several files belong together, so they share ONE panel.
        const selection = (
          uris?.length ? uris : [uri ?? vscode.window.activeTextEditor?.document.uri]
        ).filter((u): u is vscode.Uri => u !== undefined);
        if (selection.length === 0) return;
        if (selection.length === 1) {
          void vscode.commands.executeCommand('vscode.openWith', selection[0], config.viewType);
          return;
        }
        void showDeliveryPanel(selection, `${config.displayName}: ${selection.length} files`);
      },
    ),
    vscode.commands.registerCommand(`${config.commandPrefix}.openFolder`, (uri?: vscode.Uri) => {
      if (uri) void openFolder(uri);
    }),
    vscode.commands.registerCommand(
      `${config.commandPrefix}.scanWorkspace`,
      () => void scanWorkspace(),
    ),
  );

  return { openFiles };
}

/**
 * Workspace compliance profiles (<profileDir>/profile.json per folder) ride
 * the same push channel as documents — the webview's content sniff imports
 * them.
 */
async function workspaceProfiles(
  profileDir: string,
): Promise<{ fileName: string; bytes: Uint8Array<ArrayBuffer> }[]> {
  const found: { fileName: string; bytes: Uint8Array<ArrayBuffer> }[] = [];
  for (const folder of vscode.workspace.workspaceFolders ?? []) {
    const uri = vscode.Uri.joinPath(folder.uri, profileDir, 'profile.json');
    try {
      const stat = await vscode.workspace.fs.stat(uri);
      if (stat.size > MAX_PROFILE_BYTES) continue;
      found.push({
        fileName: 'profile.json',
        bytes: new Uint8Array(await vscode.workspace.fs.readFile(uri)),
      });
    } catch {
      // No profile in this folder — the normal case.
    }
  }
  return found;
}

interface WebviewSource {
  uris?: readonly vscode.Uri[];
  files?: { fileName: string; bytes: Uint8Array }[];
}

async function setupWebview(
  context: vscode.ExtensionContext,
  config: LensShellConfig,
  panel: vscode.WebviewPanel,
  source: WebviewSource,
): Promise<void> {
  const mediaRoot = vscode.Uri.joinPath(context.extensionUri, 'media');
  panel.webview.options = { enableScripts: true, localResourceRoots: [mediaRoot] };

  const rawHtml = new TextDecoder().decode(
    await vscode.workspace.fs.readFile(vscode.Uri.joinPath(mediaRoot, 'index.html')),
  );
  panel.webview.html = buildWebviewHtml(rawHtml, {
    baseHref: `${panel.webview.asWebviewUri(mediaRoot).toString()}/`,
    cspSource: panel.webview.cspSource,
    nonce: randomBytes(16).toString('base64url'),
    prefs: prefsSnapshot(
      context.globalState.keys(),
      (key) => context.globalState.get(key),
      config.prefPrefix,
    ),
  });

  const post = (message: HostToWebviewMessage) => void panel.webview.postMessage(message);
  const bridge: BridgeContext = {
    fetchBytes: nodeFetchBytes,
    secretGet: (key) => context.secrets.get(key),
    secretStore: (key, value) => context.secrets.store(key, value),
    secretDelete: (key) => context.secrets.delete(key),
    persistPref: (key, value) => context.globalState.update(key, value),
    saveFile: async (fileName, text) => {
      const target = await vscode.window.showSaveDialog({
        defaultUri: vscode.Uri.joinPath(
          vscode.workspace.workspaceFolders?.[0]?.uri ?? vscode.Uri.file(process.cwd()),
          fileName,
        ),
      });
      if (target) await vscode.workspace.fs.writeFile(target, new TextEncoder().encode(text));
    },
    openExternal: (url) => void vscode.env.openExternal(vscode.Uri.parse(url)),
    onReady: () => {
      void (async () => {
        const files: { fileName: string; bytes: Uint8Array }[] = await Promise.all(
          (source.uris ?? []).map(async (uri) => ({
            fileName: uri.path.split('/').pop() ?? config.defaultFileName,
            bytes: new Uint8Array(await vscode.workspace.fs.readFile(uri)),
          })),
        );
        files.push(...(source.files ?? []));
        files.push(...(await workspaceProfiles(config.profileDir)));
        if (files.length > 0) post({ type: 'ingestFiles', files });
      })();
    },
    ...(config.extraBridge ? { extraMessage: config.extraBridge(post) } : {}),
  };

  const handle = createBridgeHandler(post, bridge);
  panel.webview.onDidReceiveMessage(
    (message) => void handle(message),
    undefined,
    context.subscriptions,
  );
}
