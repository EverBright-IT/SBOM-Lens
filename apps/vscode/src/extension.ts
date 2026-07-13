import { randomBytes } from 'node:crypto';
import * as vscode from 'vscode';
import type { HostToWebviewMessage } from '@sbomlens/web/vscode-protocol';
import type { BridgeContext } from './bridge';
import { buildWebviewHtml, createBridgeHandler, nodeFetchBytes, prefsSnapshot } from './bridge';

const VIEW_TYPE = 'sbomlens.viewer';
const MAX_SCAN_BYTES = 50 * 1024 * 1024;
const MAX_PROFILE_BYTES = 65536;
const SBOM_GLOB = '{**/*.spdx,**/*.spdx.json,**/*.spdx.yaml,**/*.spdx.yml}';

/**
 * Workspace compliance profiles (.sbomlens/profile.json per folder) ride the
 * same push channel as documents — the webview's content sniff imports them.
 */
async function workspaceProfiles(): Promise<{ fileName: string; bytes: Uint8Array<ArrayBuffer> }[]> {
  const found: { fileName: string; bytes: Uint8Array<ArrayBuffer> }[] = [];
  for (const folder of vscode.workspace.workspaceFolders ?? []) {
    const uri = vscode.Uri.joinPath(folder.uri, '.sbomlens', 'profile.json');
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

export function activate(context: vscode.ExtensionContext): void {
  context.subscriptions.push(
    vscode.window.registerCustomEditorProvider(VIEW_TYPE, new SbomEditorProvider(context), {
      webviewOptions: { retainContextWhenHidden: true },
      supportsMultipleEditorsPerDocument: true,
    }),
    vscode.commands.registerCommand(
      'sbomlens.openWith',
      (uri?: vscode.Uri, uris?: vscode.Uri[]) => {
        // Explorer multi-select passes every selected uri as the 2nd arg —
        // several files belong together, so they share ONE panel.
        const selection = (uris?.length ? uris : [uri ?? vscode.window.activeTextEditor?.document.uri])
          .filter((u): u is vscode.Uri => u !== undefined);
        if (selection.length === 0) return;
        if (selection.length === 1) {
          void vscode.commands.executeCommand('vscode.openWith', selection[0], VIEW_TYPE);
          return;
        }
        void showDeliveryPanel(context, selection, `SBOM Lens — ${selection.length} files`);
      },
    ),
    vscode.commands.registerCommand('sbomlens.openFolder', (uri?: vscode.Uri) => {
      if (uri) void openFolder(context, uri);
    }),
    vscode.commands.registerCommand('sbomlens.scanWorkspace', () => void scanWorkspace(context)),
  );
}

/** All SPDX files under one folder — the middle ground between one file and the whole workspace. */
async function openFolder(context: vscode.ExtensionContext, folder: vscode.Uri): Promise<void> {
  const uris = await vscode.workspace.findFiles(
    new vscode.RelativePattern(folder, SBOM_GLOB),
    '**/node_modules/**',
  );
  if (uris.length === 0) {
    void vscode.window.showInformationMessage('SBOM Lens: no SPDX files found in this folder.');
    return;
  }
  const folderName = folder.path.split('/').pop() ?? 'folder';
  await showDeliveryPanel(context, uris, `SBOM Lens — ${folderName}`);
}

export function deactivate(): void {}

class SbomEditorProvider implements vscode.CustomReadonlyEditorProvider {
  constructor(private readonly context: vscode.ExtensionContext) {}

  openCustomDocument(uri: vscode.Uri): vscode.CustomDocument {
    return { uri, dispose: () => {} };
  }

  async resolveCustomEditor(
    document: vscode.CustomDocument,
    panel: vscode.WebviewPanel,
  ): Promise<void> {
    await setupWebview(this.context, panel, [document.uri]);
  }
}

async function scanWorkspace(context: vscode.ExtensionContext): Promise<void> {
  const uris = await vscode.workspace.findFiles(SBOM_GLOB, '**/node_modules/**');
  if (uris.length === 0) {
    void vscode.window.showInformationMessage('SBOM Lens: no SPDX files found in the workspace.');
    return;
  }
  await showDeliveryPanel(context, uris, 'SBOM Lens — workspace');
}

/**
 * One shared panel for every multi-document surface (workspace scan, folder,
 * explorer multi-select); re-running replaces its content.
 */
let sharedPanel: vscode.WebviewPanel | null = null;

async function showDeliveryPanel(
  context: vscode.ExtensionContext,
  uris: readonly vscode.Uri[],
  title: string,
): Promise<void> {
  const kept: vscode.Uri[] = [];
  let skipped = 0;
  for (const uri of uris) {
    const stat = await vscode.workspace.fs.stat(uri);
    if (stat.size > MAX_SCAN_BYTES) skipped++;
    else kept.push(uri);
  }
  if (skipped > 0) {
    void vscode.window.showWarningMessage(`SBOM Lens: skipped ${skipped} file(s) over 50 MB.`);
  }
  if (kept.length === 0) return;

  if (!sharedPanel) {
    sharedPanel = vscode.window.createWebviewPanel(VIEW_TYPE, title, {
      viewColumn: vscode.ViewColumn.Active,
    });
    sharedPanel.onDidDispose(() => (sharedPanel = null));
  } else {
    sharedPanel.title = title;
    sharedPanel.reveal();
  }
  await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: `SBOM Lens: loading ${kept.length} file(s)…` },
    () => setupWebview(context, sharedPanel!, kept),
  );
}

async function setupWebview(
  context: vscode.ExtensionContext,
  panel: vscode.WebviewPanel,
  uris: readonly vscode.Uri[],
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
    prefs: prefsSnapshot(context.globalState.keys(), (key) => context.globalState.get(key)),
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
        const files = await Promise.all(
          uris.map(async (uri) => ({
            fileName: uri.path.split('/').pop() ?? 'document.spdx',
            bytes: new Uint8Array(await vscode.workspace.fs.readFile(uri)),
          })),
        );
        files.push(...(await workspaceProfiles()));
        if (files.length > 0) post({ type: 'ingestFiles', files });
      })();
    },
  };

  const handle = createBridgeHandler(post, bridge);
  panel.webview.onDidReceiveMessage(
    (message) => void handle(message),
    undefined,
    context.subscriptions,
  );
}
