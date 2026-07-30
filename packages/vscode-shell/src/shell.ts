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
  /**
   * Open (or reuse) the shared panel and push in-memory files into it.
   * `compare` asks the webview to open its Diff view over the push
   * (exactly two files: base first, candidate second).
   */
  openFiles(
    files: { fileName: string; bytes: Uint8Array }[],
    title: string,
    opts?: { compare?: boolean },
  ): Promise<void>;
}

/**
 * Files up to this size are pushed as bytes (one message, overlay-sniffable).
 * Anything larger rides as a webview-resource URI the webview fetches into a
 * disk-backed Blob — the old behavior (read fully, or skip over 50 MB) held
 * whole deliveries in extension-host memory and skipped the rest.
 */
const INLINE_PUSH_BYTES = 32 * 1024 * 1024;
const MAX_PROFILE_BYTES = 65536;

export function activateLens(context: vscode.ExtensionContext, config: LensShellConfig): LensShellApi {
  /**
   * One shared panel for every multi-document surface (workspace scan,
   * folder, explorer multi-select); re-running replaces its content.
   */
  let sharedPanel: vscode.WebviewPanel | null = null;

  async function showDeliveryPanel(uris: readonly vscode.Uri[], title: string): Promise<void> {
    if (uris.length === 0) return;
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
        title: `${config.displayName}: loading ${uris.length} file(s)...`,
      },
      () => setupWebview(context, config, sharedPanel!, { uris }),
    );
  }

  async function openFiles(
    files: { fileName: string; bytes: Uint8Array }[],
    title: string,
    opts?: { compare?: boolean },
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
    await setupWebview(context, config, sharedPanel, { files, compare: opts?.compare });
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
  /** Ask the webview to diff the pushed pair (base first). */
  compare?: boolean;
}

async function setupWebview(
  context: vscode.ExtensionContext,
  config: LensShellConfig,
  panel: vscode.WebviewPanel,
  source: WebviewSource,
): Promise<void> {
  const mediaRoot = vscode.Uri.joinPath(context.extensionUri, 'media');
  // Files over the inline threshold are served to the webview as resource
  // URIs (fetched into disk-backed Blobs there), which needs their parent
  // directories among the resource roots. Only the large ones widen the
  // webview's read scope; small files keep riding the byte push.
  const sourceUris = source.uris ?? [];
  const sizes = await Promise.all(
    sourceUris.map(async (uri) => (await vscode.workspace.fs.stat(uri)).size),
  );
  const largeParents = sourceUris
    .filter((_, i) => sizes[i]! > INLINE_PUSH_BYTES)
    .map((uri) => vscode.Uri.joinPath(uri, '..'));
  panel.webview.options = {
    enableScripts: true,
    localResourceRoots: [mediaRoot, ...largeParents],
  };

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
        const files: { fileName: string; bytes: Uint8Array }[] = [];
        const handles: { fileName: string; uri: string }[] = [];
        for (const [i, uri] of sourceUris.entries()) {
          const fileName = uri.path.split('/').pop() ?? config.defaultFileName;
          if (sizes[i]! > INLINE_PUSH_BYTES) {
            handles.push({ fileName, uri: panel.webview.asWebviewUri(uri).toString() });
          } else {
            files.push({ fileName, bytes: new Uint8Array(await vscode.workspace.fs.readFile(uri)) });
          }
        }
        files.push(...(source.files ?? []));
        files.push(...(await workspaceProfiles(config.profileDir)));
        if (files.length > 0)
          post({ type: 'ingestFiles', files, ...(source.compare ? { compare: true } : {}) });
        if (handles.length > 0) post({ type: 'ingestUris', files: handles });
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
