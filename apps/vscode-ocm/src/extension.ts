import * as vscode from 'vscode';
import type { RegistryCredential } from '@sbomlens/vscode-shell';
import { activateLens, createOcmBridgeHandler, createOcmRegistryClient } from '@sbomlens/vscode-shell';

/** OCM Lens: the delivery-first flavor. All mechanics live in the shared shell. */
export function activate(context: vscode.ExtensionContext): void {
  // Registry credentials live in VS Code secrets as `ocmlens.registry.<host>`
  // with a `user:token` value; absent means anonymous (public registries).
  // (`ocmlens.token.<host>` is taken: the webview stores URL-fetch tokens
  // there as JSON.)
  const credentialFor = async (host: string): Promise<RegistryCredential | undefined> => {
    const stored = await context.secrets.get(`ocmlens.registry.${host}`);
    if (!stored) return undefined;
    const colon = stored.indexOf(':');
    if (colon === -1) return { username: 'token', password: stored };
    return { username: stored.slice(0, colon), password: stored.slice(colon + 1) };
  };
  const client = createOcmRegistryClient({ credentialFor });

  const lens = activateLens(context, {
    viewType: 'ocmlens.viewer',
    commandPrefix: 'ocmlens',
    displayName: 'OCM Lens',
    fileGlob:
      '{**/component-descriptor.yaml,**/component-descriptor.yml,**/component-descriptor.json,**/*.ctf}',
    filesNoun: 'OCM component descriptors',
    prefPrefix: 'ocmlens.',
    profileDir: '.ocmlens',
    defaultFileName: 'component-descriptor.yaml',
    extraBridge: (post) => createOcmBridgeHandler(client, post),
  });

  context.subscriptions.push(
    vscode.commands.registerCommand('ocmlens.openFromRegistry', () => void openFromRegistry()),
    vscode.commands.registerCommand('ocmlens.setRegistryCredential', () => void setRegistryCredential()),
  );

  /** Store (or clear) the per-host registry credential in VS Code secrets. */
  async function setRegistryCredential(): Promise<void> {
    const host = await vscode.window.showInputBox({
      title: 'Registry host',
      prompt: 'Host the credential is for, e.g. ghcr.io',
      ignoreFocusOut: true,
    });
    if (!host) return;
    const value = await vscode.window.showInputBox({
      title: `Credential for ${host}`,
      prompt: 'user:token (leave empty to remove the stored credential)',
      password: true,
      ignoreFocusOut: true,
    });
    if (value === undefined) return;
    if (value === '') {
      await context.secrets.delete(`ocmlens.registry.${host}`);
      void vscode.window.showInformationMessage(`OCM Lens: removed the credential for ${host}.`);
    } else {
      await context.secrets.store(`ocmlens.registry.${host}`, value);
      void vscode.window.showInformationMessage(`OCM Lens: stored a credential for ${host}.`);
    }
  }

  // Deep link for external tools: vscode://everbright-it.ocmlens/open?path=/abs/delivery.ctf
  // (VS Code asks the user before handing an external URI to the extension.)
  context.subscriptions.push(
    vscode.window.registerUriHandler({
      handleUri: (uri) => {
        const path = new URLSearchParams(uri.query).get('path');
        if (!path) {
          void vscode.window.showErrorMessage('OCM Lens: the open link needs a path query parameter.');
          return;
        }
        void openLocalPath(path);
      },
    }),
  );

  async function openLocalPath(path: string): Promise<void> {
    try {
      const fileUri = vscode.Uri.file(path);
      const bytes = new Uint8Array(await vscode.workspace.fs.readFile(fileUri));
      const fileName = path.split('/').pop() ?? 'component-descriptor.yaml';
      await lens.openFiles([{ fileName, bytes }], `OCM Lens: ${fileName}`);
    } catch (error) {
      void vscode.window.showErrorMessage(`OCM Lens: could not open ${path} (${String(error)})`);
    }
  }

  /** QuickPick flow: registry (setting or free text) → component → version. */
  async function openFromRegistry(): Promise<void> {
    const configured = vscode.workspace.getConfiguration('ocmlens').get<string[]>('registries') ?? [];
    let registry: string | undefined;
    if (configured.length > 0) {
      const ENTER_OTHER = 'Other registry...';
      const pick = await vscode.window.showQuickPick([...configured, ENTER_OTHER], {
        title: 'OCM registry',
        placeHolder: 'ghcr.io/acme/ocm',
      });
      if (pick === undefined) return;
      registry = pick === ENTER_OTHER ? undefined : pick;
    }
    registry ??= await vscode.window.showInputBox({
      title: 'OCM registry',
      prompt: 'OCI registry holding the component descriptors, e.g. ghcr.io/open-component-model/ocm',
      ignoreFocusOut: true,
    });
    if (!registry) return;

    const component = await vscode.window.showInputBox({
      title: 'Component name',
      prompt: 'e.g. ocm.software/ocmcli',
      ignoreFocusOut: true,
    });
    if (!component) return;

    const versions = await vscode.window.withProgress(
      { location: vscode.ProgressLocation.Notification, title: `OCM Lens: listing ${component} versions...` },
      () => client.listVersions(registry, component),
    );
    if (!versions.ok) {
      void vscode.window.showErrorMessage(`OCM Lens: ${versions.error}`);
      return;
    }
    if (versions.versions.length === 0) {
      void vscode.window.showInformationMessage(`OCM Lens: no versions found for ${component}.`);
      return;
    }
    const version = await vscode.window.showQuickPick([...versions.versions].reverse(), {
      title: `${component}: pick a version`,
    });
    if (!version) return;

    const resolved = await vscode.window.withProgress(
      { location: vscode.ProgressLocation.Notification, title: `OCM Lens: fetching ${component}@${version}...` },
      () => client.fetchComponentVersion(registry, component, version),
    );
    if (!resolved.ok) {
      void vscode.window.showErrorMessage(`OCM Lens: ${resolved.error}`);
      return;
    }
    if (resolved.skippedLayers > 0) {
      void vscode.window.showWarningMessage(
        `OCM Lens: ${resolved.skippedLayers} large layer(s) were not downloaded; their resources show without content.`,
      );
    }
    await lens.openFiles(
      [{ fileName: resolved.fileName, bytes: resolved.ctf }],
      `OCM Lens: ${component}@${version}`,
    );
  }
}

export function deactivate(): void {}
