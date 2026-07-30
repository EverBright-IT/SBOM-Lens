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
    vscode.commands.registerCommand('ocmlens.compareFromRegistry', () => void compareFromRegistry()),
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

  /** Shared prompts: registry (setting or free text) → component name. */
  async function pickRegistryAndComponent(): Promise<
    { registry: string; component: string } | undefined
  > {
    const configured = vscode.workspace.getConfiguration('ocmlens').get<string[]>('registries') ?? [];
    let registry: string | undefined;
    if (configured.length > 0) {
      const ENTER_OTHER = 'Other registry...';
      const pick = await vscode.window.showQuickPick([...configured, ENTER_OTHER], {
        title: 'OCM registry',
        placeHolder: 'ghcr.io/acme/ocm',
      });
      if (pick === undefined) return undefined;
      registry = pick === ENTER_OTHER ? undefined : pick;
    }
    registry ??= await vscode.window.showInputBox({
      title: 'OCM registry',
      prompt: 'OCI registry holding the component descriptors, e.g. ghcr.io/open-component-model/ocm',
      ignoreFocusOut: true,
    });
    if (!registry) return undefined;

    const component = await vscode.window.showInputBox({
      title: 'Component name',
      prompt: 'e.g. ocm.software/ocmcli',
      ignoreFocusOut: true,
    });
    if (!component) return undefined;
    return { registry, component };
  }

  /** Tag list with progress; undefined means "already reported to the user". */
  async function listVersionsReported(registry: string, component: string): Promise<string[] | undefined> {
    const versions = await vscode.window.withProgress(
      { location: vscode.ProgressLocation.Notification, title: `OCM Lens: listing ${component} versions...` },
      () => client.listVersions(registry, component),
    );
    if (!versions.ok) {
      void vscode.window.showErrorMessage(`OCM Lens: ${versions.error}`);
      return undefined;
    }
    if (versions.versions.length === 0) {
      void vscode.window.showInformationMessage(`OCM Lens: no versions found for ${component}.`);
      return undefined;
    }
    return versions.versions;
  }

  /** Fetch one component version as a CTF; undefined means "already reported". */
  async function fetchVersionReported(
    registry: string,
    component: string,
    version: string,
  ): Promise<{ fileName: string; ctf: Uint8Array; skippedLayers: number } | undefined> {
    const resolved = await vscode.window.withProgress(
      { location: vscode.ProgressLocation.Notification, title: `OCM Lens: fetching ${component}@${version}...` },
      () => client.fetchComponentVersion(registry, component, version),
    );
    if (!resolved.ok) {
      void vscode.window.showErrorMessage(`OCM Lens: ${resolved.error}`);
      return undefined;
    }
    return resolved;
  }

  function warnSkippedLayers(skipped: number): void {
    if (skipped > 0) {
      void vscode.window.showWarningMessage(
        `OCM Lens: ${skipped} large layer(s) were not downloaded; their resources show without content.`,
      );
    }
  }

  /** QuickPick flow: registry (setting or free text) → component → version. */
  async function openFromRegistry(): Promise<void> {
    const target = await pickRegistryAndComponent();
    if (!target) return;
    const versions = await listVersionsReported(target.registry, target.component);
    if (!versions) return;
    const version = await vscode.window.showQuickPick([...versions].reverse(), {
      title: `${target.component}: pick a version`,
    });
    if (!version) return;

    const resolved = await fetchVersionReported(target.registry, target.component, version);
    if (!resolved) return;
    warnSkippedLayers(resolved.skippedLayers);
    await lens.openFiles(
      [{ fileName: resolved.fileName, bytes: resolved.ctf }],
      `OCM Lens: ${target.component}@${version}`,
    );
  }

  /**
   * Same flow, but two versions land in one panel and the webview opens its
   * Diff view over them (older side = base). "What changed between 1.0.0
   * and 1.1.0 of the delivered component?" without leaving the editor.
   */
  async function compareFromRegistry(): Promise<void> {
    const target = await pickRegistryAndComponent();
    if (!target) return;
    const versions = await listVersionsReported(target.registry, target.component);
    if (!versions) return;
    if (versions.length < 2) {
      void vscode.window.showInformationMessage(
        `OCM Lens: ${target.component} has only one version; nothing to compare.`,
      );
      return;
    }
    const picked = await vscode.window.showQuickPick([...versions].reverse(), {
      title: `${target.component}: pick two versions to compare`,
      canPickMany: true,
    });
    if (!picked) return;
    if (picked.length !== 2) {
      void vscode.window.showErrorMessage(
        `OCM Lens: pick exactly two versions (got ${picked.length}).`,
      );
      return;
    }
    // Registry tag order is ascending; diff from the older to the newer.
    const [base, candidate] = [...picked].sort((a, b) => versions.indexOf(a) - versions.indexOf(b));
    const resolvedBase = await fetchVersionReported(target.registry, target.component, base!);
    if (!resolvedBase) return;
    const resolvedCandidate = await fetchVersionReported(target.registry, target.component, candidate!);
    if (!resolvedCandidate) return;
    warnSkippedLayers(resolvedBase.skippedLayers + resolvedCandidate.skippedLayers);
    await lens.openFiles(
      [
        { fileName: resolvedBase.fileName, bytes: resolvedBase.ctf },
        { fileName: resolvedCandidate.fileName, bytes: resolvedCandidate.ctf },
      ],
      `OCM Lens: ${target.component} ${base} vs ${candidate}`,
      { compare: true },
    );
  }
}

export function deactivate(): void {}
