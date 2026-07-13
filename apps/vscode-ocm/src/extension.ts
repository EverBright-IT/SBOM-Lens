import type * as vscode from 'vscode';
import { activateLens } from '@sbomlens/vscode-shell';

/** OCM Lens: the delivery-first flavor. All mechanics live in the shared shell. */
export function activate(context: vscode.ExtensionContext): void {
  activateLens(context, {
    viewType: 'ocmlens.viewer',
    commandPrefix: 'ocmlens',
    displayName: 'OCM Lens',
    fileGlob:
      '{**/component-descriptor.yaml,**/component-descriptor.yml,**/component-descriptor.json,**/*.ctf}',
    filesNoun: 'OCM component descriptors',
    prefPrefix: 'ocmlens.',
    profileDir: '.ocmlens',
    defaultFileName: 'component-descriptor.yaml',
  });
}

export function deactivate(): void {}
