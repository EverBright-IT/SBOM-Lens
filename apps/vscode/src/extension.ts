import type * as vscode from 'vscode';
import { activateLens } from '@sbomlens/vscode-shell';

/** SBOM Lens: the SPDX-first flavor. All mechanics live in the shared shell. */
export function activate(context: vscode.ExtensionContext): void {
  activateLens(context, {
    viewType: 'sbomlens.viewer',
    commandPrefix: 'sbomlens',
    displayName: 'SBOM Lens',
    fileGlob: '{**/*.spdx,**/*.spdx.json,**/*.spdx.yaml,**/*.spdx.yml}',
    filesNoun: 'SPDX files',
    prefPrefix: 'sbomlens.',
    profileDir: '.sbomlens',
    defaultFileName: 'document.spdx',
  });
}

export function deactivate(): void {}
