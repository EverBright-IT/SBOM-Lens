import type * as vscode from 'vscode';
import { activateLens } from '@sbomlens/vscode-shell';

/** SBOM Lens: the SPDX-first flavor. All mechanics live in the shared shell. */
export function activate(context: vscode.ExtensionContext): void {
  activateLens(context, {
    viewType: 'sbomlens.viewer',
    commandPrefix: 'sbomlens',
    displayName: 'SBOM Lens',
    // Folder open and workspace scan walk this glob; it must agree with the
    // customEditors selector in package.json, or a file the editor opens is
    // one the scan never finds.
    fileGlob:
      '{**/*.spdx,**/*.spdx.json,**/*.spdx.yaml,**/*.spdx.yml,**/*.cdx.json,**/*.bom.json,**/*.cdx.xml,**/*.bom.xml}',
    filesNoun: 'SBOM files',
    prefPrefix: 'sbomlens.',
    profileDir: '.sbomlens',
    defaultFileName: 'document.spdx',
  });
}

export function deactivate(): void {}
