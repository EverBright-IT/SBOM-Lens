import { ingestBuffers } from '../app/ingest';
import { useAppStore } from '../app/store';
import { rootNodes } from '@sbomlens/core';

/**
 * The bundled demo cascade. acme-identity is deliberately NOT loaded so the
 * unresolved-reference placeholder and its fetch/drop flow are discoverable —
 * its file ships under examples/extra/ and the placeholder's URL points there.
 */
const EXAMPLE_FILES = [
  'examples/acme-platform-1.0.spdx',
  'examples/acme-webstack-2.1.spdx.json',
  'examples/acme-runtime-image-3.0.spdx',
];

export async function loadExample(): Promise<void> {
  const { actions } = useAppStore.getState();
  try {
    const entries = await Promise.all(
      EXAMPLE_FILES.map(async (path) => {
        const response = await fetch(path);
        if (!response.ok) throw new Error(`${path}: ${response.status}`);
        return { fileName: path.split('/').pop()!, buffer: await response.arrayBuffer() };
      }),
    );
    await ingestBuffers(entries);
  } catch {
    actions.toast('Could not load the bundled example.', 'error');
    return;
  }

  // Open the cascade one level so the demo starts with something to see.
  const state = useAppStore.getState();
  const roots = rootNodes(state.ws);
  if (roots.length > 0) {
    state.actions.expandPaths(roots.map((r) => r.path));
    state.actions.select({ path: roots[0]!.path, target: roots[0]!.target });
  }
}
