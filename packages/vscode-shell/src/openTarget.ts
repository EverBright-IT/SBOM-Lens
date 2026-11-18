/**
 * What "Open with ..." acts on. The explorer passes its selection (every
 * selected resource as the second argument). The command palette passes
 * nothing: the command then takes the file of the active text editor, or of
 * the active tab when that is not a text editor, so a file opens whatever it
 * is called. Generic over the resource type to stay free of the vscode API.
 */
export function pickOpenTargets<T>(
  uri: T | undefined,
  uris: readonly T[] | undefined,
  active: { textEditor?: T; tab?: T },
): T[] {
  if (uris !== undefined && uris.length > 0) return [...uris];
  const single = uri ?? active.textEditor ?? active.tab;
  return single !== undefined ? [single] : [];
}
