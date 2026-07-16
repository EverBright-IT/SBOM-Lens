import type { SbomElement } from '../model/document';
import type { DocumentId } from '../model/ids';
import { purlWithoutVersion } from '../parse/spdx2/common';
import type { WorkspaceState } from '../workspace/workspace';

/**
 * Version sprawl across the cascade: the same package identity appearing in
 * more than one version anywhere in the workspace. Identity is the purl
 * without its version (`pkg:apk/alpine/openssl`), falling back to the
 * lowercased name for purl-less packages.
 */

export interface VersionOccurrence {
  element: SbomElement;
  docId: DocumentId;
  docName: string;
}

export interface VersionGroup {
  /** Display version — '(no version)' when absent. */
  version: string;
  occurrences: VersionOccurrence[];
}

export interface ConflictGroup {
  key: string;
  name: string;
  versions: VersionGroup[];
  total: number;
}

export const NO_VERSION = '(no version)';

export function packageKey(element: SbomElement): string {
  const base = element.purl
    ? `purl:${purlWithoutVersion(element.purl)}`
    : `name:${element.name.toLowerCase()}`;
  // OCM artifacts are identified by name PLUS extraIdentity: two resources
  // named "config" for different platforms are different artifacts and must
  // never merge into one conflict/diff identity.
  const extra = element.ocm?.extraIdentity;
  if (!extra) return base;
  const suffix = Object.entries(extra)
    .sort(([x], [y]) => x.localeCompare(y))
    .map(([k, v]) => `${k}=${v}`)
    .join(',');
  return suffix ? `${base}#${suffix}` : base;
}

export function findVersionConflicts(ws: WorkspaceState): ConflictGroup[] {
  const groups = new Map<string, { name: string; versions: Map<string, VersionOccurrence[]> }>();

  for (const docId of ws.order) {
    const loaded = ws.documents.get(docId);
    if (!loaded) continue;
    for (const element of loaded.document.elements) {
      if (element.kind !== 'package') continue;
      const key = packageKey(element);
      let group = groups.get(key);
      if (!group) {
        group = { name: element.name, versions: new Map() };
        groups.set(key, group);
      }
      const version = element.version ?? NO_VERSION;
      const occurrences = group.versions.get(version);
      const occurrence: VersionOccurrence = {
        element,
        docId,
        docName: loaded.document.name,
      };
      if (occurrences) occurrences.push(occurrence);
      else group.versions.set(version, [occurrence]);
    }
  }

  const conflicts: ConflictGroup[] = [];
  for (const [key, group] of groups) {
    if (group.versions.size < 2) continue;
    const versions = [...group.versions.entries()]
      .map(([version, occurrences]) => ({ version, occurrences }))
      .sort((a, b) => a.version.localeCompare(b.version, undefined, { numeric: true }));
    conflicts.push({
      key,
      name: group.name,
      versions,
      total: versions.reduce((n, v) => n + v.occurrences.length, 0),
    });
  }
  return conflicts.sort(
    (a, b) => b.versions.length - a.versions.length || a.name.localeCompare(b.name),
  );
}
