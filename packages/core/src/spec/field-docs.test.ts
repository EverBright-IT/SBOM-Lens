import { describe, expect, it } from 'vitest';
import { SPDX23_DOCS } from './spdx23-field-docs';

/** Guards the generated spec docs against a broken regeneration. */
describe('SPDX 2.3 field docs (generated)', () => {
  it('carries descriptions for the fields the detail views show', () => {
    for (const key of ['versionInfo', 'supplier', 'downloadLocation', 'licenseConcluded']) {
      expect(SPDX23_DOCS.package[key]?.description, key).toBeTruthy();
    }
    for (const key of ['documentNamespace', 'created', 'creators']) {
      expect(SPDX23_DOCS.document[key]?.description, key).toBeTruthy();
    }
    expect(SPDX23_DOCS.file.fileName?.description).toBeTruthy();
  });

  it('carries the spec enums', () => {
    expect(SPDX23_DOCS.package.primaryPackagePurpose?.enum).toContain('CONTAINER');
    expect(SPDX23_DOCS.relationshipType?.enum).toContain('CONTAINS');
    expect(SPDX23_DOCS.relationshipType?.enum?.length).toBeGreaterThan(40);
  });

  it('links every shown field into the rendered spec', () => {
    const origin = 'https://spdx.github.io/spdx-spec/v2.3/';
    expect(SPDX23_DOCS.package.versionInfo?.specUrl).toBe(
      `${origin}package-information/#73-package-version-field`,
    );
    expect(SPDX23_DOCS.document.documentNamespace?.specUrl).toBe(
      `${origin}document-creation-information/#65-spdx-document-namespace-field`,
    );
    expect(SPDX23_DOCS.relationshipType?.specUrl).toBe(
      `${origin}relationships-between-SPDX-elements/#111-relationship-field`,
    );
    for (const group of [SPDX23_DOCS.document, SPDX23_DOCS.package, SPDX23_DOCS.file]) {
      for (const [key, doc] of Object.entries(group)) {
        expect(doc.specUrl, key).toMatch(new RegExp(`^${origin.replaceAll('.', '\\.')}`));
      }
    }
  });
});

describe('OCM field docs (hand-curated)', () => {
  it('links every entry into the ocm-spec repo and carries the OCM spec name', async () => {
    const { OCM_DOCS } = await import('./ocm-field-docs');
    const all = [
      ...Object.values(OCM_DOCS.document),
      ...Object.values(OCM_DOCS.package),
      OCM_DOCS.relationshipType,
    ];
    expect(all.length).toBeGreaterThanOrEqual(10);
    for (const doc of all) {
      expect(doc.specName).toBe('OCM');
      expect(doc.description.length).toBeGreaterThan(20);
      expect(doc.specUrl).toMatch(
        /^https:\/\/github\.com\/open-component-model\/ocm-spec\/blob\/main\/doc\/01-model\//,
      );
    }
  });

  it('covers the field keys the detail views look up', async () => {
    const { OCM_DOCS } = await import('./ocm-field-docs');
    for (const key of ['documentNamespace', 'spdxVersion', 'created', 'creators', 'externalDocumentRefs']) {
      expect(OCM_DOCS.document[key], `document.${key}`).toBeDefined();
    }
    for (const key of ['versionInfo', 'primaryPackagePurpose', 'downloadLocation', 'checksums', 'SPDXID']) {
      expect(OCM_DOCS.package[key], `package.${key}`).toBeDefined();
    }
  });
});
