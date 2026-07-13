import { isRecord } from '../util/narrow';

export type Detection =
  | { format: 'spdx2-json'; parsed: Record<string, unknown>; serialization: 'json' | 'yaml' }
  | { format: 'spdx2-tag-value' }
  | { format: 'ocm-cd'; parsed: Record<string, unknown>; serialization: 'json' | 'yaml' }
  | { format: 'unsupported'; code: string; reason: string };

/**
 * YAML support is injected by the caller (the parse worker) so the yaml
 * library never weighs down the main bundle — only the worker parses.
 */
type YamlParser = (text: string) => unknown;
let yamlParser: YamlParser | null = null;

export function registerYamlParser(parser: YamlParser): void {
  yamlParser = parser;
}

/**
 * Content-based only: files named `*.spdx.json` are sometimes Trivy-native
 * reports, so extensions are never trusted. JSON and YAML feed the same
 * normalizer; recognized-but-unsupported formats get a precise message.
 */
export function detect(text: string): Detection {
  const head = text.slice(0, 65536);
  const trimmed = head.trimStart();

  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch (e) {
      return unsupported('JSON_INVALID', `Not valid JSON: ${(e as Error).message}`);
    }
    return classifyObject(parsed, 'json');
  }

  // Tag-value uses `SPDXVersion:` (capital S); YAML serialization uses
  // `spdxVersion:` — the case difference keeps the two unambiguous.
  if (/(^|\n)[ \t]*SPDXVersion:[ \t]*SPDX-/.test(head)) {
    return { format: 'spdx2-tag-value' };
  }

  const looksLikeYamlCd =
    (/(^|\n)meta:/.test(head) && /(^|\n)component:/.test(head) && /schemaVersion/.test(head)) ||
    /(^|\n)apiVersion:[ \t]*(['"]?)ocm\.software\//.test(head);
  if (/(^|\n)[ \t]*(['"]?)spdxVersion\2[ \t]*:/.test(head) || looksLikeYamlCd) {
    if (!yamlParser) {
      return unsupported('YAML_SUPPORT_UNAVAILABLE', 'YAML support is not loaded in this context.');
    }
    let parsed: unknown;
    try {
      parsed = yamlParser(text);
    } catch (e) {
      return unsupported('YAML_INVALID', `Not valid YAML: ${(e as Error).message}`);
    }
    return classifyObject(parsed, 'yaml');
  }

  return unsupported(
    'UNRECOGNIZED_FORMAT',
    'Unrecognized file format — expected SPDX 2.x as tag-value (*.spdx), JSON, or YAML.',
  );
}

function classifyObject(parsed: unknown, serialization: 'json' | 'yaml'): Detection {
  const label = serialization.toUpperCase();
  if (!isRecord(parsed)) {
    return unsupported(`${label}_NOT_OBJECT`, `${label} root is not an object — not an SPDX document.`);
  }

  const context = parsed['@context'];
  const contextStr = Array.isArray(context) ? context.join(' ') : String(context ?? '');
  if (contextStr.includes('spdx.org/rdf/3.')) {
    return unsupported(
      'SPDX3_NOT_YET_SUPPORTED',
      'This is an SPDX 3.x document (JSON-LD). SPDX 3.0 support is on the roadmap; SPDX 2.x documents work today.',
    );
  }

  const spdxVersion = parsed.spdxVersion;
  if (typeof spdxVersion === 'string') {
    if (spdxVersion.startsWith('SPDX-2')) return { format: 'spdx2-json', parsed, serialization };
    return unsupported(
      'SPDX_UNSUPPORTED_VERSION',
      `Unsupported SPDX version "${spdxVersion}" — SPDX 2.x is supported today.`,
    );
  }

  // OCM component descriptor v2: meta.schemaVersion + component{...}.
  if (
    isRecord(parsed.meta) &&
    typeof parsed.meta.schemaVersion === 'string' &&
    isRecord(parsed.component)
  ) {
    return { format: 'ocm-cd', parsed, serialization };
  }
  // OCM v3alpha1: apiVersion ocm.software/... + kind ComponentVersion.
  if (
    typeof parsed.apiVersion === 'string' &&
    parsed.apiVersion.startsWith('ocm.software/') &&
    parsed.kind === 'ComponentVersion'
  ) {
    return { format: 'ocm-cd', parsed, serialization };
  }

  if (typeof parsed.schema === 'string' && parsed.schema.startsWith('sbomlens-profile/')) {
    return unsupported(
      'SBOMLENS_PROFILE',
      'This is an SBOM Lens compliance profile, not an SBOM — drop it into the app to import it as a quality profile.',
    );
  }

  if (parsed.bomFormat === 'CycloneDX') {
    return unsupported(
      'CYCLONEDX_NOT_SUPPORTED',
      'This is a CycloneDX BOM. SBOM Lens reads SPDX — convert it (e.g. `cyclonedx convert`) or export SPDX from your tool.',
    );
  }

  if ('SchemaVersion' in parsed && ('Results' in parsed || 'ArtifactName' in parsed)) {
    return unsupported(
      'TRIVY_NATIVE_NOT_SUPPORTED',
      'This is a Trivy-native report, not SPDX. Re-run trivy with `--format spdx-json`.',
    );
  }

  return unsupported(
    `${label}_NOT_SPDX`,
    `${label} document has no "spdxVersion" — not an SPDX 2.x document.`,
  );
}

function unsupported(code: string, reason: string): Detection {
  return { format: 'unsupported', code, reason };
}
