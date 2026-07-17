/**
 * Product flavor seam: one codebase ships two branded products — SBOM Lens
 * (SPDX-first) and OCM Lens (delivery-first). The flavor derives from the
 * Vite mode at build time, so the unused branch minifies away. Every
 * product-specific string, pref key, and asset choice lives here; nothing
 * else in the app may hardcode a product name.
 */

export type Flavor = 'sbom' | 'ocm';

const MODE = import.meta.env.MODE;

export const IS_VSCODE = MODE === 'vscode' || MODE === 'vscode-ocm';
export const FLAVOR: Flavor = MODE === 'ocm' || MODE === 'vscode-ocm' ? 'ocm' : 'sbom';

/**
 * Build-time capability, not a runtime setting: OCM component descriptors and
 * delivery archives belong to OCM Lens. SBOM Lens is an SPDX viewer — every
 * `HAS_DELIVERIES` branch folds to `false` there, so the descriptor mapper,
 * the tar reader, and gzip never enter its bundle (a CI gate proves it).
 * Keep the constant, not `BRAND.something`: a plain boolean is what the
 * bundler can fold.
 */
export const HAS_DELIVERIES = FLAVOR === 'ocm';

interface Branding {
  /** Full product name, e.g. "SBOM Lens". */
  name: string;
  /** Topbar rendering: plain prefix + accent-colored suffix. */
  namePrefix: string;
  nameAccent: string;
  /** One-liner for the help-dialog footer. */
  tagline: string;
  /** Empty-state paragraph under the product name. */
  emptyStateHint: string;
  /** Empty-state small print about supported inputs. */
  formatsNote: string;
  /** Heading over catalog sources when the catalog has no own title. */
  catalogHeading: string;
  /** Full-window drop-overlay label. */
  dropHint: string;
  /** Label above the URL input in the Open-from-URL dialog. */
  urlDialogLabel: string;
  changelogUrl: string;
  /**
   * Pref/secret key namespace. SBOM Lens keeps the historical `sbomlens.`
   * keys (no migration); OCM Lens starts fresh on `ocmlens.` so both
   * extensions/PWAs can coexist without sharing state.
   */
  prefPrefix: string;
  /** Same-origin deployment-catalog filename. */
  catalogPath: string;
  /** Files loaded by the "Load example" button (relative to base). */
  exampleFiles: readonly string[];
}

const SBOM: Branding = {
  name: 'SBOM Lens',
  namePrefix: 'SBOM',
  nameAccent: 'Lens',
  tagline: 'a fast, minimal viewer for SPDX SBOMs',
  emptyStateHint:
    'Drop SPDX files or folders anywhere in this window: cascading documents ' +
    'link up automatically.',
  formatsNote: 'Supports SPDX 2.x as tag-value (.spdx), JSON, and YAML.',
  catalogHeading: 'Preconfigured SBOMs',
  dropHint: 'Drop SPDX files or folders',
  urlDialogLabel: 'URL of an SPDX document',
  changelogUrl: 'https://gitlab.com/everbrightit-group/sbom-lens/-/blob/main/CHANGELOG.md',
  prefPrefix: 'sbomlens.',
  catalogPath: 'sbomlens.catalog.json',
  exampleFiles: [
    'examples/acme-platform-1.0.spdx',
    'examples/acme-webstack-2.1.spdx.json',
    'examples/acme-runtime-image-3.0.spdx',
    'examples/acme-advisories.openvex.json',
    'examples/acme-advisories.csaf.json',
  ],
};

const OCM: Branding = {
  name: 'OCM Lens',
  namePrefix: 'OCM',
  nameAccent: 'Lens',
  tagline: 'a fast, minimal viewer for OCM component versions and deliveries',
  emptyStateHint:
    'Drop OCM component descriptors or deliveries (CTF / component archives) anywhere in ' +
    'this window: components, references, and embedded SBOMs link up automatically.',
  formatsNote:
    'Supports OCM component descriptors (YAML/JSON) and CTF / component archives ' +
    '(.ctf, .tar, .tgz), plus SPDX 2.x for the SBOMs they carry.',
  catalogHeading: 'Preconfigured deliveries',
  dropHint: 'Drop OCM deliveries or component descriptors',
  urlDialogLabel: 'URL of a component descriptor or delivery',
  changelogUrl: 'https://gitlab.com/everbrightit-group/sbom-lens/-/blob/main/CHANGELOG.md',
  prefPrefix: 'ocmlens.',
  catalogPath: 'ocmlens.catalog.json',
  exampleFiles: ['examples/ocm/acme-delivery.ctf.tar'],
};

export const BRAND: Branding = FLAVOR === 'ocm' ? OCM : SBOM;

/** Namespaced pref/secret key: pref('theme') → "sbomlens.theme" / "ocmlens.theme". */
export function pref(name: string): string {
  return BRAND.prefPrefix + name;
}
