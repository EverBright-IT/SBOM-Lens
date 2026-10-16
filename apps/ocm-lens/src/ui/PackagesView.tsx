import { useEffect, useMemo, useRef, useState } from 'react';
import clsx from 'clsx';
import { useVirtualizer } from '@tanstack/react-virtual';
import type { VexDocument, VexFinding, VexStatus } from '@sbomlens/core';
import { worstVexStatus } from '@sbomlens/core';
import type {
  DeliveryPackage,
  DeliveryPackages,
  DeliveryVex,
  OcmBundle,
  PackageFilter,
  PackagePlace,
  PackageSearch,
  SbomCoverageRow,
  VexSource,
} from '@sbomlens/core/ocm';
import {
  deliveryConflicts,
  deliveryLicenses,
  findVulnerabilities,
  NOT_LISTED_LABEL,
  packagesToCsv,
  packagesToJson,
  placeBinding,
  placeLabel,
  searchAnswer,
  searchPackages,
  tr03191Summary,
  VEX_STATUS_LABEL,
} from '@sbomlens/core/ocm';
import { saveBytes } from '../app/download';
import { useSbomEvidence } from '../app/evidence';
import { addVexFiles, loadSbomPackages, loadVexSources, runSbomAnalysis } from '../app/ingest';
import { useDeliveryPackages, useDeliveryVex } from '../app/packages';
import type { PackageTab } from '../app/store';
import { useAppStore } from '../app/store';
import { APP_VERSION } from '../version';
import type { ChipTone } from './bits';
import { BUTTON_SECONDARY, Chip, KV, Section } from './bits';
import { artifactAt } from './sbomBits';

/**
 * "What ships, where, and is X in it?" Every package the delivery's SBOMs
 * list, once per identity and version, with the artifact it ships in and
 * how firmly its SBOM is tied to that artifact. Search takes a name, a purl
 * or a CPE; every answer also says which artifacts it could not look into.
 * Licenses are counted, not judged; versions that differ between artifacts
 * get their own tab, and so does what the supplier states about known
 * vulnerabilities (VEX and CSAF, read offline).
 */

const ROW_HEIGHT = 30;

const PACKAGE_GRID =
  'grid-cols-[minmax(9rem,2fr)_minmax(5rem,1fr)_5.5rem_minmax(6rem,1.2fr)_minmax(10rem,2.2fr)]';
// With VEX the status sits right after the version: it is what the reader
// came for, and narrow panes cut the table from the right.
const PACKAGE_GRID_VEX =
  'grid-cols-[minmax(8rem,2fr)_minmax(4.5rem,1fr)_8rem_4.5rem_minmax(5rem,1fr)_minmax(9rem,2fr)]';

const VEX_TONE: Record<VexStatus, ChipTone> = {
  affected: 'danger',
  under_investigation: 'warn',
  fixed: 'ok',
  not_affected: 'neutral',
};

function VexChip({ status, title, count }: { status: VexStatus; title?: string; count?: number }) {
  return (
    <Chip tone={VEX_TONE[status]} {...(title ? { title } : {})}>
      {count !== undefined ? `${count} ` : ''}
      {VEX_STATUS_LABEL[status]}
    </Chip>
  );
}

/** The worst status the supplier states for a package, with the vulnerabilities as a tooltip. */
function VexCell({ findings }: { findings: readonly VexFinding[] | undefined }) {
  const worst = worstVexStatus(findings);
  if (!worst || !findings) return <span className="text-xs text-slate-400">-</span>;
  return (
    <span className="flex min-w-0 items-center gap-1 overflow-hidden">
      <VexChip
        status={worst}
        title={findings.map((f) => `${f.vulnerability}: ${VEX_STATUS_LABEL[f.status]}`).join('\n')}
      />
      {findings.length > 1 && <span className="text-xs text-slate-400">{findings.length}</span>}
    </span>
  );
}

const STRENGTH_TONE: Record<PackagePlace['strength'], ChipTone> = {
  digest: 'ok',
  reference: 'accent',
  component: 'neutral',
  none: 'warn',
};

const STRENGTH_TITLE: Record<PackagePlace['strength'], string> = {
  digest: 'Its SBOM names a digest of this artifact',
  reference: 'Its SBOM names the same repository and tag, no shared digest',
  component: 'Its SBOM names the component version, not one artifact',
  none: 'Its SBOM describes nothing found in this delivery',
};

export function PackagesView() {
  const delivery = useAppStore((s) => s.delivery);
  const analyses = useAppStore((s) => s.delivery?.sbomAnalyses);
  const filter = useAppStore((s) => s.packageFilter);
  const tab = useAppStore((s) => s.packageTab);
  const setFilter = useAppStore((s) => s.actions.setPackageFilter);
  const setTab = useAppStore((s) => s.actions.setPackageTab);
  const sbomRun = useAppStore((s) => s.sbomRun);
  const packageRun = useAppStore((s) => s.packageRun);
  const packageError = useAppStore((s) => s.packageError);
  const evidence = useSbomEvidence();
  const model = useDeliveryPackages();
  const vex = useDeliveryVex(model);
  const vexSources = useAppStore((s) => s.delivery?.vexSources);
  const extracted = useAppStore((s) => s.delivery?.extracted);
  const vexLoading = useAppStore((s) => s.vexLoading);
  const vexError = useAppStore((s) => s.vexError);
  const [selected, setSelected] = useState<string | null>(null);

  // The delivery's own VEX documents are read when the view opens.
  useEffect(() => {
    if (extracted) void loadVexSources();
  }, [extracted]);

  // Package lists are read on first need, and again when "Analyse now"
  // brings more analysed SBOMs.
  useEffect(() => {
    if (analyses) void loadSbomPackages();
  }, [analyses]);

  // A status filter needs read VEX documents: once none is left (the last
  // added file removed), it no longer applies, so it must not narrow the
  // answer or describe the export either.
  const applied = useMemo(() => {
    if (filter.vex === undefined || (vex !== null && vex.documents.length > 0)) return filter;
    const rest: PackageFilter = { ...filter };
    delete rest.vex;
    return rest;
  }, [filter, vex]);

  // Search stays synchronous: a few milliseconds even for large deliveries,
  // and the answer box must never pair a new question with an old result.
  const search = useMemo(
    () => (model ? searchPackages(model, applied, vex ?? undefined) : null),
    [model, applied, vex],
  );
  const licenses = useMemo(() => (model ? deliveryLicenses(model) : null), [model]);
  const conflicts = useMemo(() => (model ? deliveryConflicts(model) : []), [model]);

  if (!delivery || !evidence || !model || !search || !licenses) return null;
  const { bundle } = delivery;
  const across = conflicts.filter((c) => c.acrossPlaces).length;
  const selectedPackage = selected ? model.packages.find((p) => p.id === selected) : undefined;

  const exportRows = (format: 'csv' | 'json') => {
    const base = bundle.fileName.replace(/(\.(ctf|tar|tgz|gz|yaml|yml|json))+$/i, '');
    if (format === 'csv') {
      saveBytes(
        `${base}.packages.csv`,
        'text/csv',
        packagesToCsv(bundle, search.rows, vex ?? undefined),
      );
    } else {
      const active = Object.fromEntries(Object.entries(applied).filter(([, v]) => v !== undefined));
      saveBytes(
        `${base}.packages.json`,
        'application/json',
        packagesToJson(
          bundle,
          model,
          search.rows,
          { generatedAt: new Date().toISOString(), toolVersion: APP_VERSION, filter: active },
          vex ?? undefined,
        ),
      );
    }
  };

  const tabs: { id: PackageTab; label: string }[] = [
    { id: 'packages', label: `All packages (${model.packages.length})` },
    { id: 'licenses', label: `Licenses (${licenses.rows.length})` },
    { id: 'versions', label: `Versions (${across})` },
    { id: 'vulnerabilities', label: `Vulnerabilities (${vex?.vulnerabilities.length ?? 0})` },
  ];

  return (
    <div className="flex h-full min-h-0">
      <div className="flex min-w-0 flex-1 flex-col p-4">
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <h1 className="text-lg font-semibold">Packages</h1>
          <Chip tone="accent">
            {model.packages.length} package{model.packages.length === 1 ? '' : 's'} from{' '}
            {model.sources.length} SBOM
            {model.sources.length === 1 ? '' : 's'}
          </Chip>
          {model.ecosystems.length > 0 && <Chip>{model.ecosystems.length} ecosystem(s)</Chip>}
          {across > 0 && (
            <Chip title="Packages that ship in different versions in different artifacts (see Versions)">
              {across} differ between artifacts
            </Chip>
          )}
          <span className={clsx('ml-auto flex gap-2', tab !== 'packages' && 'invisible')}>
            <button
              type="button"
              onClick={() => exportRows('csv')}
              disabled={search.rows.length === 0}
              className={BUTTON_SECONDARY}
              title="The packages shown below, one line per package and artifact"
            >
              Export CSV ({search.rows.length})
            </button>
            <button
              type="button"
              onClick={() => exportRows('json')}
              disabled={search.rows.length === 0}
              className={BUTTON_SECONDARY}
              title="The packages shown below with every artifact, plus what the list does not cover"
            >
              JSON
            </button>
          </span>
        </div>

        <StatusBanners
          deferred={evidence.counts.deferred}
          sbomRun={sbomRun}
          packageRun={packageRun}
          packageError={packageError}
        />

        <nav className="mb-3 flex gap-0.5 self-start rounded border border-slate-200 p-0.5 dark:border-slate-700">
          {tabs.map((t) => (
            <button
              key={t.id}
              type="button"
              onClick={() => setTab(t.id)}
              className={clsx(
                'rounded px-2 py-0.5 text-xs',
                tab === t.id
                  ? 'bg-accent-600 text-white'
                  : 'text-slate-500 hover:text-accent-700 dark:text-slate-400 dark:hover:text-accent-400',
              )}
            >
              {t.label}
            </button>
          ))}
        </nav>

        {tab === 'packages' && (
          <PackagesTab
            model={model}
            bundle={bundle}
            filter={applied}
            search={search}
            licenseIds={licenses.rows.map((r) => r.id)}
            vex={vex}
            selected={selected}
            onSelect={setSelected}
            onFilter={setFilter}
          />
        )}
        {tab === 'licenses' && (
          <LicensesTab
            licenses={licenses}
            bundle={bundle}
            onPick={(licenseId) => {
              setFilter({ licenseId });
              setTab('packages');
            }}
          />
        )}
        {tab === 'vulnerabilities' && (
          <VulnerabilitiesTab
            vex={vex}
            model={model}
            bundle={bundle}
            sources={vexSources ?? []}
            loading={vexLoading}
            error={vexError}
            onPackage={(pkg) => {
              setFilter({ text: pkg.purl ?? pkg.name });
              setTab('packages');
              setSelected(pkg.id);
            }}
            onPlace={(place) => {
              setFilter({ place: place.key });
              setTab('packages');
            }}
          />
        )}
        {tab === 'versions' && (
          <VersionsTab
            conflicts={conflicts}
            bundle={bundle}
            onShow={(text) => {
              setFilter({ text });
              setTab('packages');
            }}
          />
        )}
      </div>

      {selectedPackage && tab === 'packages' && (
        <aside className="w-96 shrink-0 overflow-auto border-l border-slate-200 p-3 dark:border-slate-800">
          <PackageDetail
            pkg={selectedPackage}
            model={model}
            bundle={bundle}
            findings={vex?.byPackage.get(selectedPackage)}
            onSelect={setSelected}
            onClose={() => setSelected(null)}
          />
        </aside>
      )}
    </div>
  );
}

function StatusBanners({
  deferred,
  sbomRun,
  packageRun,
  packageError,
}: {
  deferred: number;
  sbomRun: { done: number; total: number } | null;
  packageRun: { done: number; total: number } | null;
  packageError: string | null;
}) {
  return (
    <>
      {sbomRun && (
        <div className="mb-3 rounded border border-slate-200 px-2.5 py-1.5 text-sm text-slate-600 dark:border-slate-700 dark:text-slate-300">
          Analysing SBOMs... {sbomRun.done} of {sbomRun.total}; their packages follow.
        </div>
      )}
      {packageRun && (
        <div className="mb-3 rounded border border-slate-200 px-2.5 py-1.5 text-sm text-slate-600 dark:border-slate-700 dark:text-slate-300">
          Reading packages... {packageRun.done} of {packageRun.total} SBOMs
        </div>
      )}
      {!sbomRun && deferred > 0 && (
        <div className="mb-3 flex items-center gap-2 rounded border border-amber-300 bg-amber-50 px-2.5 py-1.5 text-sm dark:border-amber-800 dark:bg-amber-950">
          <span>
            {deferred} SBOM{deferred === 1 ? ' is' : 's are'} not analysed yet (beyond the load-time
            size budget):
            {deferred === 1 ? ' its' : ' their'} packages are missing from this list.
          </span>
          <button
            type="button"
            onClick={() => void runSbomAnalysis()}
            className={clsx(BUTTON_SECONDARY, 'ml-auto')}
          >
            Analyse now
          </button>
        </div>
      )}
      {packageError && !packageRun && (
        <p className="mb-3 text-xs text-red-600 dark:text-red-400">
          Reading the packages stopped: {packageError}. Open the view again to retry.
        </p>
      )}
    </>
  );
}

function PlaceChip({
  place,
  bundle,
  onClick,
}: {
  place: PackagePlace;
  bundle: OcmBundle;
  onClick?: (place: PackagePlace) => void;
}) {
  const notes = place.notes.includes('digest-differs') ? ', digest differs' : '';
  const chip = (
    <Chip
      tone={STRENGTH_TONE[place.strength]}
      title={`${STRENGTH_TITLE[place.strength]}${notes} (${place.cvId})`}
    >
      {placeLabel(bundle, place)}
    </Chip>
  );
  if (!onClick) return chip;
  return (
    <button
      type="button"
      onClick={(e) => {
        e.stopPropagation();
        onClick(place);
      }}
      className="hover:opacity-80"
    >
      {chip}
    </button>
  );
}

function FilterSelect({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string | undefined;
  options: { value: string; label: string }[];
  onChange: (value: string | undefined) => void;
}) {
  return (
    <label className="flex items-center gap-1 text-xs text-slate-500 dark:text-slate-400">
      {label}
      <select
        value={value ?? '\u0000'}
        onChange={(e) => onChange(e.target.value === '\u0000' ? undefined : e.target.value)}
        className="max-w-48 rounded border border-slate-200 bg-transparent px-1 py-0.5 text-xs dark:border-slate-700 dark:bg-slate-900"
      >
        <option value={'\u0000'}>all</option>
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </label>
  );
}

function PackagesTab({
  model,
  bundle,
  filter,
  search,
  licenseIds,
  vex,
  selected,
  onSelect,
  onFilter,
}: {
  model: DeliveryPackages;
  bundle: OcmBundle;
  filter: PackageFilter;
  search: PackageSearch;
  licenseIds: string[];
  vex: DeliveryVex | null;
  selected: string | null;
  onSelect: (id: string) => void;
  onFilter: (filter: PackageFilter) => void;
}) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const rows = search.rows;
  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 20,
  });
  const set = (patch: Partial<PackageFilter>) => {
    const next: PackageFilter = { ...filter, ...patch };
    for (const key of Object.keys(next) as (keyof PackageFilter)[])
      if (next[key] === undefined) delete next[key];
    onFilter(next);
  };
  const byPlace = (place: PackagePlace) => set({ place: place.key });
  // With VEX documents loaded the table gains a column for the supplier's statements.
  const withVex = vex !== null && vex.documents.length > 0;
  const grid = withVex ? PACKAGE_GRID_VEX : PACKAGE_GRID;
  const sbomSource =
    filter.sbom !== undefined ? model.sources.find((s) => s.sha1 === filter.sbom) : undefined;
  const text = filter.text?.trim() ?? '';

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <input
          value={filter.text ?? ''}
          onChange={(e) => set({ text: e.target.value === '' ? undefined : e.target.value })}
          placeholder="Name, or a purl or CPE: pkg:deb/debian/openssl, cpe:2.3:a:..."
          className="w-96 max-w-full rounded border border-slate-200 bg-transparent px-2 py-1 text-sm outline-none focus:border-accent-400 dark:border-slate-700"
        />
        <FilterSelect
          label="Ecosystem"
          value={filter.ecosystem}
          options={model.ecosystems.map((e) => ({
            value: e.ecosystem ?? '',
            label: `${e.ecosystem ?? 'without purl'} (${e.packages})`,
          }))}
          onChange={(ecosystem) => set({ ecosystem })}
        />
        <FilterSelect
          label="Ships in"
          value={filter.place}
          options={model.places.map((p) => ({
            value: p.place.key,
            label: `${placeLabel(bundle, p.place)} (${p.packages})`,
          }))}
          onChange={(place) => set({ place })}
        />
        <FilterSelect
          label="License"
          value={filter.licenseId}
          options={[
            ...licenseIds.map((id) => ({ value: id, label: id })),
            { value: '', label: 'without a license' },
          ]}
          onChange={(licenseId) => set({ licenseId })}
        />
        {withVex && (
          <FilterSelect
            label="VEX"
            value={filter.vex}
            options={[
              ...(['affected', 'under_investigation', 'fixed', 'not_affected'] as const).map(
                (status) => ({
                  value: status,
                  label: `${VEX_STATUS_LABEL[status]} (${vex.counts[status]})`,
                }),
              ),
              {
                value: 'none',
                label: `no statement (${vex.counts.without + vex.counts.unmatchable})`,
              },
            ]}
            onChange={(value) => set({ vex: value as VexStatus | 'none' | undefined })}
          />
        )}
        {sbomSource && (
          <button
            type="button"
            onClick={() => set({ sbom: undefined })}
            className="rounded border border-accent-400 bg-accent-50 px-1.5 py-0.5 text-[11px] text-accent-700 dark:bg-accent-950 dark:text-accent-300"
            title="Remove this filter"
          >
            listed by {sbomSource.fileName.split('!').pop()} ✕
          </button>
        )}
        <span className="ml-auto text-xs text-slate-400">
          {rows.length} of {model.packages.length}
        </span>
      </div>

      {text !== '' && (
        <Answer model={model} bundle={bundle} filter={filter} search={search} onPlace={byPlace} />
      )}

      {model.sources.length === 0 ? (
        <NoLists model={model} bundle={bundle} />
      ) : (
        <div className="flex min-h-0 flex-1 flex-col overflow-hidden rounded-md border border-slate-200 dark:border-slate-800">
          <div
            className={clsx(
              'grid gap-2 bg-slate-50 px-3 py-1.5 text-xs font-medium text-slate-500 dark:bg-slate-900 dark:text-slate-400',
              grid,
            )}
          >
            <span>Package</span>
            <span>Version</span>
            {withVex && <span>VEX</span>}
            <span>Ecosystem</span>
            <span>License</span>
            <span>Ships in</span>
          </div>
          <div ref={scrollRef} className="min-h-0 flex-1 overflow-auto">
            <div className="relative" style={{ height: virtualizer.getTotalSize() }}>
              {virtualizer.getVirtualItems().map((item) => {
                const pkg = rows[item.index]!;
                return (
                  <div
                    key={pkg.id}
                    onClick={() => onSelect(pkg.id)}
                    className={clsx(
                      'absolute inset-x-0 grid cursor-pointer items-center gap-2 border-t border-slate-100 px-3 text-sm dark:border-slate-800/60',
                      grid,
                      selected === pkg.id
                        ? 'bg-accent-50 dark:bg-accent-950'
                        : 'hover:bg-slate-50 dark:hover:bg-slate-900',
                    )}
                    style={{ top: item.start, height: ROW_HEIGHT }}
                  >
                    <span className="flex min-w-0 items-center gap-1.5">
                      <span className="truncate font-medium" title={pkg.purl ?? pkg.name}>
                        {pkg.name}
                      </span>
                      {pkg.subject && <SubjectChip />}
                    </span>
                    <span
                      className="truncate font-mono text-xs text-slate-500 dark:text-slate-400"
                      title={pkg.version}
                    >
                      {pkg.version ?? '-'}
                    </span>
                    {withVex && <VexCell findings={vex.byPackage.get(pkg)} />}
                    <span className="truncate text-xs text-slate-500 dark:text-slate-400">
                      {pkg.ecosystem ?? '-'}
                    </span>
                    <LicenseCell pkg={pkg} />
                    <span className="flex min-w-0 items-center gap-1 overflow-hidden">
                      {pkg.places.slice(0, 2).map((place) => (
                        <PlaceChip
                          key={place.key}
                          place={place}
                          bundle={bundle}
                          onClick={byPlace}
                        />
                      ))}
                      {pkg.places.length > 2 && (
                        <span className="text-xs text-slate-400">+{pkg.places.length - 2}</span>
                      )}
                    </span>
                  </div>
                );
              })}
            </div>
            {rows.length === 0 && (
              <p className="px-3 py-4 text-center text-xs text-slate-400">
                {text !== '' ? 'No package matches.' : 'Nothing matches the filter.'}
              </p>
            )}
          </div>
        </div>
      )}
      <p className="mt-2 text-xs text-slate-400">
        Each package once per identity and version, the SBOMs' subjects (the images and products
        they describe) included and marked.
        {model.omitted.files > 0 ? ` Not listed: ${model.omitted.files} file entries.` : ''}
      </p>
    </div>
  );
}

function LicenseCell({ pkg }: { pkg: DeliveryPackage }) {
  if (pkg.licenses.length === 0) return <span className="text-xs text-slate-400">-</span>;
  const text = pkg.licenses.join('; ');
  return (
    <span
      className={clsx(
        'truncate text-xs',
        pkg.licensesUnparsed.length > 0
          ? 'text-amber-700 dark:text-amber-400'
          : 'text-slate-600 dark:text-slate-300',
      )}
      title={pkg.licensesUnparsed.length > 0 ? `${text} (not an SPDX expression)` : text}
    >
      {text}
    </span>
  );
}

/** "Is it in this delivery, and where?", with what could not be searched. */
function SubjectChip() {
  return (
    <Chip title="The image or product an SBOM describes: it ships too, so it is listed and searched">
      SBOM subject
    </Chip>
  );
}

/** "Is it in this delivery, and where?", with everything that qualifies the answer. */
function Answer({
  model,
  bundle,
  filter,
  search,
  onPlace,
}: {
  model: DeliveryPackages;
  bundle: OcmBundle;
  filter: PackageFilter;
  search: PackageSearch;
  onPlace: (place: PackagePlace) => void;
}) {
  const answer = useMemo(() => searchAnswer(model, filter, search), [model, filter, search]);
  const where = (rows: SbomCoverageRow[]) =>
    rows
      .map((row) => {
        const cv = bundle.componentVersions.find((c) => c.id === row.artifact.cvId);
        const short = cv ? (cv.name.split('/').pop() ?? cv.name) : row.artifact.cvId;
        return `${short} · ${artifactAt(bundle, row.artifact)?.name ?? '?'}`;
      })
      .join('; ');

  return (
    <div className="mb-3 rounded border border-slate-200 px-2.5 py-2 text-sm dark:border-slate-700">
      {answer.found > 0 ? (
        <>
          <p className="mb-1">
            {answer.identifier ? 'Matched by identity: ' : ''}
            {answer.found} package{answer.found === 1 ? '' : 's'} in {answer.places.length} place
            {answer.places.length === 1 ? '' : 's'}:
          </p>
          <ul className="mb-1 space-y-0.5">
            {answer.places.slice(0, 12).map((group) => (
              <li key={group.place.key} className="flex flex-wrap items-center gap-1.5">
                <PlaceChip place={group.place} bundle={bundle} onClick={onPlace} />
                <span className="text-xs text-slate-600 dark:text-slate-300">
                  {group.packages
                    .slice(0, 6)
                    .map((p) => `${p.name} ${p.version ?? ''}`.trim())
                    .join(', ')}
                  {group.packages.length > 6 ? `, and ${group.packages.length - 6} more` : ''}
                </span>
              </li>
            ))}
            {answer.places.length > 12 && (
              <li className="text-xs text-slate-400">
                and {answer.places.length - 12} more places
              </li>
            )}
          </ul>
        </>
      ) : (
        <p className="mb-1">
          Not found in the packages of the {model.sources.length} analysed SBOM
          {model.sources.length === 1 ? '' : 's'}
          {answer.narrowed ? ', within the filters' : ''}.
        </p>
      )}
      {answer.narrowed && (
        <p className="text-xs text-slate-500 dark:text-slate-400">
          A filter limits this search to part of the delivery.
        </p>
      )}
      {answer.notSearched.length > 0 && (
        <p className="text-xs text-amber-700 dark:text-amber-400">
          Not searched, because their packages are not in the list:{' '}
          {answer.notSearched
            .map(({ row, reason }) => `${where([row])} (${NOT_LISTED_LABEL[reason]})`)
            .join('; ')}
          .
        </p>
      )}
      {answer.unverified.length > 0 && (
        <p className="text-xs text-amber-700 dark:text-amber-400">
          Searched only through an SBOM that does not identify them: {where(answer.unverified)}.
        </p>
      )}
      {answer.digestDiffers.length > 0 && (
        <p className="text-xs text-amber-700 dark:text-amber-400">
          Searched through an SBOM that states a different digest, so it may describe a local build
          rather than the delivered bytes: {where(answer.digestDiffers)}.
        </p>
      )}
      {answer.everyArtifactSearched && (
        <p className="text-xs text-slate-500 dark:text-slate-400">
          Every artifact that ships software was searched through an SBOM bound to it.
        </p>
      )}
      {answer.withoutIdentifier > 0 && (
        <p className="text-xs text-slate-500 dark:text-slate-400">
          {answer.withoutIdentifier} package{answer.withoutIdentifier === 1 ? ' states' : 's state'}{' '}
          no {answer.identifier === 'purl' ? 'purl' : 'CPE'} and can only be found by name.
        </p>
      )}
    </div>
  );
}

function NoLists({ model, bundle }: { model: DeliveryPackages; bundle: OcmBundle }) {
  return (
    <div className="rounded border border-slate-200 px-3 py-4 text-sm text-slate-600 dark:border-slate-700 dark:text-slate-300">
      <p>No package list: this delivery carries no analysed SBOM yet.</p>
      {model.scope.notListed.length > 0 && (
        <ul className="mt-2 space-y-0.5 text-xs text-slate-500 dark:text-slate-400">
          {model.scope.notListed.map(({ row, reason }) => (
            <li key={`${row.artifact.cvId}#${row.artifact.index}`}>
              {row.artifact.cvId} · {artifactAt(bundle, row.artifact)?.name}:{' '}
              {NOT_LISTED_LABEL[reason]}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

const LICENSE_GRID =
  'grid grid-cols-[minmax(10rem,2fr)_9rem_5.5rem_minmax(10rem,3fr)] items-center gap-2 px-3';

function LicensesTab({
  licenses,
  bundle,
  onPick,
}: {
  licenses: ReturnType<typeof deliveryLicenses>;
  bundle: OcmBundle;
  onPick: (licenseId: string) => void;
}) {
  const unparsed = licenses.unparsed.reduce((n, u) => n + u.packages, 0);
  // Real deliveries name hundreds of identifiers (syft writes a LicenseRef
  // per unrecognized license text): the list is virtualized like the
  // package table. The last row stands for packages without a license.
  const count = licenses.rows.length + (licenses.withoutLicense > 0 ? 1 : 0);
  const scrollRef = useRef<HTMLDivElement>(null);
  const virtualizer = useVirtualizer({
    count,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 20,
  });
  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="mb-3 flex flex-wrap gap-2">
        <Chip tone="accent">{licenses.rows.length} identifier(s)</Chip>
        {licenses.kinds.deprecated > 0 && (
          <Chip tone="warn" title="On the SPDX License List but deprecated there">
            {licenses.kinds.deprecated} deprecated
          </Chip>
        )}
        {licenses.kinds.ref > 0 && (
          <Chip title="LicenseRef-...: defined by the SBOM author">
            {licenses.kinds.ref} LicenseRef
          </Chip>
        )}
        {licenses.kinds.unknown > 0 && (
          <Chip tone="warn" title="Not on the SPDX License List">
            {licenses.kinds.unknown} not on the list
          </Chip>
        )}
        <Chip
          tone={licenses.withoutLicense > licenses.subjectsWithoutLicense ? 'warn' : 'neutral'}
          title="Missing, NONE or NOASSERTION in every SBOM that lists the package"
        >
          {licenses.withoutLicense} package(s) without a license
          {licenses.subjectsWithoutLicense > 0
            ? ` (${licenses.subjectsWithoutLicense} of them SBOM subjects)`
            : ''}
        </Chip>
        {unparsed > 0 && (
          <Chip tone="warn" title="A license name or text where an SPDX expression belongs">
            {unparsed} not an SPDX expression
          </Chip>
        )}
      </div>
      <p className="mb-3 max-w-3xl text-xs text-slate-500 dark:text-slate-400">
        A package's license is the concluded one, else the declared one, as its SBOMs state it.
        Identifiers are checked against the SPDX License List and counted; what a license obliges,
        or whether two fit together, is not judged here.
      </p>
      {licenses.unparsed.length > 0 && (
        <details className="mb-3 text-xs">
          <summary className="cursor-pointer text-slate-500 dark:text-slate-400">
            Values that are not SPDX expressions ({licenses.unparsed.length})
          </summary>
          <ul className="mt-1 max-h-40 space-y-0.5 overflow-auto text-slate-600 dark:text-slate-300">
            {licenses.unparsed.map((u) => (
              <li key={u.value}>
                <span className="font-mono">{u.value}</span>
                <span className="ml-2 text-slate-400">{u.packages} package(s)</span>
              </li>
            ))}
          </ul>
        </details>
      )}
      {count === 0 ? (
        <p className="text-sm text-slate-500 dark:text-slate-400">No packages.</p>
      ) : (
        <div className="flex min-h-0 flex-1 flex-col overflow-hidden rounded-md border border-slate-200 dark:border-slate-800">
          <div
            className={clsx(
              LICENSE_GRID,
              'bg-slate-50 py-1.5 text-xs font-medium text-slate-500 dark:bg-slate-900 dark:text-slate-400',
            )}
          >
            <span>Identifier</span>
            <span>Status</span>
            <span>Packages</span>
            <span>Ships in</span>
          </div>
          <div ref={scrollRef} className="min-h-0 flex-1 overflow-auto">
            <div className="relative" style={{ height: virtualizer.getTotalSize() }}>
              {virtualizer.getVirtualItems().map((item) => {
                const row = licenses.rows[item.index];
                const rowClass = clsx(
                  LICENSE_GRID,
                  'absolute inset-x-0 cursor-pointer border-t border-slate-100 text-sm hover:bg-slate-50 dark:border-slate-800/60 dark:hover:bg-slate-900',
                );
                if (!row) {
                  return (
                    <div
                      key="without-license"
                      onClick={() => onPick('')}
                      className={rowClass}
                      style={{ top: item.start, height: ROW_HEIGHT }}
                      title="Show these packages"
                    >
                      <span className="text-xs text-slate-500 italic dark:text-slate-400">
                        without a license
                      </span>
                      <span className="truncate text-xs text-slate-500 dark:text-slate-400">
                        missing, NONE or NOASSERTION
                      </span>
                      <span className="text-slate-500 dark:text-slate-400">
                        {licenses.withoutLicense}
                      </span>
                      <span />
                    </div>
                  );
                }
                return (
                  <div
                    key={row.id}
                    onClick={() => onPick(row.id)}
                    className={rowClass}
                    style={{ top: item.start, height: ROW_HEIGHT }}
                    title="Show these packages"
                  >
                    <span className="truncate font-mono text-xs" title={row.id}>
                      {row.id}
                    </span>
                    <span className="truncate text-xs text-slate-500 dark:text-slate-400">
                      {KIND_LABEL[row.kind]}
                    </span>
                    <span className="text-slate-500 dark:text-slate-400">{row.packages}</span>
                    <span className="flex min-w-0 items-center gap-1 overflow-hidden">
                      {row.places.slice(0, 3).map((place) => (
                        <PlaceChip key={place.key} place={place} bundle={bundle} />
                      ))}
                      {row.places.length > 3 && (
                        <span className="text-xs text-slate-400">+{row.places.length - 3}</span>
                      )}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

const KIND_LABEL = {
  listed: 'SPDX License List',
  deprecated: 'deprecated',
  ref: 'LicenseRef',
  unknown: 'not on the list',
} as const;

function VersionsTab({
  conflicts,
  bundle,
  onShow,
}: {
  conflicts: ReturnType<typeof deliveryConflicts>;
  bundle: OcmBundle;
  onShow: (text: string) => void;
}) {
  const [within, setWithin] = useState(false);
  const across = conflicts.filter((c) => c.acrossPlaces);
  const shown = within ? conflicts : across;
  return (
    <div className="min-h-0 flex-1 overflow-auto">
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <p className="max-w-3xl text-xs text-slate-500 dark:text-slate-400">
          Packages the delivery ships in more than one version. Versions that differ between
          artifacts come first: one image carrying two versions of a library is common, two images
          disagreeing about it is worth a look.
        </p>
        {conflicts.length > across.length && (
          <label className="ml-auto flex items-center gap-1 text-xs text-slate-500 dark:text-slate-400">
            <input type="checkbox" checked={within} onChange={(e) => setWithin(e.target.checked)} />
            also inside one artifact ({conflicts.length - across.length})
          </label>
        )}
      </div>
      {shown.length === 0 ? (
        <p className="text-sm text-slate-500 dark:text-slate-400">
          {conflicts.length === 0
            ? 'Every package ships in one version.'
            : 'No package differs in version between artifacts.'}
        </p>
      ) : (
        <ul className="space-y-2">
          {shown.slice(0, 500).map((conflict) => {
            const identity = conflict.key.startsWith('purl:')
              ? conflict.key.slice('purl:'.length)
              : conflict.name;
            return (
              <li
                key={conflict.key}
                className="rounded border border-slate-200 px-2.5 py-1.5 dark:border-slate-800"
              >
                <div className="mb-1 flex items-center gap-2">
                  <span className="font-medium">{conflict.name}</span>
                  <span className="truncate font-mono text-xs text-slate-400">{identity}</span>
                  {!conflict.acrossPlaces && <Chip>inside one artifact</Chip>}
                  <button
                    type="button"
                    onClick={() => onShow(identity)}
                    className="ml-auto text-xs text-accent-700 hover:underline dark:text-accent-400"
                  >
                    Show packages
                  </button>
                </div>
                <ul className="space-y-0.5">
                  {conflict.versions.map((v) => (
                    <li key={v.version} className="flex flex-wrap items-center gap-1.5">
                      <span className="w-28 shrink-0 truncate font-mono text-xs" title={v.version}>
                        {v.version}
                      </span>
                      {v.package.places.map((place) => (
                        <PlaceChip key={place.key} place={place} bundle={bundle} />
                      ))}
                    </li>
                  ))}
                </ul>
              </li>
            );
          })}
        </ul>
      )}
      {shown.length > 500 && (
        <p className="mt-2 text-xs text-slate-400">and {shown.length - 500} more</p>
      )}
    </div>
  );
}

/** BSI TR-03191 on a CSAF document: how many applicable requirements hold. A measurement, not a verdict. */
function Tr03191Chip({ document }: { document: VexDocument }) {
  const tr = document.format === 'csaf' ? tr03191Summary(document) : undefined;
  if (!tr) return null;
  return (
    <Chip
      tone={tr.passed === tr.total ? 'ok' : 'neutral'}
      title={
        tr.open.length > 0 ? `Not met: ${tr.open.join('; ')}` : 'Every applicable requirement holds'
      }
    >
      BSI TR-03191 {tr.passed} of {tr.total}
    </Chip>
  );
}

const VEX_SOURCE_STATE: Record<VexSource['state'], { label: string; tone: ChipTone }> = {
  loaded: { label: 'read', tone: 'ok' },
  pending: { label: 'not read yet', tone: 'neutral' },
  external: { label: 'outside the delivery', tone: 'warn' },
  unreadable: { label: 'unreadable', tone: 'danger' },
};

/**
 * "What does the supplier say about this vulnerability?" The statements of
 * the delivery's VEX and CSAF documents (and of files the reader adds),
 * per vulnerability, with the packages and places they reach. A missing
 * statement is said to be one, never presented as an all-clear.
 */
function VulnerabilitiesTab({
  vex,
  model,
  bundle,
  sources,
  loading,
  error,
  onPackage,
  onPlace,
}: {
  vex: DeliveryVex | null;
  model: DeliveryPackages;
  bundle: OcmBundle;
  sources: readonly (VexSource & { key: string })[];
  loading: boolean;
  error: string | null;
  onPackage: (pkg: DeliveryPackage) => void;
  onPlace: (place: PackagePlace) => void;
}) {
  const [query, setQuery] = useState('');
  const fileInput = useRef<HTMLInputElement>(null);
  const removeVexEntry = useAppStore((s) => s.actions.removeVexEntry);
  const selectArtifact = useAppStore((s) => s.actions.selectArtifact);
  const rows = useMemo(() => (vex ? findVulnerabilities(vex, query) : []), [vex, query]);
  const documents = vex?.documents.length ?? 0;
  const where = (row: SbomCoverageRow) => {
    const cv = bundle.componentVersions.find((c) => c.id === row.artifact.cvId);
    return `${cv ? (cv.name.split('/').pop() ?? cv.name) : row.artifact.cvId} · ${artifactAt(bundle, row.artifact)?.name ?? '?'}`;
  };
  const notListed = model.scope.notListed;
  // Listed, but with neither a purl nor a CPE: no statement can name them.
  const unmatchable = vex?.counts.unmatchable ?? 0;
  const mayShip = [
    notListed.length > 0
      ? `in an artifact the list does not cover: ${notListed
          .map(({ row, reason }) => `${where(row)} (${NOT_LISTED_LABEL[reason]})`)
          .join('; ')}`
      : '',
    unmatchable > 0
      ? `as one of the ${unmatchable} listed package(s) without a purl or CPE, which no statement can name`
      : '',
  ].filter(Boolean);

  return (
    <div className="min-h-0 flex-1 overflow-auto">
      <div className="mb-3 flex flex-wrap items-center gap-2">
        {vex && documents > 0 ? (
          <>
            {(['affected', 'under_investigation', 'fixed', 'not_affected'] as const).map(
              (status) => (
                <VexChip
                  key={status}
                  status={status}
                  count={vex.counts[status]}
                  title="Packages with this as their worst stated status"
                />
              ),
            )}
            <Chip title="Packages no statement names, with or without a purl or CPE">
              {vex.counts.without + vex.counts.unmatchable} without a statement
            </Chip>
          </>
        ) : (
          <span className="text-sm text-slate-500 dark:text-slate-400">
            No VEX or CSAF document read for this delivery.
          </span>
        )}
        <button
          type="button"
          onClick={() => fileInput.current?.click()}
          className={clsx(BUTTON_SECONDARY, 'ml-auto')}
        >
          Add VEX or CSAF file...
        </button>
        <input
          ref={fileInput}
          type="file"
          multiple
          hidden
          accept=".json,application/json"
          onChange={(e) => {
            const files = [...(e.target.files ?? [])];
            if (files.length > 0) void addVexFiles(files);
            e.target.value = '';
          }}
        />
      </div>
      <p className="mb-3 max-w-3xl text-xs text-slate-500 dark:text-slate-400">
        What the supplier states about known vulnerabilities, from OpenVEX and CSAF documents in the
        delivery or added here, matched to the package list by purl, CPE and file hash. Read
        offline: nothing is looked up and nothing is scanned, so a package without a statement is
        not cleared.
      </p>
      {loading && <p className="mb-2 text-xs text-slate-500">Reading VEX documents...</p>}
      {error && !loading && (
        <p className="mb-2 text-xs text-red-600 dark:text-red-400">
          Reading the VEX documents stopped: {error}.
        </p>
      )}

      {sources.length > 0 && (
        <Section title={`Documents (${sources.length})`}>
          <ul className="space-y-1 text-sm">
            {sources.map((source) => {
              const state = VEX_SOURCE_STATE[source.state];
              return (
                <li key={source.key} className="flex flex-wrap items-center gap-2">
                  <span className="font-medium">
                    {source.state === 'loaded'
                      ? (source.document.title ?? source.document.id)
                      : source.name}
                  </span>
                  {source.state === 'loaded' && (
                    <Chip>{source.document.format === 'csaf' ? 'CSAF' : 'OpenVEX'}</Chip>
                  )}
                  {source.state === 'loaded' && <Tr03191Chip document={source.document} />}
                  <Chip
                    tone={state.tone}
                    title={source.state !== 'loaded' ? source.reason : undefined}
                  >
                    {state.label}
                  </Chip>
                  {source.state === 'loaded' && (
                    <span className="text-xs text-slate-400">
                      {source.document.statements.length} statement(s)
                      {source.document.author ? `, ${source.document.author}` : ''}
                    </span>
                  )}
                  {source.origin.kind === 'resource' ? (
                    <button
                      type="button"
                      onClick={() => {
                        if (source.origin.kind !== 'resource') return;
                        const { cvId, index } = source.origin.ref;
                        selectArtifact({ cvId, role: 'resource', index });
                      }}
                      className="font-mono text-xs text-slate-400 hover:text-accent-700 dark:hover:text-accent-400"
                    >
                      {source.origin.ref.cvId} · {source.name}
                    </button>
                  ) : (
                    <>
                      <span className="text-xs text-slate-400">added file</span>
                      <button
                        type="button"
                        onClick={() => removeVexEntry(source.key)}
                        className="text-xs text-accent-700 hover:underline dark:text-accent-400"
                      >
                        Remove
                      </button>
                    </>
                  )}
                  {source.state === 'unreadable' && source.reason && (
                    <span className="text-xs text-red-600 dark:text-red-400">{source.reason}</span>
                  )}
                </li>
              );
            })}
          </ul>
        </Section>
      )}

      {vex && documents > 0 && (
        <>
          <div className="mb-2 flex items-center gap-2">
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Vulnerability id or alias: CVE-..., GHSA-..."
              className="w-80 max-w-full rounded border border-slate-200 bg-transparent px-2 py-1 text-sm outline-none focus:border-accent-400 dark:border-slate-700"
            />
            <span className="ml-auto text-xs text-slate-400">
              {rows.length} of {vex.vulnerabilities.length} vulnerabilities
            </span>
          </div>
          {rows.length === 0 && query.trim() !== '' && (
            <p className="mb-3 rounded border border-slate-200 px-2.5 py-2 text-sm dark:border-slate-700">
              No statement about "{query.trim()}" in the {documents} document
              {documents === 1 ? '' : 's'}. A missing statement is not an all-clear: the supplier
              may not have said anything about it yet.
            </p>
          )}
          <ul className="space-y-2">
            {rows.slice(0, 500).map((v) => (
              <li
                key={v.id}
                className="rounded border border-slate-200 px-2.5 py-1.5 dark:border-slate-800"
              >
                <div className="mb-1 flex flex-wrap items-center gap-2">
                  <span className="font-mono text-sm font-medium">{v.id}</span>
                  <VexChip status={v.status} />
                  {v.aliases.length > 0 && (
                    <span className="truncate font-mono text-xs text-slate-400">
                      {v.aliases.join(', ')}
                    </span>
                  )}
                </div>
                {v.description && (
                  <p className="mb-1 text-xs text-slate-600 dark:text-slate-300">{v.description}</p>
                )}
                <ul className="space-y-0.5">
                  {v.packages.map(({ pkg, finding }) => (
                    <li key={pkg.id} className="flex flex-wrap items-center gap-1.5 text-xs">
                      <button
                        type="button"
                        onClick={() => onPackage(pkg)}
                        className="font-medium hover:text-accent-700 dark:hover:text-accent-400"
                      >
                        {pkg.name} {pkg.version ?? ''}
                      </button>
                      <VexChip status={finding.status} />
                      {pkg.places.map((place) => (
                        <PlaceChip
                          key={place.key}
                          place={place}
                          bundle={bundle}
                          onClick={onPlace}
                        />
                      ))}
                      {(finding.actionStatement ??
                        finding.impactStatement ??
                        finding.justification) && (
                        <span className="text-slate-500 dark:text-slate-400">
                          {finding.actionStatement ??
                            finding.impactStatement ??
                            finding.justification}
                        </span>
                      )}
                    </li>
                  ))}
                </ul>
                {v.unmatched.length > 0 && (
                  <p className="mt-1 text-xs text-amber-700 dark:text-amber-400">
                    {v.packages.length > 0 ? 'Also names' : 'Names'} no package in the list:{' '}
                    {[...new Set(v.unmatched.flatMap((u) => u.products))].slice(0, 5).join(', ')}.
                    {mayShip.length > 0 ? ` It may still ship ${mayShip.join(', or ')}.` : ''}
                  </p>
                )}
              </li>
            ))}
          </ul>
          {rows.length > 500 && (
            <p className="mt-2 text-xs text-slate-400">and {rows.length - 500} more</p>
          )}
        </>
      )}
    </div>
  );
}

function PackageDetail({
  pkg,
  model,
  bundle,
  findings,
  onSelect,
  onClose,
}: {
  pkg: DeliveryPackage;
  model: DeliveryPackages;
  bundle: OcmBundle;
  findings: readonly VexFinding[] | undefined;
  onSelect: (id: string) => void;
  onClose: () => void;
}) {
  const selectArtifact = useAppStore((s) => s.actions.selectArtifact);
  const selectCv = useAppStore((s) => s.actions.selectCv);
  const selectSbom = useAppStore((s) => s.actions.selectSbom);
  const cpes = [
    ...new Set(
      pkg.occurrences.flatMap(
        (o) =>
          o.element.externalRefs
            ?.filter((r) => r.locator.toLowerCase().startsWith('cpe:'))
            .map((r) => r.locator) ?? [],
      ),
    ),
  ];
  const others = model.packages.filter((p) => p.key === pkg.key && p.id !== pkg.id);
  const open = (place: PackagePlace) => {
    if (place.kind === 'component') selectCv(place.cvId);
    else if (place.ref && place.kind === 'artifact')
      selectArtifact({ cvId: place.ref.cvId, role: 'resource', index: place.ref.index });
    else if (place.ref)
      selectSbom({ cvId: place.ref.cvId, role: 'resource', index: place.ref.index });
  };

  return (
    <div>
      <div className="mb-2 flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="font-medium break-words">{pkg.name}</div>
          <div className="font-mono text-xs text-slate-400">{pkg.version ?? 'no version'}</div>
          {pkg.subject && (
            <div className="mt-1">
              <SubjectChip />
            </div>
          )}
        </div>
        <button type="button" onClick={onClose} className="text-slate-400" aria-label="Close">
          ✕
        </button>
      </div>

      <Section title="Identity">
        <KV label="Ecosystem">{pkg.ecosystem ?? '-'}</KV>
        <KV label="purl" mono>
          {pkg.purl ?? '-'}
        </KV>
        {cpes.length > 0 && (
          <KV label="CPE" mono>
            {cpes.slice(0, 5).map((c) => (
              <div key={c}>{c}</div>
            ))}
            {cpes.length > 5 && <div className="text-slate-400">and {cpes.length - 5} more</div>}
          </KV>
        )}
        <KV label="Supplier">{pkg.supplier ?? '-'}</KV>
        <KV label="License">
          {pkg.licenses.length > 0 ? pkg.licenses.join('; ') : '-'}
          {pkg.licensesUnparsed.length > 0 && (
            <span className="ml-1 text-xs text-amber-700 dark:text-amber-400">
              (not an SPDX expression)
            </span>
          )}
        </KV>
      </Section>

      <Section title="Ships in">
        <ul className="space-y-1.5">
          {pkg.places.map((place) => (
            <li key={place.key} className="text-sm">
              <div className="flex flex-wrap items-center gap-1.5">
                <PlaceChip place={place} bundle={bundle} />
                <button
                  type="button"
                  onClick={() => open(place)}
                  className="text-xs text-accent-700 hover:underline dark:text-accent-400"
                >
                  {place.kind === 'component'
                    ? 'Open component'
                    : place.kind === 'artifact'
                      ? 'Open artifact'
                      : 'Open SBOM'}
                </button>
              </div>
              <div className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
                SBOM binding: {placeBinding(place)} · listed by{' '}
                {place.sboms.map((ref, i) => (
                  <span key={`${ref.cvId}#${ref.index}`}>
                    {i > 0 && ', '}
                    <button
                      type="button"
                      onClick={() =>
                        selectSbom({ cvId: ref.cvId, role: 'resource', index: ref.index })
                      }
                      className="text-accent-700 hover:underline dark:text-accent-400"
                    >
                      {artifactAt(bundle, ref)?.name ?? '?'}
                    </button>
                  </span>
                ))}
              </div>
            </li>
          ))}
        </ul>
      </Section>

      {findings && findings.length > 0 && (
        <Section title="What the supplier states (VEX)">
          <ul className="space-y-1.5">
            {findings.map((f) => (
              <li key={f.vulnerability} className="text-sm">
                <div className="flex flex-wrap items-center gap-1.5">
                  <span className="font-mono text-xs">{f.vulnerability}</span>
                  <VexChip status={f.status} />
                </div>
                {(f.actionStatement ?? f.impactStatement ?? f.justification) && (
                  <div className="mt-0.5 text-xs text-slate-600 dark:text-slate-300">
                    {f.actionStatement ?? f.impactStatement ?? f.justification}
                  </div>
                )}
                <div className="text-xs text-slate-400">
                  {f.sourceFile}
                  {f.timestamp ? `, ${f.timestamp.slice(0, 10)}` : ''}
                  {f.viaSubcomponent ? ', as a component of a named product' : ''}
                </div>
              </li>
            ))}
          </ul>
        </Section>
      )}

      {others.length > 0 && (
        <Section title="Other versions in this delivery">
          <ul className="space-y-0.5">
            {others.map((other) => (
              <li key={other.id} className="flex flex-wrap items-center gap-1.5 text-sm">
                <button
                  type="button"
                  onClick={() => onSelect(other.id)}
                  className="font-mono text-xs text-accent-700 hover:underline dark:text-accent-400"
                >
                  {other.version ?? 'no version'}
                </button>
                {other.places.map((place) => (
                  <PlaceChip key={place.key} place={place} bundle={bundle} />
                ))}
              </li>
            ))}
          </ul>
        </Section>
      )}
    </div>
  );
}
