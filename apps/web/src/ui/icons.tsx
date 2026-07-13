import type { SVGProps } from 'react';

type IconProps = SVGProps<SVGSVGElement>;

function base(props: IconProps): IconProps {
  return {
    width: 14,
    height: 14,
    viewBox: '0 0 16 16',
    fill: 'none',
    stroke: 'currentColor',
    strokeWidth: 1.5,
    strokeLinecap: 'round',
    strokeLinejoin: 'round',
    'aria-hidden': true,
    ...props,
  };
}

export const ChevronIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <path d="M6 4l4 4-4 4" />
  </svg>
);

export const DocumentIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <path d="M4 1.5h5.5L12 4v10.5H4z" />
    <path d="M9.5 1.5V4H12" />
  </svg>
);

export const PackageIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <path d="M8 1.5l5.5 3v7l-5.5 3-5.5-3v-7z" />
    <path d="M2.5 4.5L8 7.5l5.5-3M8 7.5v7" />
  </svg>
);

export const FileIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <path d="M5 2h4.5L12 4.5V14H5z" />
  </svg>
);

export const PlaceholderIcon = (props: IconProps) => (
  <svg {...base(props)} strokeDasharray="2 2">
    <rect x="2.5" y="2.5" width="11" height="11" rx="1.5" />
  </svg>
);

export const GroupIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <path d="M2.5 5.5v-2a1 1 0 0 1 1-1h2l1.5 1.5h5.5a1 1 0 0 1 1 1v8a1 1 0 0 1-1 1h-9a1 1 0 0 1-1-1z" />
  </svg>
);

export const CycleIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <path d="M13 8a5 5 0 1 1-1.5-3.5M13 2v3h-3" />
  </svg>
);

export const SearchIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <circle cx="7" cy="7" r="4.5" />
    <path d="M10.5 10.5L14 14" />
  </svg>
);

export const CopyIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <rect x="5.5" y="5.5" width="8" height="8" rx="1" />
    <path d="M10.5 5.5v-3h-8v8h3" />
  </svg>
);

export const CheckIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <path d="M2.5 8.5l3.5 3.5 7-8" />
  </svg>
);

export const CloseIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <path d="M3.5 3.5l9 9M12.5 3.5l-9 9" />
  </svg>
);

export const WarningIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <path d="M8 2L1.5 13.5h13z" />
    <path d="M8 6.5V10M8 11.8v.2" />
  </svg>
);

export const LinkIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <path d="M6.5 9.5l3-3" />
    <path d="M7.5 4.5l1-1a2.5 2.5 0 0 1 3.5 3.5l-1 1M8.5 11.5l-1 1a2.5 2.5 0 0 1-3.5-3.5l1-1" />
  </svg>
);

export const UploadIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <path d="M8 10.5V2.5M4.5 6L8 2.5 11.5 6" />
    <path d="M2.5 10.5v3h11v-3" />
  </svg>
);

export const RevealIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <path d="M2.5 4.5h11M4.5 8h9M6.5 11.5h7" />
  </svg>
);

export const FunnelIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <path d="M2 3h12L9.5 8.5V13l-3-1.5V8.5z" />
  </svg>
);

export const SunIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <circle cx="8" cy="8" r="3" />
    <path d="M8 1.5v1.6M8 12.9v1.6M1.5 8h1.6M12.9 8h1.6M3.4 3.4l1.1 1.1M11.5 11.5l1.1 1.1M12.6 3.4l-1.1 1.1M4.5 11.5l-1.1 1.1" />
  </svg>
);

export const MoonIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <path d="M13.5 9.5A5.75 5.75 0 0 1 6.5 2.5a5.75 5.75 0 1 0 7 7z" />
  </svg>
);

export const SystemThemeIcon = (props: IconProps) => (
  <svg {...base(props)}>
    <rect x="1.5" y="2.5" width="13" height="9" rx="1.5" />
    <path d="M6 14.5h4M8 11.5v3" />
  </svg>
);

/** Brand marks ship their official filled paths, not the stroke base. */
const brand = (props: IconProps): IconProps => ({
  width: 15,
  height: 15,
  viewBox: '0 0 24 24',
  fill: 'currentColor',
  'aria-hidden': true,
  ...props,
});

export const GitHubIcon = (props: IconProps) => (
  <svg {...brand(props)}>
    <path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12" />
  </svg>
);

export const GitLabIcon = (props: IconProps) => (
  <svg {...brand(props)}>
    <path d="m23.6004 9.5927-.0337-.0862L20.3.9814a.851.851 0 0 0-.3362-.405.8748.8748 0 0 0-.9997.0539.8748.8748 0 0 0-.29.4399l-2.2055 6.748H7.5375l-2.2057-6.748a.8573.8573 0 0 0-.29-.4412.8748.8748 0 0 0-.9997-.0537.8585.8585 0 0 0-.3362.4049L.4332 9.5015l-.0325.0862a6.0657 6.0657 0 0 0 2.0119 7.0105l.0113.0087.03.0213 4.976 3.7264 2.462 1.8633 1.4995 1.1321a1.0085 1.0085 0 0 0 1.2197 0l1.4995-1.1321 2.462-1.8633 5.006-3.7489.0125-.01a6.0682 6.0682 0 0 0 2.0094-7.003z" />
  </svg>
);

export const InfoIcon = (props: IconProps) => (
  <svg {...base({ width: 12, height: 12, ...props })}>
    <circle cx="8" cy="8" r="6.2" />
    <path d="M8 7.2v3.6M8 5v.2" />
  </svg>
);

/** Brand mark from docs/brand/logo.svg: a lens over a 3-node cascade. */
export const LensLogo = (props: IconProps) => (
  <svg {...base({ width: 18, height: 18, ...props })} strokeWidth={1.8}>
    <circle cx="7" cy="7" r="5" />
    <path d="M10.7 10.7L14.3 14.3" />
    <path d="M7 5.5L5.1 8.4M7 5.5l1.9 2.9" strokeWidth={1.3} />
    <circle cx="7" cy="4.9" r="0.95" fill="currentColor" stroke="none" />
    <circle cx="4.8" cy="8.9" r="0.95" fill="currentColor" stroke="none" />
    <circle cx="9.2" cy="8.9" r="0.95" fill="currentColor" stroke="none" />
  </svg>
);
