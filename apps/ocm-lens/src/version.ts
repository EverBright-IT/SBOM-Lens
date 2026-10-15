import { version } from '../package.json';

/** package.json is the single source; Vite's JSON named import bundles only this field. */
export const APP_VERSION: string = version;
