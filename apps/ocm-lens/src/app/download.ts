import { host } from '../host';

/** Hand a generated or extracted file to the user (download or save dialog). */
export function saveBytes(fileName: string, mime: string, data: Uint8Array | string): void {
  host.saveFile(fileName, mime, data);
}
