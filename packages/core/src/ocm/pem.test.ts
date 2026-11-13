import { describe, expect, it } from 'vitest';
import { KeyImportError, spkiFromPem } from './pem';

const pem = (label: string, bytes: number[]): string =>
  `-----BEGIN ${label}-----\n${Buffer.from(bytes).toString('base64')}\n-----END ${label}-----`;

describe('spkiFromPem — malformed DER lengths', () => {
  // A long-form length of 0x84 FF FF FF FA is -6 under signed 32-bit bitwise
  // math, which once pointed a TLV's end back at its own start and spun the
  // walk forever. Parsing must now stop fast with a KeyImportError.
  it('rejects a certificate whose long-form length is negative, without hanging', () => {
    const t0 = Date.now();
    expect(() => spkiFromPem(pem('CERTIFICATE', [0x30, 0x06, 0x30, 0x84, 0xff, 0xff, 0xff, 0xfa]))).toThrow(
      KeyImportError,
    );
    expect(Date.now() - t0).toBeLessThan(1000);
  });

  it('rejects a declared length that runs past the input', () => {
    expect(() => spkiFromPem(pem('CERTIFICATE', [0x30, 0x7f]))).toThrow(KeyImportError);
    expect(() => spkiFromPem(pem('CERTIFICATE', [0x30, 0x82, 0xff, 0xff]))).toThrow(KeyImportError);
  });

  it('still extracts the SPKI from a well-formed certificate', () => {
    // SEQUENCE{ tbs=SEQUENCE{ SPKI=SEQUENCE{ SEQUENCE{}, BIT STRING } } }
    const spki = [0x30, 0x06, 0x30, 0x00, 0x03, 0x02, 0x00, 0xff];
    const tbs = [0x30, spki.length, ...spki];
    const cert = [0x30, tbs.length, ...tbs];
    expect(Array.from(spkiFromPem(pem('CERTIFICATE', cert)))).toEqual(spki);
  });

  it('returns a PUBLIC KEY block unchanged', () => {
    const der = [0x30, 0x03, 0x02, 0x01, 0x07];
    expect(Array.from(spkiFromPem(pem('PUBLIC KEY', der)))).toEqual(der);
  });
});
