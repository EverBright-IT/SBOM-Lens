import { describe, expect, it } from 'vitest';
import { MAX_DEEP_LINKS, readDeepLinks } from './deepLink';

/**
 * A deep link is input from whoever sent the link, so the parsing rules are
 * security boundaries, not conveniences. They are pinned here rather than left
 * to review: a regression would turn a shareable link into a way to make
 * someone else's browser fetch something.
 */
describe('readDeepLinks', () => {
  it('reads a single url', () => {
    expect(readDeepLinks('?url=https://acme.example/release.spdx.json')).toEqual({
      urls: ['https://acme.example/release.spdx.json'],
      rejected: 0,
    });
  });

  it('reads a whole cascade, in order', () => {
    const { urls } = readDeepLinks(
      '?url=https://acme.example/release.spdx.json&url=https://acme.example/webstack.spdx.json',
    );
    expect(urls).toEqual([
      'https://acme.example/release.spdx.json',
      'https://acme.example/webstack.spdx.json',
    ]);
  });

  it('works without the leading question mark', () => {
    expect(readDeepLinks('url=https://acme.example/a.spdx.json').urls).toHaveLength(1);
  });

  it('ignores other query parameters', () => {
    const { urls } = readDeepLinks('?theme=dark&url=https://acme.example/a.spdx.json&ref=readme');
    expect(urls).toEqual(['https://acme.example/a.spdx.json']);
  });

  it('is empty for an empty query', () => {
    expect(readDeepLinks('')).toEqual({ urls: [], rejected: 0 });
    expect(readDeepLinks('?')).toEqual({ urls: [], rejected: 0 });
  });

  it('deduplicates repeated urls without counting them as rejected', () => {
    const query = '?url=https://acme.example/a.json&url=https://acme.example/a.json';
    expect(readDeepLinks(query)).toEqual({ urls: ['https://acme.example/a.json'], rejected: 0 });
  });

  it('accepts http as well as https', () => {
    expect(readDeepLinks('?url=http://localhost:8080/a.spdx.json').urls).toHaveLength(1);
  });

  describe('rejects what must never reach a fetch', () => {
    it.each([
      ['javascript:', 'javascript:alert(1)'],
      ['data:', 'data:application/json,{}'],
      ['file:', 'file:///etc/passwd'],
      ['blob:', 'blob:https://acme.example/1234'],
      ['relative path', '/etc/passwd'],
      ['scheme-relative', '//acme.example/a.json'],
      ['nonsense', 'not a url at all'],
    ])('%s', (_label, value) => {
      const result = readDeepLinks(`?url=${encodeURIComponent(value)}`);
      expect(result.urls).toEqual([]);
      expect(result.rejected).toBe(1);
    });
  });

  it('caps the number of documents one link may open', () => {
    const query = Array.from({ length: MAX_DEEP_LINKS + 3 }, (_, i) => `url=https://acme.example/${i}.json`).join('&');
    const result = readDeepLinks(`?${query}`);
    expect(result.urls).toHaveLength(MAX_DEEP_LINKS);
    expect(result.rejected).toBe(3);
  });

  it('keeps the good urls when one is rejected', () => {
    const result = readDeepLinks('?url=javascript:alert(1)&url=https://acme.example/a.json');
    expect(result.urls).toEqual(['https://acme.example/a.json']);
    expect(result.rejected).toBe(1);
  });

  it('preserves query strings inside the linked url', () => {
    // Registry links carry their own parameters; encoding must survive.
    const inner = 'https://registry.example/api/v4/packages?id=42&format=spdx';
    const { urls } = readDeepLinks(`?url=${encodeURIComponent(inner)}`);
    expect(urls).toEqual([inner]);
  });
});
