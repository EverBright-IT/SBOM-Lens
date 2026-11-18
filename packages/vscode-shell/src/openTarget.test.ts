import { describe, expect, it } from 'vitest';
import { pickOpenTargets } from './openTarget';

/**
 * What "Open with ..." acts on. The explorer hands over its selection; the
 * command palette hands over nothing, and the command then takes the file of
 * the active editor, whatever that file is called.
 */
describe('pickOpenTargets', () => {
  it('takes the explorer multi-selection as it is', () => {
    expect(pickOpenTargets('a', ['a', 'b'], { textEditor: 'x', tab: 'y' })).toEqual(['a', 'b']);
  });

  it('takes the single explorer resource when there is no multi-selection', () => {
    expect(pickOpenTargets('a', undefined, { textEditor: 'x' })).toEqual(['a']);
    expect(pickOpenTargets('a', [], { textEditor: 'x' })).toEqual(['a']);
  });

  it('falls back to the active text editor, then to the active tab', () => {
    expect(pickOpenTargets(undefined, undefined, { textEditor: 'x', tab: 'y' })).toEqual(['x']);
    expect(pickOpenTargets(undefined, undefined, { tab: 'y' })).toEqual(['y']);
  });

  it('has nothing to open when no file is active', () => {
    expect(pickOpenTargets(undefined, undefined, {})).toEqual([]);
  });
});
