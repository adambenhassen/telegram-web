import {describe, expect, it} from 'vitest';
import keepAsset from '../keepAsset.js';

describe('build asset retention', () => {
  it('does not preserve the legacy version resource', () => {
    expect(keepAsset('version')).toBe(false);
  });
});
