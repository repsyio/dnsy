import { ApiError } from '../../core/api-error';
import { formatEpoch, messageOf } from './util';

describe('util', () => {
  it('prefers the API message and falls back otherwise', () => {
    expect(messageOf(new ApiError(422, null, 'bad cidr'), 'x')).toBe('bad cidr');
    expect(messageOf(new Error('boom'), 'fallback')).toBe('fallback');
  });
  it('formats epoch seconds', () => {
    expect(formatEpoch(0)).toBe('1970-01-01 00:00 UTC');
    expect(formatEpoch(null)).toBe('-');
    expect(formatEpoch(undefined)).toBe('-');
  });
});
