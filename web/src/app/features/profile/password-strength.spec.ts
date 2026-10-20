import { passwordStrength } from './password-strength';

describe('passwordStrength', () => {
  it('rates short passwords as too weak with a length hint', () => {
    const s = passwordStrength('abc');
    expect(s.score).toBe(0);
    expect(s.hints[0]).toContain('at least 8');
  });
  it('rates a long mixed password as strong with no hints', () => {
    const s = passwordStrength('Correct-Horse-9-Battery');
    expect(s.score).toBe(4);
    expect(s.label).toBe('Strong');
    expect(s.hints).toEqual([]);
  });
  it('suggests missing character classes', () => {
    const s = passwordStrength('alllowercase');
    expect(s.score).toBe(2);
    expect(s.hints).toContain('Add a digit.');
  });
});
