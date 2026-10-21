import { TestBed } from '@angular/core/testing';
import { DnssecBadge, SourceBadge } from './badges';

async function render<T>(cmp: new () => T, value: string): Promise<HTMLElement> {
  const fixture = TestBed.createComponent(cmp);
  fixture.componentRef.setInput('value', value);
  await fixture.whenStable();
  return fixture.nativeElement as HTMLElement;
}

describe('badges', () => {
  it('dnssec_badge_per_status', async () => {
    const secure = await render(DnssecBadge, 'secure');
    expect(secure.querySelector('svg')).not.toBeNull();
    expect(secure.querySelector('.text-secure')).not.toBeNull();

    const bogus = await render(DnssecBadge, 'bogus');
    expect(bogus.querySelector('svg')).not.toBeNull();
    expect(bogus.querySelector('.text-amber')).not.toBeNull();
    expect(bogus.textContent).toContain('bogus');

    for (const s of ['insecure', 'unchecked']) {
      const el = await render(DnssecBadge, s);
      expect(el.querySelector('svg')).toBeNull();
      expect(el.querySelector('.text-muted')).not.toBeNull();
      expect(el.textContent).toContain(s);
    }
    expect(
      (await render(DnssecBadge, 'indeterminate')).querySelector('.text-amber'),
    ).not.toBeNull();
    expect((await render(DnssecBadge, 'garbage')).textContent).toContain('unknown');
  });

  it('labels sources and tags stale', async () => {
    expect((await render(SourceBadge, 'cache_stale')).textContent).toContain('Stale');
    expect((await render(SourceBadge, 'cache_stale')).querySelector('.text-amber')).not.toBeNull();
    expect((await render(SourceBadge, 'blocked')).textContent).toContain('Blocked');
    expect((await render(SourceBadge, 'upstream')).textContent).toContain('Forwarded');
    expect((await render(SourceBadge, 'cache')).querySelector('.text-secure')).not.toBeNull();
    expect((await render(SourceBadge, 'authoritative')).querySelector('.text-text')).not.toBeNull();
    expect((await render(SourceBadge, 'odd')).textContent).toContain('odd');
  });
});
