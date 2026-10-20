import { TestBed } from '@angular/core/testing';
import { RowDrawer } from './row-drawer';
import type { LogRecord } from './query-log.model';

const REC: LogRecord = {
  id: 9,
  ts_ms: 1_700_000_000_000,
  client: '10.0.0.2',
  transport: 'doh',
  qname: 'bad.example.',
  qtype: 'A',
  rcode: 'SERVFAIL',
  source: 'upstream',
  source_detail: '1.1.1.1:53',
  principal: 'laptop',
  dnssec: 'bogus',
  latency_us: 1500,
};

async function setup() {
  const fixture = TestBed.createComponent(RowDrawer);
  fixture.componentRef.setInput('record', REC);
  const closed = vi.fn();
  fixture.componentInstance.closed.subscribe(closed);
  await fixture.whenStable();
  return { fixture, el: fixture.nativeElement as HTMLElement, closed };
}

describe('RowDrawer', () => {
  it('shows the record fields', async () => {
    const { el } = await setup();
    const text = el.textContent ?? '';
    for (const s of [
      'bad.example.',
      '10.0.0.2',
      'doh',
      'SERVFAIL',
      '1.1.1.1:53',
      'laptop',
      '1.5 ms',
      'bogus',
    ]) {
      expect(text).toContain(s);
    }
    expect(el.querySelector('[role=dialog]')?.getAttribute('aria-modal')).toBe('true');
  });

  it('closes on Escape and the button', async () => {
    const { el, closed } = await setup();
    const dialog = el.querySelector('[role=dialog]') as HTMLElement;
    dialog.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    (el.querySelector('button') as HTMLButtonElement).click();
    expect(closed).toHaveBeenCalledTimes(2);
  });

  it('keeps Tab inside', async () => {
    const { el } = await setup();
    const dialog = el.querySelector('[role=dialog]') as HTMLElement;
    const button = el.querySelector('button') as HTMLButtonElement;
    button.focus();
    const ev = new KeyboardEvent('keydown', { key: 'Tab', bubbles: true, cancelable: true });
    dialog.dispatchEvent(ev);
    expect(ev.defaultPrevented).toBe(true);
    const back = new KeyboardEvent('keydown', {
      key: 'Tab',
      shiftKey: true,
      bubbles: true,
      cancelable: true,
    });
    dialog.dispatchEvent(back);
    expect(back.defaultPrevented).toBe(true);
  });
});
