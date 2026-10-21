import { Component } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ConfirmDialog } from './confirm-dialog';
import { Dialog } from './dialog';

@Component({
  imports: [Dialog],
  template: `<button id="opener" type="button">o</button
    ><app-dialog heading="H" (closed)="n = n + 1"
      ><button id="a" type="button">a</button><button id="b" type="button">b</button></app-dialog
    >`,
})
class Host {
  n = 0;
}

describe('Dialog', () => {
  it('focuses first control, traps Tab and closes on Escape', async () => {
    const fixture = TestBed.createComponent(Host);
    document.body.append(fixture.nativeElement);
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;
    const a = el.querySelector<HTMLElement>('#a')!;
    const b = el.querySelector<HTMLElement>('#b')!;
    expect(document.activeElement).toBe(a);
    const dlg = el.querySelector('[role="dialog"]')!;
    expect(dlg.getAttribute('aria-labelledby')).toBe('dlg-title');
    b.focus();
    const tab = new KeyboardEvent('keydown', { key: 'Tab', bubbles: true, cancelable: true });
    b.dispatchEvent(tab);
    expect(tab.defaultPrevented).toBe(true);
    expect(document.activeElement).toBe(a);
    const back = new KeyboardEvent('keydown', {
      key: 'Tab',
      shiftKey: true,
      bubbles: true,
      cancelable: true,
    });
    a.dispatchEvent(back);
    expect(document.activeElement).toBe(b);
    const mid = new KeyboardEvent('keydown', { key: 'Tab', bubbles: true, cancelable: true });
    a.focus();
    a.dispatchEvent(mid);
    expect(mid.defaultPrevented).toBe(false);
    dlg.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    expect(fixture.componentInstance.n).toBe(1);
    fixture.nativeElement.remove();
  });
});

describe('ConfirmDialog', () => {
  it('emits confirm and cancel', async () => {
    const fixture = TestBed.createComponent(ConfirmDialog);
    fixture.componentRef.setInput('heading', 'Delete');
    fixture.componentRef.setInput('message', 'Sure?');
    fixture.componentRef.setInput('error', 'oops');
    const ok = vi.fn();
    const no = vi.fn();
    fixture.componentInstance.confirmed.subscribe(ok);
    fixture.componentInstance.cancelled.subscribe(no);
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain('oops');
    const [cancel, confirm] = Array.from(el.querySelectorAll('button'));
    confirm.click();
    cancel.click();
    expect(ok).toHaveBeenCalled();
    expect(no).toHaveBeenCalled();
  });
});
