import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { Shell } from './shell';

describe('Shell mascot wiring', () => {
  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideRouter([]), provideHttpClient(), provideHttpClientTesting()],
    });
  });

  it('shows_offline_mascot_when_connection_drops', async () => {
    const fixture = TestBed.createComponent(Shell);
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('dnsy-mascot-offline')).toBeNull();
    window.dispatchEvent(new Event('offline'));
    await fixture.whenStable();
    expect(el.querySelector('dnsy-mascot-offline')).not.toBeNull();
    window.dispatchEvent(new Event('online'));
    await fixture.whenStable();
    expect(el.querySelector('dnsy-mascot-offline')).toBeNull();
  });
});

describe('Shell off-canvas menu', () => {
  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideRouter([]), provideHttpClient(), provideHttpClientTesting()],
    });
  });

  async function mountShell() {
    const fixture = TestBed.createComponent(Shell);
    document.body.appendChild(fixture.nativeElement);
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;
    return {
      fixture,
      el,
      button: el.querySelector<HTMLButtonElement>('button[aria-controls="main-nav"]')!,
      nav: el.querySelector<HTMLElement>('#main-nav')!,
    };
  }

  it('starts closed, opens from the menu button and moves focus into the nav', async () => {
    const { fixture, button, nav } = await mountShell();
    expect(button.getAttribute('aria-expanded')).toBe('false');
    expect(nav.classList.contains('translate-x-0')).toBe(false);
    button.click();
    await fixture.whenStable();
    await new Promise((r) => setTimeout(r));
    expect(button.getAttribute('aria-expanded')).toBe('true');
    expect(nav.classList.contains('translate-x-0')).toBe(true);
    expect(nav.contains(document.activeElement)).toBe(true);
    fixture.nativeElement.remove();
  });

  it('closes on Escape and returns focus to the menu button', async () => {
    const { fixture, button, nav } = await mountShell();
    button.click();
    await fixture.whenStable();
    await new Promise((r) => setTimeout(r));
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
    await fixture.whenStable();
    expect(button.getAttribute('aria-expanded')).toBe('false');
    expect(nav.classList.contains('translate-x-0')).toBe(false);
    expect(document.activeElement).toBe(button);
    fixture.nativeElement.remove();
  });

  it('closes when the backdrop or a link is clicked and toggles shut with the button', async () => {
    const { fixture, el, button } = await mountShell();
    button.click();
    await fixture.whenStable();
    el.querySelector<HTMLElement>('button[aria-label="Close menu"]')!.click();
    await fixture.whenStable();
    expect(button.getAttribute('aria-expanded')).toBe('false');
    button.click();
    await fixture.whenStable();
    button.click();
    await fixture.whenStable();
    expect(button.getAttribute('aria-expanded')).toBe('false');
    fixture.nativeElement.remove();
  });

  it('hides the Users entry from non-admins', async () => {
    const { el } = await mountShell();
    expect(el.textContent).not.toContain('Users');
    expect(el.textContent).toContain('Tokens');
    expect(el.textContent).toContain('Profile');
    el.remove();
  });
});
