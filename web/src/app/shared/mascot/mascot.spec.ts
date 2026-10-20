import { ComponentFixture, TestBed } from '@angular/core/testing';
import { Type } from '@angular/core';
import {
  MascotEmptyComponent,
  MascotErrorComponent,
  MascotLoadingComponent,
  MascotNotFoundComponent,
  MascotOfflineComponent,
  MascotSuccessComponent,
} from './mascot-states';

const STATES: [string, Type<unknown>][] = [
  ['loading', MascotLoadingComponent],
  ['empty', MascotEmptyComponent],
  ['error', MascotErrorComponent],
  ['success', MascotSuccessComponent],
  ['offline', MascotOfflineComponent],
  ['not-found', MascotNotFoundComponent],
];

function stubMatchMedia(reduced: boolean): void {
  vi.stubGlobal('matchMedia', (query: string) => ({
    matches: reduced && query.includes('prefers-reduced-motion'),
    media: query,
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
  }));
}

async function render(type: Type<unknown>): Promise<ComponentFixture<unknown>> {
  const fixture = TestBed.createComponent(type);
  await fixture.whenStable();
  return fixture;
}

describe('mascot components', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('each_state_has_accessible_label', async () => {
    const labels = new Set<string>();
    for (const [state, type] of STATES) {
      const el = (await render(type)).nativeElement as HTMLElement;
      const svg = el.querySelector('svg[role="img"]');
      expect(svg, state).not.toBeNull();
      const label = svg!.getAttribute('aria-label') ?? '';
      expect(label.length, state).toBeGreaterThan(3);
      labels.add(label);
    }
    expect(labels.size).toBe(STATES.length);
  });

  it('reduced_motion_disables_animation', async () => {
    stubMatchMedia(true);
    for (const [state, type] of STATES) {
      const el = (await render(type)).nativeElement as HTMLElement;
      expect(el.querySelector('svg')!.classList.contains('nox-static'), state).toBe(true);
    }
  });

  it('animates_when_motion_is_allowed', async () => {
    stubMatchMedia(false);
    const el = (await render(MascotLoadingComponent)).nativeElement as HTMLElement;
    expect(el.querySelector('svg')!.classList.contains('nox-static')).toBe(false);
  });

  it('renders_default_and_custom_message', async () => {
    const fixture = TestBed.createComponent(MascotEmptyComponent);
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('figcaption')!.textContent).toContain('Nothing here');
    fixture.componentRef.setInput('message', 'No zones yet');
    await fixture.whenStable();
    expect(el.querySelector('figcaption')!.textContent).toContain('No zones yet');
  });

  it('size_input_changes_dimensions', async () => {
    const fixture = TestBed.createComponent(MascotErrorComponent);
    fixture.componentRef.setInput('size', 'lg');
    await fixture.whenStable();
    const svg = (fixture.nativeElement as HTMLElement).querySelector('svg')!;
    expect(svg.classList.contains('h-40')).toBe(true);
  });

  it('action_button_emits', async () => {
    const fixture = TestBed.createComponent(MascotErrorComponent);
    const spy = vi.fn();
    fixture.componentInstance.actionClick.subscribe(spy);
    const el = fixture.nativeElement as HTMLElement;
    await fixture.whenStable();
    expect(el.querySelector('button')).toBeNull();
    fixture.componentRef.setInput('action', 'Retry');
    await fixture.whenStable();
    const button = el.querySelector('button')!;
    expect(button.textContent).toContain('Retry');
    button.click();
    expect(spy).toHaveBeenCalledOnce();
  });

  it('has_no_inline_styles_or_scripts', async () => {
    for (const [state, type] of STATES) {
      const el = (await render(type)).nativeElement as HTMLElement;
      expect(el.querySelector('[style], script, foreignObject, style'), state).toBeNull();
    }
  });
});
