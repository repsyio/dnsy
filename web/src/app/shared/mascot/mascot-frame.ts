import { ChangeDetectionStrategy, Component, computed, input, output } from '@angular/core';
import {
  MASCOT_LABELS,
  MASCOT_MESSAGES,
  MASCOT_ROLES,
  MASCOT_SIZES,
  MascotSize,
  MascotState,
} from './mascot-state';
import { injectReducedMotion } from './reduced-motion';

/**
 * Nox, drawn inline so the global rules in mascot.css can colour and animate its parts from the
 * brand tokens. The art follows branding/mascot/nox-*.svg in the 200x200 design space (the files
 * scale it into their 64x64 viewBox); the standalone files stay the static source of truth.
 */
@Component({
  selector: 'dnsy-mascot-frame',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <figure class="m-0 flex flex-col items-center gap-3 text-center">
      <svg
        xmlns="http://www.w3.org/2000/svg"
        viewBox="0 0 200 200"
        role="img"
        [attr.aria-label]="label()"
        class="nox"
        [class]="svgClass()"
        [class.nox-static]="reduced()"
      >
        <g
          class="nox-head"
          [attr.transform]="state() === 'not-found' ? 'rotate(-9 100 100)' : null"
        >
          <path
            class="nox-ln"
            d="M100 34 L146 20 L162 70 L152 140 L100 178 L48 140 L38 70 L54 20 Z"
          />
          <path
            class="nox-ln nox-dash"
            d="M100 46 L138 34 L150 72 L141 133 L100 163 L59 133 L50 72 L62 34 Z"
          />
          @switch (state()) {
            @case ('loading') {
              <path class="nox-ln" d="M44 80 L100 98 L156 80" />
              <path class="nox-eye nox-dim" d="M62 101.5 H88 M112 101.5 H138" />
              <rect class="nox-sweep" x="62" y="100.5" width="9" height="2" />
              <path class="nox-beak" d="M93 108 L100 116 L107 108" />
            }
            @case ('empty') {
              <path class="nox-ln" d="M44 86 L100 96 L156 86" />
              <path class="nox-eye" d="M68 108 H84 M116 108 H132" />
              <path class="nox-beak" d="M93 114 L100 122 L107 114" />
            }
            @case ('error') {
              <path class="nox-ln" d="M44 74 L100 100 L156 74" />
              <path class="nox-eye nox-flicker" d="M62 97 L88 105 M112 105 L138 97" />
              <path class="nox-beak" d="M93 110 L100 118 L107 110" />
            }
            @case ('success') {
              <path class="nox-ln" d="M44 80 L100 98 L156 80" />
              <path class="nox-eye" d="M62 105 L75 98 L88 105 M112 105 L125 98 L138 105" />
              <path class="nox-beak" d="M93 110 L100 118 L107 110" />
            }
            @case ('offline') {
              <path class="nox-ln" d="M44 80 L100 98 L156 80" />
              <path class="nox-eye nox-broken" d="M62 101.5 H88 M112 101.5 H138" />
              <path class="nox-beak" d="M93 108 L100 116 L107 108" />
            }
            @case ('not-found') {
              <path class="nox-ln" d="M44 80 L100 98 L156 80" />
              <path class="nox-eye" d="M62 101.5 H88" />
              <circle class="nox-eye" cx="125" cy="101" r="6" />
              <path class="nox-beak" d="M93 108 L100 116 L107 108" />
            }
          }
        </g>
      </svg>
      <figcaption class="text-sm text-muted" [attr.role]="role()">{{ text() }}</figcaption>
      @if (action(); as actionLabel) {
        <button class="btn" type="button" (click)="actionClick.emit()">{{ actionLabel }}</button>
      }
    </figure>
  `,
})
export class MascotFrame {
  readonly state = input.required<MascotState>();
  readonly size = input<MascotSize>('md');
  readonly message = input<string>();
  readonly action = input<string>();
  readonly actionClick = output<void>();

  protected readonly reduced = injectReducedMotion();
  protected readonly label = computed(() => MASCOT_LABELS[this.state()]);
  protected readonly text = computed(() => this.message() ?? MASCOT_MESSAGES[this.state()]);
  protected readonly role = computed(() => MASCOT_ROLES[this.state()]);
  protected readonly svgClass = computed(
    () => `nox nox-${this.state()} ${MASCOT_SIZES[this.size()]}`,
  );
}
