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
 * Nox, drawn inline so global CSS keyframes (styles/mascot.css) can animate its parts. The art
 * follows branding/mascot/nox-*.svg; the standalone files stay the static source of truth.
 */
@Component({
  selector: 'dnsy-mascot-frame',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <figure class="m-0 flex flex-col items-center gap-3 text-center">
      <svg
        xmlns="http://www.w3.org/2000/svg"
        viewBox="0 0 64 64"
        role="img"
        [attr.aria-label]="label()"
        class="nox"
        [class]="svgClass()"
        [class.nox-static]="reduced()"
      >
        <g class="nox-bob">
          <path
            class="nox-body"
            d="M12 8 L24 16 H40 L52 8 V34 L44 52 L32 58 L20 52 L12 34 Z"
            fill="#05080d"
            stroke="#19e6ff"
            stroke-width="2.5"
            stroke-linejoin="round"
          />
          @switch (state()) {
            @case ('loading') {
              <circle cx="23" cy="28" r="6" fill="none" stroke="#19e6ff" stroke-width="2" />
              <circle
                cx="41"
                cy="28"
                r="6"
                fill="#19e6ff"
                fill-opacity=".25"
                stroke="#19e6ff"
                stroke-width="2"
              />
              <g class="nox-scan">
                <circle cx="23" cy="28" r="2.4" fill="#19e6ff" />
                <circle cx="41" cy="28" r="2.4" fill="#19e6ff" />
              </g>
            }
            @case ('empty') {
              <circle
                class="nox-dash"
                cx="23"
                cy="28"
                r="6"
                fill="none"
                stroke="#19e6ff"
                stroke-width="2"
                stroke-dasharray="3 3"
              />
              <circle
                class="nox-dash"
                cx="41"
                cy="28"
                r="6"
                fill="none"
                stroke="#19e6ff"
                stroke-width="2"
                stroke-dasharray="3 3"
              />
            }
            @case ('error') {
              <path
                class="nox-flash"
                d="M18 23 L28 33 M28 23 L18 33 M36 23 L46 33 M46 23 L36 33"
                fill="none"
                stroke="#ff3b5c"
                stroke-width="2.5"
                stroke-linecap="round"
              />
            }
            @case ('success') {
              <path
                d="M17 31 Q23 22 29 31 M35 31 Q41 22 47 31"
                fill="none"
                stroke="#2dff9a"
                stroke-width="2.5"
                stroke-linecap="round"
              />
            }
            @case ('offline') {
              <path
                class="nox-breathe"
                d="M17 29 Q23 34 29 29 M35 29 Q41 34 47 29"
                fill="none"
                stroke="#19e6ff"
                stroke-width="2.5"
                stroke-linecap="round"
              />
            }
            @case ('not-found') {
              <circle cx="23" cy="28" r="6" fill="none" stroke="#19e6ff" stroke-width="2" />
              <circle
                cx="41"
                cy="28"
                r="6"
                fill="#19e6ff"
                fill-opacity=".25"
                stroke="#19e6ff"
                stroke-width="2"
              />
              <g class="nox-scan">
                <circle cx="23" cy="28" r="2.4" fill="#19e6ff" />
                <circle cx="41" cy="28" r="2.4" fill="#19e6ff" />
              </g>
              <text
                class="nox-flash font-display"
                x="32"
                y="20"
                text-anchor="middle"
                font-weight="700"
                font-size="11"
                fill="#ff8a1f"
              >
                404
              </text>
            }
          }
          <path d="M28 38 H36 L32 46 Z" fill="#ff8a1f" />
        </g>
        @switch (state()) {
          @case ('loading') {
            <circle
              cx="54"
              cy="14"
              r="8"
              fill="none"
              stroke="#ff8a1f"
              stroke-opacity=".2"
              stroke-width="2.5"
            />
            <g class="nox-spin">
              <path
                d="M54 6 A8 8 0 1 1 46 14"
                fill="none"
                stroke="#ff8a1f"
                stroke-width="2.5"
                stroke-linecap="round"
              />
            </g>
          }
          @case ('empty') {
            <path
              class="nox-floor"
              d="M8 62 H56"
              stroke="#19e6ff"
              stroke-opacity=".4"
              stroke-dasharray="4 3"
            />
          }
          @case ('error') {
            <path class="nox-flash" d="M32 0 L36 8 H28 Z" fill="#ff3b5c" />
          }
          @case ('success') {
            <path
              class="nox-draw"
              d="M48 8 L53 13 L61 3"
              pathLength="1"
              fill="none"
              stroke="#2dff9a"
              stroke-width="3"
              stroke-linecap="round"
              stroke-linejoin="round"
            />
          }
          @case ('offline') {
            <path
              class="nox-flash"
              d="M6 6 L58 58"
              stroke="#ff3b5c"
              stroke-width="2.5"
              stroke-linecap="round"
            />
          }
        }
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
