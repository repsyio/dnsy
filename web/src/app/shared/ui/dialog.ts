import {
  ChangeDetectionStrategy,
  Component,
  ElementRef,
  afterNextRender,
  inject,
  input,
  output,
} from '@angular/core';

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select, textarea';

/** Modal dialog frame: labelled, Escape closes, Tab stays inside, focus returns on close. */
@Component({
  selector: 'app-dialog',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="fixed inset-0 z-50 flex items-center justify-center bg-bg/80 p-4">
      <div
        class="panel max-h-full w-full max-w-lg overflow-y-auto"
        role="dialog"
        aria-modal="true"
        [attr.aria-labelledby]="'dlg-title'"
        (keydown)="onKey($event)"
      >
        <h2 id="dlg-title" class="mb-4 section-title">{{ heading() }}</h2>
        <ng-content />
      </div>
    </div>
  `,
})
export class Dialog {
  readonly heading = input.required<string>();
  readonly closed = output<void>();
  private readonly host = inject<ElementRef<HTMLElement>>(ElementRef);
  private readonly opener = document.activeElement as HTMLElement | null;

  constructor() {
    afterNextRender(() => this.focusables()[0]?.focus());
  }

  private focusables(): HTMLElement[] {
    return Array.from(this.host.nativeElement.querySelectorAll<HTMLElement>(FOCUSABLE));
  }

  close(): void {
    this.closed.emit();
    this.opener?.focus?.();
  }

  onKey(event: KeyboardEvent): void {
    if (event.key === 'Escape') {
      event.stopPropagation();
      this.close();
    } else if (event.key === 'Tab') {
      const items = this.focusables();
      if (items.length === 0) return;
      const first = items[0];
      const last = items[items.length - 1];
      const active = document.activeElement;
      if (event.shiftKey && active === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && active === last) {
        event.preventDefault();
        first.focus();
      }
    }
  }
}
