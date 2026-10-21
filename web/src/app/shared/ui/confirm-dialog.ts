import { ChangeDetectionStrategy, Component, input, output, signal } from '@angular/core';
import { Dialog } from './dialog';

/** Confirmation for destructive actions; optionally requires typing a phrase. */
@Component({
  selector: 'app-confirm-dialog',
  imports: [Dialog],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <app-dialog [heading]="heading()" (closed)="cancelled.emit()">
      <p class="mb-4 text-sm">{{ message() }}</p>
      @if (phrase(); as p) {
        <label class="field-label" for="confirm-phrase">Type {{ p }} to confirm</label>
        <input
          id="confirm-phrase"
          class="field-input"
          autocomplete="off"
          [value]="typed()"
          (input)="typed.set($any($event.target).value)"
        />
      }
      @if (error()) {
        <p class="field-error" role="alert">{{ error() }}</p>
      }
      <div class="mt-6 flex flex-wrap justify-end gap-3">
        <button class="btn" type="button" (click)="cancelled.emit()">Cancel</button>
        <button
          class="btn btn-danger"
          type="button"
          [disabled]="busy() || (phrase() !== null && typed() !== phrase())"
          (click)="confirmed.emit()"
        >
          {{ confirmLabel() }}
        </button>
      </div>
    </app-dialog>
  `,
})
export class ConfirmDialog {
  readonly heading = input.required<string>();
  readonly message = input.required<string>();
  readonly confirmLabel = input('Delete');
  readonly phrase = input<string | null>(null);
  readonly busy = input(false);
  readonly error = input<string | null>(null);
  readonly confirmed = output<void>();
  readonly cancelled = output<void>();
  protected readonly typed = signal('');
}
