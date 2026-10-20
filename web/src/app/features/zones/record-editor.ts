import { ChangeDetectionStrategy, Component, computed, input, output, signal } from '@angular/core';
import { RECORD_TYPES, validateRecord } from './record-validation';
import type { RecordDraft } from './record-validation';
import type { RecordInput } from './zones.service';

/** Add/edit form for one record with per-type validation. */
@Component({
  selector: 'app-record-editor',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <form
      class="grid grid-cols-1 gap-3 sm:grid-cols-6"
      novalidate
      [attr.aria-label]="label()"
      (submit)="submit($event)"
      (keydown.escape)="cancelled.emit()"
    >
      <div class="sm:col-span-2">
        <label class="field-label" [for]="id + '-name'">Name</label>
        <input
          class="field-input"
          autocomplete="off"
          placeholder="@ or www"
          [id]="id + '-name'"
          [value]="draft().name"
          [attr.aria-invalid]="show() && errors().name ? 'true' : null"
          (input)="set('name', $event)"
        />
        @if (show() && errors().name) {
          <p class="field-error">{{ errors().name }}</p>
        }
      </div>
      <div>
        <label class="field-label" [for]="id + '-type'">Type</label>
        <select
          class="field-input"
          [id]="id + '-type'"
          [value]="draft().type"
          (change)="set('type', $event)"
        >
          @for (t of types; track t) {
            <option [value]="t" [selected]="t === draft().type">{{ t }}</option>
          }
        </select>
      </div>
      <div>
        <label class="field-label" [for]="id + '-ttl'">TTL (s)</label>
        <input
          class="field-input"
          inputmode="numeric"
          placeholder="zone default"
          [id]="id + '-ttl'"
          [value]="draft().ttl"
          [attr.aria-invalid]="show() && errors().ttl ? 'true' : null"
          (input)="set('ttl', $event)"
        />
        @if (show() && errors().ttl) {
          <p class="field-error">{{ errors().ttl }}</p>
        }
      </div>
      <div class="sm:col-span-2">
        <label class="field-label" [for]="id + '-value'">Value</label>
        <input
          class="field-input"
          autocomplete="off"
          [id]="id + '-value'"
          [value]="draft().value"
          [attr.aria-invalid]="show() && errors().value ? 'true' : null"
          (input)="set('value', $event)"
        />
        @if (show() && errors().value) {
          <p class="field-error">{{ errors().value }}</p>
        }
      </div>
      @if (error()) {
        <p class="field-error sm:col-span-6" role="alert">{{ error() }}</p>
      }
      <div class="flex flex-wrap gap-3 sm:col-span-6">
        <button class="btn" type="submit" [disabled]="busy()">Save</button>
        <button class="btn" type="button" (click)="cancelled.emit()">Cancel</button>
      </div>
    </form>
  `,
})
export class RecordEditor {
  readonly initial = input<RecordDraft>({ name: '', type: 'A', ttl: '', value: '' });
  readonly label = input('Record');
  readonly busy = input(false);
  readonly error = input<string | null>(null);
  readonly saved = output<RecordInput>();
  readonly cancelled = output<void>();

  private static next = 0;
  protected readonly id = `rec-${RecordEditor.next++}`;
  protected readonly types = RECORD_TYPES;
  private readonly edits = signal<Partial<RecordDraft>>({});
  protected readonly draft = computed<RecordDraft>(() => ({ ...this.initial(), ...this.edits() }));
  protected readonly errors = computed(() => validateRecord(this.draft()));
  protected readonly show = signal(false);

  protected set(field: keyof RecordDraft, event: Event): void {
    const value = (event.target as HTMLInputElement).value;
    this.edits.update((e) => ({ ...e, [field]: value }));
  }

  protected submit(event: Event): void {
    event.preventDefault();
    this.show.set(true);
    if (Object.keys(this.errors()).length > 0) return;
    const d = this.draft();
    const ttl = d.ttl.trim();
    this.saved.emit({
      name: d.name.trim(),
      type: d.type,
      value: d.value.trim(),
      ...(ttl ? { ttl: Number(ttl) } : {}),
    });
  }
}
