import { ChangeDetectionStrategy, Component, input, output, signal } from '@angular/core';
import { Dialog } from '../../shared/ui/dialog';
import { copyText, dohUrl } from '../../shared/util/copy';

/** Shows a new token secret exactly once. The page drops the secret when this closes. */
@Component({
  selector: 'app-secret-dialog',
  imports: [Dialog],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <app-dialog heading="Token created" (closed)="done.emit()">
      <p class="mb-4 hairline border-amber p-3 text-sm text-amber" role="alert">
        Copy this secret now. It is shown only once and cannot be retrieved again; if you lose it,
        revoke the token and create a new one.
      </p>
      <label class="field-label" for="tk-secret">Secret for {{ name() }}</label>
      <input
        id="tk-secret"
        class="field-input mb-3"
        readonly
        autocomplete="off"
        spellcheck="false"
        [value]="secret()"
      />
      <div class="flex flex-wrap gap-3">
        <button class="btn" type="button" (click)="copy('secret', secret())">Copy secret</button>
        @if (doh()) {
          <button class="btn" type="button" (click)="copy('doh', url())">Copy DoH URL</button>
        }
      </div>
      <p class="mt-3 text-sm text-secure" role="status">{{ copied() }}</p>
      <div class="mt-6 flex justify-end">
        <button class="btn" type="button" (click)="done.emit()">I have saved it</button>
      </div>
    </app-dialog>
  `,
})
export class SecretDialog {
  readonly name = input.required<string>();
  readonly secret = input.required<string>();
  /** Whether the token can query DNS, so a DoH URL is useful. */
  readonly doh = input(false);
  readonly done = output<void>();
  protected readonly copied = signal('');

  protected url(): string {
    return dohUrl(location.host, this.secret());
  }

  protected async copy(what: 'secret' | 'doh', text: string): Promise<void> {
    const ok = await copyText(text);
    this.copied.set(
      ok
        ? what === 'secret'
          ? 'Secret copied.'
          : 'DoH URL copied.'
        : 'Copy failed; select it by hand.',
    );
  }
}
