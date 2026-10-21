import { ChangeDetectionStrategy, Component, signal } from '@angular/core';
import {
  MascotEmptyComponent,
  MascotErrorComponent,
  MascotLoadingComponent,
  MascotNotFoundComponent,
  MascotOfflineComponent,
  MascotSuccessComponent,
} from '../../shared/mascot';
import type { MascotSize } from '../../shared/mascot';

/** Dev-only gallery of the Nox states, mounted at /dev/mascot behind auth. */
@Component({
  selector: 'app-mascot-gallery-page',
  imports: [
    MascotEmptyComponent,
    MascotErrorComponent,
    MascotLoadingComponent,
    MascotNotFoundComponent,
    MascotOfflineComponent,
    MascotSuccessComponent,
  ],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <h1 class="mb-6 page-title">Mascot gallery</h1>
    <div class="mb-6 flex gap-3" role="group" aria-label="Size">
      @for (s of sizes; track s) {
        <button class="btn" type="button" [attr.aria-pressed]="size() === s" (click)="size.set(s)">
          {{ s }}
        </button>
      }
    </div>
    <div class="grid grid-cols-1 gap-6 sm:grid-cols-2 xl:grid-cols-3">
      <section class="panel"><dnsy-mascot-loading [size]="size()" /></section>
      <section class="panel"><dnsy-mascot-empty [size]="size()" action="Create one" /></section>
      <section class="panel"><dnsy-mascot-error [size]="size()" action="Retry" /></section>
      <section class="panel"><dnsy-mascot-success [size]="size()" /></section>
      <section class="panel"><dnsy-mascot-offline [size]="size()" /></section>
      <section class="panel"><dnsy-mascot-not-found [size]="size()" /></section>
    </div>
  `,
})
export class MascotGalleryPage {
  protected readonly sizes: MascotSize[] = ['sm', 'md', 'lg'];
  protected readonly size = signal<MascotSize>('md');
}
