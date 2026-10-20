import { ChangeDetectionStrategy, Component } from '@angular/core';
import { RouterLink } from '@angular/router';
import { MascotNotFoundComponent } from '../../shared/mascot';

@Component({
  selector: 'app-not-found-page',
  imports: [MascotNotFoundComponent, RouterLink],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <section class="panel mx-auto mt-10 max-w-xl text-center">
      <dnsy-mascot-not-found size="lg" message="Nox could not find that page." />
      <h1 class="mt-4 text-3xl font-bold text-orange">404</h1>
      <a class="btn mt-4 inline-block" routerLink="/dashboard">Back to dashboard</a>
    </section>
  `,
})
export class NotFoundPage {}
