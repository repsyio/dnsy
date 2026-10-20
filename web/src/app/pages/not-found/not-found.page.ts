import { ChangeDetectionStrategy, Component } from '@angular/core';
import { RouterLink } from '@angular/router';

@Component({
  selector: 'app-not-found-page',
  imports: [RouterLink],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <section class="panel mx-auto mt-10 max-w-xl text-center">
      <img src="mascot/nox-404.svg" alt="" class="mx-auto h-40 w-40" />
      <h1 class="mt-4 text-3xl font-bold text-orange">404</h1>
      <p class="my-4 text-muted">Nox could not find that page.</p>
      <a class="btn inline-block" routerLink="/dashboard">Back to dashboard</a>
    </section>
  `,
})
export class NotFoundPage {}
