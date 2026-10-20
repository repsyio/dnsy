import { ChangeDetectionStrategy, Component, Directive, input, output } from '@angular/core';
import { MascotFrame } from './mascot-frame';
import { MascotSize, MascotState } from './mascot-state';

/** Shared inputs: `message` replaces the default caption, `action` adds a button. */
@Directive()
abstract class MascotBase {
  abstract readonly state: MascotState;
  readonly size = input<MascotSize>('md');
  readonly message = input<string>();
  readonly action = input<string>();
  readonly actionClick = output<void>();
}

const TEMPLATE = `<dnsy-mascot-frame
  [state]="state"
  [size]="size()"
  [message]="message()"
  [action]="action()"
  (actionClick)="actionClick.emit()"
/>`;

@Component({
  selector: 'dnsy-mascot-loading',
  imports: [MascotFrame],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: TEMPLATE,
})
export class MascotLoadingComponent extends MascotBase {
  readonly state = 'loading';
}

@Component({
  selector: 'dnsy-mascot-empty',
  imports: [MascotFrame],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: TEMPLATE,
})
export class MascotEmptyComponent extends MascotBase {
  readonly state = 'empty';
}

@Component({
  selector: 'dnsy-mascot-error',
  imports: [MascotFrame],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: TEMPLATE,
})
export class MascotErrorComponent extends MascotBase {
  readonly state = 'error';
}

@Component({
  selector: 'dnsy-mascot-success',
  imports: [MascotFrame],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: TEMPLATE,
})
export class MascotSuccessComponent extends MascotBase {
  readonly state = 'success';
}

@Component({
  selector: 'dnsy-mascot-offline',
  imports: [MascotFrame],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: TEMPLATE,
})
export class MascotOfflineComponent extends MascotBase {
  readonly state = 'offline';
}

@Component({
  selector: 'dnsy-mascot-not-found',
  imports: [MascotFrame],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: TEMPLATE,
})
export class MascotNotFoundComponent extends MascotBase {
  readonly state = 'not-found';
}
