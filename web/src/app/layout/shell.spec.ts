import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { Shell } from './shell';

describe('Shell mascot wiring', () => {
  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideRouter([]), provideHttpClient(), provideHttpClientTesting()],
    });
  });

  it('shows_offline_mascot_when_connection_drops', async () => {
    const fixture = TestBed.createComponent(Shell);
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('dnsy-mascot-offline')).toBeNull();
    window.dispatchEvent(new Event('offline'));
    await fixture.whenStable();
    expect(el.querySelector('dnsy-mascot-offline')).not.toBeNull();
    window.dispatchEvent(new Event('online'));
    await fixture.whenStable();
    expect(el.querySelector('dnsy-mascot-offline')).toBeNull();
  });
});
