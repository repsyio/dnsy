import { TestBed } from '@angular/core/testing';
import { Router, UrlTree, provideRouter } from '@angular/router';
import { AuthService } from '../../core/auth.service';
import { adminGuard } from './admin.guard';

async function run(role: string | null) {
  TestBed.configureTestingModule({
    providers: [
      provideRouter([]),
      { provide: AuthService, useValue: { ensure: async () => (role ? { role } : null) } },
    ],
  });
  return TestBed.runInInjectionContext(() => adminGuard({} as never, {} as never));
}

describe('adminGuard', () => {
  it('lets admins in', async () => expect(await run('admin')).toBe(true));
  it.each(['viewer', 'operator', null])('redirects %s to the dashboard', async (role) => {
    const r = await run(role);
    expect(r).toBeInstanceOf(UrlTree);
    expect(TestBed.inject(Router).serializeUrl(r as UrlTree)).toBe('/dashboard');
  });
});
