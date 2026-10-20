import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { ApiService } from './api.service';

describe('ApiService', () => {
  it('prefixes paths and encodes defined query params', () => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    const api = TestBed.inject(ApiService);
    const ctrl = TestBed.inject(HttpTestingController);
    api.get('/querylog', { limit: 5, q: undefined, live: true }).subscribe();
    const get = ctrl.expectOne('/api/v1/querylog?limit=5&live=true');
    get.flush({});
    api.put('/a', 1).subscribe();
    ctrl.expectOne((r) => r.method === 'PUT' && r.url === '/api/v1/a').flush({});
    api.patch('/a', 1).subscribe();
    ctrl.expectOne((r) => r.method === 'PATCH').flush({});
    api.delete('/a').subscribe();
    ctrl.expectOne((r) => r.method === 'DELETE').flush({});
    ctrl.verify();
  });
});
