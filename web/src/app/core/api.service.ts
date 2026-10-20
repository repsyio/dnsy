import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';

export const API_BASE = '/api/v1';

type Query = Record<string, string | number | boolean | undefined>;

/** Thin typed wrapper over `HttpClient`; errors arrive as `ApiError` via the interceptor. */
@Injectable({ providedIn: 'root' })
export class ApiService {
  private readonly http = inject(HttpClient);

  get<T>(path: string, query?: Query): Observable<T> {
    return this.http.get<T>(API_BASE + path, { params: toParams(query) });
  }

  post<T>(path: string, body: unknown): Observable<T> {
    return this.http.post<T>(API_BASE + path, body);
  }

  put<T>(path: string, body: unknown): Observable<T> {
    return this.http.put<T>(API_BASE + path, body);
  }

  patch<T>(path: string, body: unknown): Observable<T> {
    return this.http.patch<T>(API_BASE + path, body);
  }

  delete<T>(path: string, query?: Query): Observable<T> {
    return this.http.delete<T>(API_BASE + path, { params: toParams(query) });
  }
}

function toParams(query?: Query): HttpParams {
  let params = new HttpParams();
  for (const [k, v] of Object.entries(query ?? {})) {
    if (v !== undefined) params = params.set(k, String(v));
  }
  return params;
}
