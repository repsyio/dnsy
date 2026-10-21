import { HttpClient, HttpHeaders, HttpResponse } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable, map } from 'rxjs';
import type { components } from '../../api/schema';
import { API_BASE } from '../../core/api.service';

type Schemas = components['schemas'];
export type ZoneSummary = Schemas['ZoneSummary'];
export type ZoneDetail = Schemas['ZoneDetail'];
export type ZoneBody = Schemas['ZoneBody'];
export type CreateZone = Schemas['CreateZone'];
export type RecordView = Schemas['RecordView'];
export type RecordInput = Schemas['RecordInput'];
export type RecordPage = Schemas['RecordPage'];

/** A response body together with the zone `ETag` it came with. */
export interface Tagged<T> {
  body: T;
  etag: string | null;
}

export interface RecordQuery {
  limit: number;
  offset: number;
  type?: string;
}

function tagged<T>(res: HttpResponse<T>): Tagged<T> {
  return { body: res.body as T, etag: res.headers.get('ETag') };
}

function ifMatch(etag: string | null): HttpHeaders {
  return etag ? new HttpHeaders({ 'If-Match': etag }) : new HttpHeaders();
}

/** Zones, records and export endpoints; keeps the `ETag` for `If-Match`. */
@Injectable({ providedIn: 'root' })
export class ZonesService {
  private readonly http = inject(HttpClient);

  private zoneUrl(zone: string): string {
    return `${API_BASE}/zones/${encodeURIComponent(zone)}`;
  }

  list(): Observable<ZoneSummary[]> {
    return this.http.get<ZoneSummary[]>(`${API_BASE}/zones`);
  }

  get(zone: string): Observable<Tagged<ZoneDetail>> {
    return this.http.get<ZoneDetail>(this.zoneUrl(zone), { observe: 'response' }).pipe(map(tagged));
  }

  create(body: CreateZone): Observable<Tagged<ZoneDetail>> {
    return this.http
      .post<ZoneDetail>(`${API_BASE}/zones`, body, { observe: 'response' })
      .pipe(map(tagged));
  }

  remove(zone: string, etag: string | null): Observable<void> {
    return this.http.delete<void>(this.zoneUrl(zone), { headers: ifMatch(etag) });
  }

  records(zone: string, q: RecordQuery): Observable<Tagged<RecordPage>> {
    const params: Record<string, string> = { limit: String(q.limit), offset: String(q.offset) };
    if (q.type) params['type'] = q.type;
    return this.http
      .get<RecordPage>(`${this.zoneUrl(zone)}/records`, { params, observe: 'response' })
      .pipe(map(tagged));
  }

  addRecord(zone: string, input: RecordInput, etag: string | null): Observable<Tagged<RecordView>> {
    return this.http
      .post<RecordView>(`${this.zoneUrl(zone)}/records`, input, {
        headers: ifMatch(etag),
        observe: 'response',
      })
      .pipe(map(tagged));
  }

  updateRecord(
    zone: string,
    id: string,
    input: RecordInput,
    etag: string | null,
  ): Observable<Tagged<RecordView>> {
    return this.http
      .put<RecordView>(`${this.zoneUrl(zone)}/records/${encodeURIComponent(id)}`, input, {
        headers: ifMatch(etag),
        observe: 'response',
      })
      .pipe(map(tagged));
  }

  deleteRecord(zone: string, id: string, etag: string | null): Observable<string | null> {
    return this.http
      .delete(`${this.zoneUrl(zone)}/records/${encodeURIComponent(id)}`, {
        headers: ifMatch(etag),
        observe: 'response',
      })
      .pipe(map((res) => res.headers.get('ETag')));
  }

  exportZone(zone: string, signed: boolean): Observable<string> {
    return this.http.get(`${this.zoneUrl(zone)}/export`, {
      params: { signed: String(signed) },
      responseType: 'text',
    });
  }
}
