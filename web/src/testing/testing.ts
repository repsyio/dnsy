import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { Type } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { apiInterceptor } from '../app/core/api.interceptor';

/** Mount `page` with the typed HTTP stack and a request controller. */
export function mount<T>(page: Type<T>) {
  TestBed.configureTestingModule({
    providers: [
      provideRouter([]),
      provideHttpClient(withInterceptors([apiInterceptor])),
      provideHttpClientTesting(),
    ],
  });
  const fixture = TestBed.createComponent(page);
  const http = TestBed.inject(HttpTestingController);
  const el = fixture.nativeElement as HTMLElement;
  return { fixture, http, el };
}

export function problem(status: number, detail: string) {
  return {
    body: { type: 'about:blank/invalid', title: 'Invalid', status, detail },
    init: { status, statusText: 'err', headers: { 'Content-Type': 'application/problem+json' } },
  };
}

export function type(el: HTMLElement, selector: string, value: string): void {
  const input = el.querySelector<HTMLInputElement>(selector)!;
  input.value = value;
  input.dispatchEvent(new Event('input'));
}

export function click(el: HTMLElement, selector: string): void {
  el.querySelector<HTMLElement>(selector)!.click();
}

export function clickByText(el: ParentNode, text: string): void {
  const btn = Array.from(el.querySelectorAll<HTMLButtonElement>('button')).find(
    (b) => b.textContent?.trim() === text,
  );
  if (!btn) throw new Error(`no button "${text}"`);
  btn.click();
}
