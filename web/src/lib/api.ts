// A small fetch wrapper for the instance's JSON API.
//
// Requests go to the same origin as the page (the session cookie is
// HttpOnly and SameSite=Strict), prefixed with `base` so the app also works
// when the instance's public URL has a path.

import { resolve } from '$app/paths';
import type { ApiErrorBody } from './types.ts';

/** The app's base path without a trailing slash ('' at the origin's root). */
function apiBase(): string {
	return resolve('/').replace(/\/$/, '');
}

/** The full URL of an API path on this instance, e.g. for an `<img>`. */
export function apiUrl(path: string): string {
	return `${apiBase()}${path}`;
}

export class ApiError extends Error {
	constructor(
		/** HTTP status, or 0 when the server could not be reached. */
		readonly status: number,
		/** The API's machine-readable code, e.g. `invalid_setup_token`. */
		readonly code: string,
		message: string,
		/** Seconds to wait, from `Retry-After` on a 429. */
		readonly retryAfterSecs?: number
	) {
		super(message);
		this.name = 'ApiError';
	}
}

/** A raw request body with its own content type (a file upload). */
class RawBody {
	constructor(
		readonly data: Blob,
		readonly contentType: string
	) {}
}

function encodeBody(body: unknown): { headers: Record<string, string>; body?: BodyInit } {
	if (body === undefined) return { headers: {} };
	if (body instanceof RawBody) {
		return { headers: { 'content-type': body.contentType }, body: body.data };
	}
	return { headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) };
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
	let res: Response;
	try {
		res = await fetch(`${apiBase()}${path}`, {
			method,
			credentials: 'same-origin',
			...encodeBody(body)
		});
	} catch {
		throw new ApiError(0, 'network', 'Could not reach the Faro server.');
	}

	const text = await res.text();
	let data: unknown = null;
	if (text) {
		try {
			data = JSON.parse(text);
		} catch {
			// Not JSON: a proxy in front of Faro answered. Handled below.
		}
	}

	if (!res.ok) {
		const err = data as Partial<ApiErrorBody> | null;
		const retry = Number(res.headers.get('retry-after'));
		throw new ApiError(
			res.status,
			err?.error ?? `http_${res.status}`,
			err?.message ?? (res.statusText || `HTTP ${res.status}`),
			Number.isFinite(retry) && retry > 0 ? retry : undefined
		);
	}
	if (res.status === 204) {
		return undefined as T;
	}
	if (data === null) {
		throw new ApiError(res.status, 'bad_response', 'The server sent an unexpected response.');
	}
	return data as T;
}

export const api = {
	get: <T>(path: string) => request<T>('GET', path),
	/** For a `204 No Content` answer, use `T = void`. */
	post: <T>(path: string, body?: unknown) => request<T>('POST', path, body),
	patch: <T>(path: string, body: unknown) => request<T>('PATCH', path, body),
	put: <T>(path: string, body: unknown) => request<T>('PUT', path, body),
	/** `PUT` a file as the raw body, with its own `Content-Type`. */
	putFile: <T>(path: string, data: Blob, contentType: string) =>
		request<T>('PUT', path, new RawBody(data, contentType)),
	/** For a `204 No Content` answer, use `T = void`. */
	delete: <T>(path: string, body?: unknown) => request<T>('DELETE', path, body)
};

/** `encodeURIComponent` for one path segment. */
export const seg = encodeURIComponent;

/** A sentence for an error the page has no specific wording for. */
export function describeError(e: unknown): string {
	if (e instanceof ApiError) {
		if (e.code === 'network') return e.message;
		if (e.code === 'rate_limited') {
			return e.retryAfterSecs
				? `Too many attempts. Wait ${e.retryAfterSecs} seconds and try again.`
				: 'Too many attempts. Wait a minute and try again.';
		}
		if (e.code === 'internal') return 'The server hit an error. Its log has the details.';
		return `${e.message} (${e.code})`;
	}
	return 'Something went wrong.';
}
