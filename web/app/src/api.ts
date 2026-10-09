export class ApiError extends Error {
  constructor(readonly status: number) {
    super(`Request failed (${status})`);
  }
}

/** GET a local viewer API path. An aborted request rejects with the platform AbortError. */
export async function api<T>(path: string, signal?: AbortSignal): Promise<T> {
  const response = await fetch(path, {
    credentials: 'same-origin',
    headers: { 'X-XTrace-Client': 'viewer-v1' },
    signal,
  });
  if (!response.ok) {
    throw new ApiError(response.status);
  }
  return (await response.json()) as T;
}

export function failureMessage(error: unknown): string {
  if (error instanceof ApiError) return `Request failed with status ${error.status}.`;
  return 'The local viewer could not complete this request. Retry to continue.';
}
