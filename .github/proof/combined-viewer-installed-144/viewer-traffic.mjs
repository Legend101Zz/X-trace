import assert from 'node:assert/strict';

// Install after the journey's original guards, before navigation. Allowed
// requests still pass through the earlier token, origin and cleanup checks.
export async function guardViewerWrites(context, origin, allowExport = false) {
  const posts = new Set(['/api/v1/auth/exchange']);
  if (allowExport) {
    posts.add('/api/v1/exports/preview');
    posts.add('/api/v1/exports/save');
  }
  let refused = 0;
  await context.route('**/*', async route => {
    const request = route.request();
    const url = new URL(request.url());
    const method = request.method();
    if (url.origin === origin && (method === 'GET' || method === 'HEAD' ||
        (method === 'POST' && posts.has(url.pathname) && !url.search))) {
      await route.fallback();
    } else {
      refused++;
      await route.abort();
    }
  });
  const close = context.close.bind(context);
  context.close = async (...args) => {
    await close(...args);
    assert.equal(refused, 0, 'viewer requested a destination or method outside the journey');
  };
}
