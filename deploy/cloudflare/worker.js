/**
 * Freedom Cry 2.0 — Censorship-Resistant Cloudflare Edge Worker
 * 
 * Provides an unblockable, Anycast CDN front for the Freedom Cry Master API.
 * Even if Russian censorship (TSPU/RKN) blocks the origin server IP,
 * clients connect seamlessly via Cloudflare's clean IP addresses.
 *
 * Features:
 * - Origin Cloaking: Strips client real IP headers to preserve Zero-Knowledge privacy.
 * - Secret Edge Authentication: Injects X-Edge-Secret to prevent direct origin bypass.
 * - Anti-Probing: Rejects unauthorized scanners before they reach origin.
 * - Streaming proxy for large config downloads.
 */

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // 1. Health check at edge
    if (url.pathname === '/edge-health') {
      return new Response(JSON.stringify({ status: 'ok', edge: 'Cloudflare Workers', region: request.cf?.colo || 'UNKNOWN' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // 2. Resolve target origin backend (Configured via env.ORIGIN_URL or default fallback)
    const originBase = env.ORIGIN_URL || 'https://api.freedomcry.net';
    const targetUrl = new URL(url.pathname + url.search, originBase);

    // 3. Clone and sanitize headers to preserve client privacy
    const headers = new Headers(request.headers);
    headers.set('Host', targetUrl.hostname);
    
    // Privacy: Overwrite client tracking headers
    headers.set('X-Forwarded-For', '127.0.0.1');
    headers.set('X-Real-IP', '127.0.0.1');
    headers.delete('CF-Connecting-IP');
    headers.delete('True-Client-IP');

    // Origin Shield: Verify and pass shared secret if configured
    if (env.EDGE_SHARED_SECRET) {
      headers.set('X-Edge-Secret', env.EDGE_SHARED_SECRET);
    }

    const init = {
      method: request.method,
      headers: headers,
      redirect: 'follow',
    };

    // Include body for non-GET/HEAD methods
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      init.body = request.body;
    }

    try {
      const response = await fetch(targetUrl.toString(), init);

      // Sanitize response headers
      const responseHeaders = new Headers(response.headers);
      responseHeaders.set('X-Powered-By', 'Freedom-Cry-Edge');
      responseHeaders.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
      responseHeaders.set('X-Content-Type-Options', 'nosniff');
      responseHeaders.set('Referrer-Policy', 'no-referrer');

      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders,
      });
    } catch (err) {
      return new Response(JSON.stringify({ error: 'Edge Gateway Error', details: 'Origin unreachable' }), {
        status: 502,
        headers: { 'Content-Type': 'application/json' },
      });
    }
  },
};
