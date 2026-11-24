
const ISSUER = 'https://young-cake-3c68.cloudflareaccess.com';
const AUD = '98b3f2121188cea4d91cb5bc31de503849cb5963abd8a25d1cb8433a6556db6d';

const response = (status, error, retry) =>
  Response.json({ error }, {
    status,
    headers: {
      'Cache-Control': 'no-store',
      ...(retry ? {'Retry-After': String(retry)} : {})
    }
  });

let cachedKeys = [];
let keysExpire = 0;

function decodeBase64Url(value) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw Error('invalid token');
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  return Uint8Array.from(
    atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, '=')),
    c => c.charCodeAt(0)
  );
}

async function getKey(kid) {
  if (Date.now() >= keysExpire || !cachedKeys.some(k => k.kid === kid)) {
    const r = await fetch(ISSUER + '/cdn-cgi/access/certs', {
      signal: AbortSignal.timeout(5000),
      redirect: 'error'
    });

    if (!r.ok) throw Error('keys unavailable');

    const data = await r.json();
    if (!Array.isArray(data.keys)) throw Error('invalid keys');

    cachedKeys = data.keys;
    keysExpire = Date.now() + 300000;
  }

  return cachedKeys.find(k =>
    k.kid === kid &&
    k.kty === 'RSA' &&
    k.alg === 'RS256'
  );
}

async function verifyAccess(request) {
  const cookies = request.headers.get('Cookie') || '';
  const cookie = cookies.match(/(?:^|;\s*)CF_Authorization=([^;]+)/);

  const token =
    request.headers.get('Cf-Access-Jwt-Assertion') ||
    cookie?.[1];

  if (!token || token.length > 16384) return false;

  try {
    const parts = token.split('.');
    if (parts.length !== 3) return false;

    const decoder = new TextDecoder();
    const header = JSON.parse(decoder.decode(decodeBase64Url(parts[0])));
    const payload = JSON.parse(decoder.decode(decodeBase64Url(parts[1])));

    const now = Math.floor(Date.now() / 1000);

    if (header.alg !== 'RS256' || typeof header.kid !== 'string') return false;
    if (typeof payload.iss !== 'string' ||     payload.iss.replace(/\/+$/, '') !== ISSUER) {   console.warn('Access JWT: issuer mismatch');   return false; }
    if (!Array.isArray(payload.aud) || !payload.aud.includes(AUD)) return false;
    if (!Number.isFinite(payload.exp) || payload.exp <= now) return false;
    if (payload.nbf !== undefined && (!Number.isFinite(payload.nbf) || payload.nbf > now)) return false;
    if (typeof payload.email !== 'string' || !payload.email) return false;

    const jwk = await getKey(header.kid);
    if (!jwk) return false;

    const key = await crypto.subtle.importKey(
      'jwk',
      jwk,
      {
        name: 'RSASSA-PKCS1-v1_5',
        hash: 'SHA-256'
      },
      false,
      ['verify']
    );

    return await crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5',
      key,
      decodeBase64Url(parts[2]),
      new TextEncoder().encode(parts[0] + '.' + parts[1])
    );
  } catch {
    return false;
  }
}

async function consume(db, key, limit, seconds) {
  const now = Math.floor(Date.now() / 1000);

  const row = await db.prepare(`
    INSERT INTO rate_limits(key, attempts, expires_at)
    VALUES(?, 1, ?)
    ON CONFLICT(key) DO UPDATE SET
      attempts = CASE
        WHEN expires_at <= ? THEN 1
        ELSE MIN(attempts + 1, ?)
      END,
      expires_at = CASE
        WHEN expires_at <= ? THEN excluded.expires_at
        ELSE expires_at
      END
    RETURNING attempts, expires_at
  `).bind(
    key, now + seconds, now, limit + 1, now
  ).first();

  if (!row) throw Error('rate limit unavailable');

  return row.attempts > limit
    ? Math.max(1, row.expires_at - now)
    : 0;
}

export async function onRequest(c) {
  const path = new URL(c.request.url).pathname.replace(/\/+$/, '');
  const method = c.request.method;

  const checkout =
    path === '/api/orders' && method === 'POST';

  const admin =
    (path === '/api/orders' &&
      ['GET', 'PATCH', 'DELETE', 'HEAD'].includes(method)) ||
    (path === '/api/products' && method === 'PUT') ||
    (path === '/api/product-image' && method === 'POST') ||
    (path === '/api/receipt' &&
      ['GET', 'HEAD'].includes(method));

  if (!checkout && !admin) return c.next();

  try {
    const ip = c.request.headers.get('CF-Connecting-IP');

    if (!ip) return response(503, 'security unavailable');

    const key = Array.from(
      new Uint8Array(
        await crypto.subtle.digest(
          'SHA-256',
          new TextEncoder().encode(ip)
        )
      )
    ).map(x => x.toString(16).padStart(2, '0')).join('');

    if (admin) {
      if (!c.env.ADMIN_PASSWORD) {
        return response(503, 'security unavailable');
      }

      if (new URL(c.request.url).hostname !== 'retart-art.pages.dev') {
        return response(403, 'access denied');
      }

      if (!(await verifyAccess(c.request))) {
        return response(403, 'cloudflare access required');
      }

      const now = Math.floor(Date.now() / 1000);

      const row = await c.env.DB.prepare(
        'SELECT attempts, expires_at FROM rate_limits WHERE key=?'
      ).bind('admin:' + key).first();

      if (row && row.attempts >= 5 && row.expires_at > now) {
        return response(
          429,
          'too many attempts',
          row.expires_at - now
        );
      }

      if (
        c.request.headers.get('Authorization') !==
        'Bearer ' + c.env.ADMIN_PASSWORD
      ) {
        const retry = await consume(
          c.env.DB, 'admin:' + key, 5, 900
        );

        return retry
          ? response(429, 'too many attempts', retry)
          : response(401, 'unauthorized');
      }
    } else {
      const retry = await consume(
        c.env.DB, 'checkout:' + key, 5, 60
      );

      if (retry) {
        return response(429, 'too many requests', retry);
      }
    }

    if (Math.random() < 0.02) {
      c.waitUntil(
        c.env.DB.prepare(
          'DELETE FROM rate_limits WHERE expires_at <= ?'
        ).bind(
          Math.floor(Date.now() / 1000)
        ).run().catch(() => {})
      );
    }
  } catch {
    return response(503, 'security unavailable');
  }

  return c.next();
}
