/**
 * Xtream Gateway - Multi-Profile Xtream Codes & HLS Reverse Proxy
 * Licensed under the MIT License.
 */

const http = require('http');
const https = require('https');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { URL, URLSearchParams } = require('url');
const { pipeline } = require('stream');

const PROXY_PORT = parseInt(process.env.PORT || '8888', 10);
const DEFAULT_HOST = process.env.PROXY_HOST || 'viveentucoche.com';
const CDN_SECRET = process.env.CDN_SECRET || 'xtream_gateway_default_salt_2026';
function getProvidersFilePath() {
  return process.env.PROVIDERS_FILE || path.join(__dirname, 'providers.json');
}

// --- Provider Management & Live Hot-Reload ---
let cachedProviders = [];
let lastMtime = 0;
let lastFilePath = '';

function getProviders() {
  const filePath = getProvidersFilePath();
  try {
    if (fs.existsSync(filePath)) {
      const stat = fs.statSync(filePath);
      if (stat.mtimeMs !== lastMtime || filePath !== lastFilePath) {
        const raw = fs.readFileSync(filePath, 'utf8');
        cachedProviders = JSON.parse(raw);
        lastMtime = stat.mtimeMs;
        lastFilePath = filePath;
        console.log(`[CONFIG] Loaded ${cachedProviders.length} profile(s): ${cachedProviders.map(p => p.id || p.name).join(', ')}`);
      }
    }
  } catch (err) {
    console.error('[CONFIG ERROR]', err.message);
  }
  return cachedProviders;
}

getProviders();

// --- Rate Limiting & Anti-Scanner Shield ---
const failedAttempts = new Map(); // ip -> { count, blockedUntil }

function isIpBlocked(ip) {
  const record = failedAttempts.get(ip);
  if (!record) return false;
  if (record.blockedUntil && Date.now() < record.blockedUntil) return true;
  if (record.blockedUntil && Date.now() >= record.blockedUntil) {
    failedAttempts.delete(ip);
    return false;
  }
  return false;
}

function recordFailedAttempt(ip) {
  const now = Date.now();
  let record = failedAttempts.get(ip);
  if (!record) {
    record = { count: 1, firstSeen: now };
    failedAttempts.set(ip, record);
    return;
  }
  record.count++;
  if (record.count >= 15) {
    record.blockedUntil = now + 15 * 60 * 1000; // Block for 15 minutes
    console.warn(`[SECURITY] Blocked IP ${ip} for 15 minutes due to repeated unauthorized requests.`);
  }
}

// --- Cryptographic HMAC & Anti-SSRF Helpers ---
function getCdnToken(host) {
  return crypto.createHmac('sha256', CDN_SECRET).update(host).digest('hex').slice(0, 16);
}

function isPrivateHost(host) {
  if (!host) return true;
  const h = host.split(':')[0].toLowerCase();
  if (h === 'localhost' || h === '127.0.0.1' || h.startsWith('10.') || h.startsWith('192.168.')) return true;
  const match = h.match(/^172\.(\d+)\./);
  if (match) {
    const octet = parseInt(match[1], 10);
    if (octet >= 16 && octet <= 31) return true;
  }
  return false;
}

function setCorsHeaders(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, HEAD');
  res.setHeader('Access-Control-Allow-Headers', '*');
}

function getFwdUserAgent(req) {
  const ua = req.headers['user-agent'] || '';
  if (!ua || ua.includes('Python') || ua.includes('curl') || ua.includes('Wget')) {
    return 'VLC/3.0.18 LibVLC/3.0.18';
  }
  return ua;
}

function extractCredentials(req, postBody) {
  let user = null;
  let pass = null;
  const reqUrl = (req && req.url) || (typeof req === 'string' ? req : '');

  try {
    const parsed = new URL(reqUrl, 'http://localhost');
    user = parsed.searchParams.get('username') || parsed.searchParams.get('user');
    pass = parsed.searchParams.get('password') || parsed.searchParams.get('pass');
  } catch (_) {}

  if (!user || !pass) {
    const streamMatch = reqUrl.match(/^\/(?:live|movie|series)\/([^/]+)\/([^/]+)\//);
    if (streamMatch) {
      user = decodeURIComponent(streamMatch[1]);
      pass = decodeURIComponent(streamMatch[2]);
    }
  }

  if ((!user || !pass) && req && req.headers && req.headers['authorization']) {
    const authHeader = req.headers['authorization'];
    if (authHeader.startsWith('Basic ')) {
      try {
        const decoded = Buffer.from(authHeader.slice(6), 'base64').toString('utf8');
        const colonIdx = decoded.indexOf(':');
        if (colonIdx !== -1) {
          user = decoded.slice(0, colonIdx);
          pass = decoded.slice(colonIdx + 1);
        }
      } catch (_) {}
    }
  }

  if ((!user || !pass) && postBody) {
    try {
      const params = new URLSearchParams(postBody);
      if (params.has('username')) user = params.get('username');
      else if (params.has('user')) user = params.get('user');
      if (params.has('password')) pass = params.get('password');
      else if (params.has('pass')) pass = params.get('pass');
    } catch (_) {}
    if ((!user || !pass) && postBody.startsWith('{')) {
      try {
        const json = JSON.parse(postBody);
        if (json.username) user = json.username;
        else if (json.user) user = json.user;
        if (json.password) pass = json.password;
        else if (json.pass) pass = json.pass;
      } catch (_) {}
    }
  }

  return { user, pass };
}

function translateUrlAndBody(targetUrl, postBody, upstreamUser, upstreamPass) {
  let translatedUrl = targetUrl;
  let translatedBody = postBody;

  try {
    const u = new URL(targetUrl, 'http://localhost');
    let modified = false;
    for (const key of ['username', 'user']) {
      if (u.searchParams.has(key)) {
        u.searchParams.set(key, upstreamUser);
        modified = true;
      }
    }
    for (const key of ['password', 'pass']) {
      if (u.searchParams.has(key)) {
        u.searchParams.set(key, upstreamPass);
        modified = true;
      }
    }
    if (modified) {
      translatedUrl = u.pathname + u.search;
    }
  } catch (_) {}

  if (translatedBody) {
    try {
      const sp = new URLSearchParams(translatedBody);
      let modified = false;
      for (const key of ['username', 'user']) {
        if (sp.has(key)) {
          sp.set(key, upstreamUser);
          modified = true;
        }
      }
      for (const key of ['password', 'pass']) {
        if (sp.has(key)) {
          sp.set(key, upstreamPass);
          modified = true;
        }
      }
      if (modified) {
        translatedBody = sp.toString();
      }
    } catch (_) {}
  }

  return { translatedUrl, translatedBody };
}

function findProvider(user, pass) {
  if (!user || !pass) return null;
  const providers = getProviders();

  for (const p of providers) {
    // 1. Virtual client profile match
    if (p.clientUser && p.clientPass && p.clientUser === user && p.clientPass === pass) {
      const upUrl = (p.upstream && p.upstream.url) || p.upstream;
      const upUser = (p.upstream && p.upstream.user) || p.user;
      const upPass = (p.upstream && p.upstream.pass) || p.pass;
      return {
        matchedAs: 'virtual',
        profile: p,
        upstreamUrl: upUrl.replace(/\/+$/, ''),
        upstreamUser: upUser,
        upstreamPass: upPass,
        clientUser: p.clientUser,
        clientPass: p.clientPass,
      };
    }

    // 2. Direct upstream credentials match
    const upUser = (p.upstream && p.upstream.user) || p.user;
    const upPass = (p.upstream && p.upstream.pass) || p.pass;
    const upUrl = (p.upstream && p.upstream.url) || p.upstream;
    if (upUser === user && upPass === pass) {
      return {
        matchedAs: 'direct',
        profile: p,
        upstreamUrl: (upUrl || '').replace(/\/+$/, ''),
        upstreamUser: upUser,
        upstreamPass: upPass,
        clientUser: user,
        clientPass: pass,
      };
    }
  }

  return null;
}

// --- HTTP Server Core ---
const server = http.createServer((req, res) => {
  setCorsHeaders(res);

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  let postBody = '';
  if (req.method === 'POST') {
    req.on('data', chunk => {
      postBody += chunk.toString();
    });
    req.on('end', () => {
      handleRequest(req, res, postBody);
    });
  } else {
    handleRequest(req, res, null);
  }
});

function handleRequest(req, res, postBody) {
  const reqUrl = req.url || '';
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  if (isIpBlocked(clientIp)) {
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    res.end('403 Forbidden');
    return;
  }

  // 1. Signed CDN Chunk Streaming (/cdn/<token>/<host>/<path>)
  if (reqUrl.startsWith('/cdn/')) {
    const raw = reqUrl.slice('/cdn/'.length);
    const firstSlash = raw.indexOf('/');
    const secondSlash = raw.indexOf('/', firstSlash + 1);
    if (firstSlash === -1 || secondSlash === -1) {
      res.writeHead(400);
      res.end('Invalid CDN URL');
      return;
    }
    const token = raw.slice(0, firstSlash);
    const targetHost = raw.slice(firstSlash + 1, secondSlash);
    const targetPath = raw.slice(secondSlash);

    // Cryptographic token & SSRF validation
    if (isPrivateHost(targetHost) || token !== getCdnToken(targetHost)) {
      console.warn(`[SECURITY] Rejected unsigned/invalid CDN access from ${clientIp} for host ${targetHost}`);
      recordFailedAttempt(clientIp);
      res.writeHead(403);
      res.end('403 Forbidden');
      return;
    }

    const fwdHeaders = {
      'User-Agent': getFwdUserAgent(req),
      'Accept': req.headers['accept'] || '*/*',
    };
    if (req.headers['range']) fwdHeaders['Range'] = req.headers['range'];

    const upstreamReq = http.request(`http://${targetHost}${targetPath}`, {
      method: req.method,
      headers: fwdHeaders,
    }, (upstreamRes) => {
      setCorsHeaders(res);
      const resHeaders = { ...upstreamRes.headers };
      delete resHeaders['transfer-encoding'];
      res.writeHead(upstreamRes.statusCode, resHeaders);
      pipeline(upstreamRes, res, () => {});
    });

    upstreamReq.on('error', (err) => {
      console.error('[CDN ERROR]', err.message);
      if (!res.headersSent) res.writeHead(502);
      res.end('502 Bad Gateway');
    });

    if (postBody) upstreamReq.write(postBody);
    upstreamReq.end();
    return;
  }

  // 2. Authentication & Provider Resolution
  const { user, pass } = extractCredentials(req, postBody);
  const matched = findProvider(user, pass);

  if (!matched) {
    console.warn(`${new Date().toISOString()} [AUTH FAILED] [${clientIp}] ${req.method} ${reqUrl.slice(0, 100)} (user=${user || 'none'})`);
    recordFailedAttempt(clientIp);
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    res.end('403 Forbidden');
    return;
  }

  const { upstreamUrl, upstreamUser, upstreamPass, clientUser, clientPass, matchedAs } = matched;

  // 3. Media Streams (/live/, /movie/, /series/)
  if (reqUrl.startsWith('/live/') || reqUrl.startsWith('/movie/') || reqUrl.startsWith('/series/')) {
    let translatedPath = reqUrl;
    if (matchedAs === 'virtual') {
      translatedPath = reqUrl.replace(/^\/(live|movie|series)\/[^/]+\/[^/]+\//, `/$1/${encodeURIComponent(upstreamUser)}/${encodeURIComponent(upstreamPass)}/`);
    }

    const targetStreamUrl = `${upstreamUrl}${translatedPath}`;
    const fwdHeaders = {
      'User-Agent': getFwdUserAgent(req),
      'Accept': req.headers['accept'] || '*/*',
    };
    if (req.headers['range']) fwdHeaders['Range'] = req.headers['range'];
    if (req.headers['if-range']) fwdHeaders['If-Range'] = req.headers['if-range'];

    const streamClient = targetStreamUrl.startsWith('https://') ? https : http;
    const upstreamReq = streamClient.request(targetStreamUrl, {
      method: req.method,
      headers: fwdHeaders,
    }, (upstreamRes) => {
      // Follow 301, 302, 307, 308 redirects to ephemeral CDN servers
      if ([301, 302, 307, 308].includes(upstreamRes.statusCode) && upstreamRes.headers.location) {
        const locationUrl = new URL(upstreamRes.headers.location);
        const cdnHost = locationUrl.host;
        const cdnToken = getCdnToken(cdnHost);
        const cdnClient = locationUrl.protocol === 'https:' ? https : http;

        // HLS playlist: rewrite relative chunks to HMAC signed /cdn/<token>/<cdnHost>/...
        if (reqUrl.includes('.m3u8')) {
          cdnClient.get(locationUrl.href, {
            headers: { 'User-Agent': getFwdUserAgent(req) }
          }, (cdnRes) => {
            const chunks = [];
            cdnRes.on('data', c => chunks.push(c));
            cdnRes.on('end', () => {
              const body = Buffer.concat(chunks).toString('utf8');
              const rewritten = body.replace(/(\/hls\/[^\s\r\n]+)/g, (match) => `/cdn/${cdnToken}/${cdnHost}${match}`);
              res.writeHead(cdnRes.statusCode, {
                'Content-Type': cdnRes.headers['content-type'] || 'application/vnd.apple.mpegurl',
                'Content-Length': Buffer.byteLength(rewritten),
                'Access-Control-Allow-Origin': '*',
              });
              res.end(rewritten);
            });
          }).on('error', () => {
            if (!res.headersSent) res.writeHead(502);
            res.end('502 CDN Error');
          });
          return;
        }

        // Direct MPEG-TS / MP4 binary stream
        const cdnHeaders = { 'User-Agent': getFwdUserAgent(req) };
        if (req.headers['range']) cdnHeaders['Range'] = req.headers['range'];
        if (req.headers['if-range']) cdnHeaders['If-Range'] = req.headers['if-range'];

        cdnClient.get(locationUrl.href, { headers: cdnHeaders }, (cdnRes) => {
          setCorsHeaders(res);
          const outHeaders = { ...cdnRes.headers };
          delete outHeaders['transfer-encoding'];
          res.writeHead(cdnRes.statusCode, outHeaders);
          pipeline(cdnRes, res, () => {});
        }).on('error', (err) => {
          console.error('[STREAM ERROR]', err.message);
          if (!res.headersSent) res.writeHead(502);
          res.end('502 CDN Error');
        });
        return;
      }

      // Direct upstream stream (without 302 redirect)
      setCorsHeaders(res);
      const outHeaders = { ...upstreamRes.headers };
      delete outHeaders['transfer-encoding'];
      res.writeHead(upstreamRes.statusCode, outHeaders);
      pipeline(upstreamRes, res, () => {});
    });

    upstreamReq.on('error', (err) => {
      console.error('[UPSTREAM STREAM ERROR]', err.message);
      if (!res.headersSent) res.writeHead(502);
      res.end('502 Bad Gateway');
    });

    upstreamReq.end();
    return;
  }

  // 4. Xtream Codes Client API (/player_api.php or /panel_api.php)
  if (reqUrl.startsWith('/player_api.php') || reqUrl.startsWith('/panel_api.php')) {
    const { translatedUrl, translatedBody } = (matchedAs === 'virtual')
      ? translateUrlAndBody(reqUrl, postBody, upstreamUser, upstreamPass)
      : { translatedUrl: reqUrl, translatedBody: postBody };

    let parsedUrl;
    try {
      parsedUrl = new URL(reqUrl, 'http://localhost');
    } catch (_) {
      parsedUrl = { searchParams: new URLSearchParams() };
    }
    const action = parsedUrl.searchParams.get('action');
    const isLoginInfo = !action || ['get_account_info', 'get_profile'].includes(action);

    const fwdHeaders = {
      'User-Agent': getFwdUserAgent(req),
      'Accept': req.headers['accept'] || '*/*',
    };
    if (translatedBody) {
      fwdHeaders['Content-Type'] = req.headers['content-type'] || 'application/x-www-form-urlencoded';
      fwdHeaders['Content-Length'] = Buffer.byteLength(translatedBody);
    }

    const apiClient = upstreamUrl.startsWith('https://') ? https : http;
    const upstreamReq = apiClient.request(`${upstreamUrl}${translatedUrl}`, {
      method: req.method,
      headers: fwdHeaders,
    }, (upstreamRes) => {
      setCorsHeaders(res);

      if (isLoginInfo) {
        const chunks = [];
        upstreamRes.on('data', c => chunks.push(c));
        upstreamRes.on('end', () => {
          const isHttps = req.headers['x-forwarded-proto'] === 'https';
          const hostHeader = (req.headers['host'] || '').split(':')[0] || DEFAULT_HOST;
          const hostUrl = hostHeader || DEFAULT_HOST || '127.0.0.1';
          const hostPort = isHttps ? '443' : String(PROXY_PORT);
          const proto = isHttps ? 'https' : 'http';

          let body = Buffer.concat(chunks).toString('utf8');
          body = body.replace(/"url"\s*:\s*"[^"]+"/g, `"url":"${hostUrl}"`);
          body = body.replace(/"port"\s*:\s*"\d+"/g, `"port":"${hostPort}"`);
          body = body.replace(/"server_protocol"\s*:\s*"[^"]+"/g, `"server_protocol":"${proto}"`);

          if (matchedAs === 'virtual') {
            body = body.replace(new RegExp(`"username"\\s*:\\s*"${upstreamUser}"`, 'g'), `"username":"${clientUser}"`);
            body = body.replace(new RegExp(`"password"\\s*:\\s*"${upstreamPass}"`, 'g'), `"password":"${clientPass}"`);
          }

          res.writeHead(upstreamRes.statusCode, {
            'Content-Type': 'application/json; charset=utf-8',
            'Content-Length': Buffer.byteLength(body),
            'Access-Control-Allow-Origin': '*',
          });
          res.end(body);
        });
      } else {
        // High-speed catalog & EPG streaming
        const outHeaders = { ...upstreamRes.headers };
        delete outHeaders['transfer-encoding'];
        res.writeHead(upstreamRes.statusCode, outHeaders);
        pipeline(upstreamRes, res, () => {});
      }
    });

    upstreamReq.on('error', (err) => {
      console.error('[API UPSTREAM ERROR]', err.message);
      if (!res.headersSent) res.writeHead(502);
      res.end('502 Bad Gateway');
    });

    if (translatedBody) upstreamReq.write(translatedBody);
    upstreamReq.end();
    return;
  }

  // 5. Fallback Pass-through (/xmltv.php, /epg.php, /get.php, icons, etc.)
  const { translatedUrl, translatedBody } = (matchedAs === 'virtual')
    ? translateUrlAndBody(reqUrl, postBody, upstreamUser, upstreamPass)
    : { translatedUrl: reqUrl, translatedBody: postBody };

  let upstreamHost = 'localhost';
  try {
    upstreamHost = new URL(upstreamUrl).host;
  } catch (_) {}

  const fwdHeaders = { ...req.headers };
  delete fwdHeaders['host'];
  fwdHeaders['host'] = upstreamHost;
  fwdHeaders['user-agent'] = getFwdUserAgent(req);

  if (translatedBody) {
    fwdHeaders['content-length'] = Buffer.byteLength(translatedBody);
  }

  const fallbackClient = upstreamUrl.startsWith('https://') ? https : http;
  const upstreamReq = fallbackClient.request(`${upstreamUrl}${translatedUrl}`, {
    method: req.method,
    headers: fwdHeaders,
  }, (upstreamRes) => {
    // Transparently follow redirects (e.g. 302 to external CDN or S3)
    if ([301, 302, 307, 308].includes(upstreamRes.statusCode) && upstreamRes.headers.location) {
      try {
        const redirectUrl = new URL(upstreamRes.headers.location, upstreamUrl);
        const redirectClient = redirectUrl.protocol === 'https:' ? https : http;
        const redirectHeaders = { ...fwdHeaders };
        redirectHeaders['host'] = redirectUrl.host;

        const redirectReq = redirectClient.request(redirectUrl.href, {
          method: req.method === 'POST' ? 'GET' : req.method,
          headers: redirectHeaders,
        }, (redirectRes) => {
          setCorsHeaders(res);
          const outHeaders = { ...redirectRes.headers };
          delete outHeaders['transfer-encoding'];
          res.writeHead(redirectRes.statusCode, outHeaders);
          pipeline(redirectRes, res, () => {});
        });

        redirectReq.on('error', (err) => {
          console.error('[FALLBACK REDIRECT ERROR]', err.message);
          if (!res.headersSent) res.writeHead(502);
          res.end('502 Bad Gateway');
        });

        redirectReq.end();
        return;
      } catch (err) {
        console.error('[REDIRECT PARSE ERROR]', err.message);
      }
    }

    // Special handling for M3U playlist generation (/get.php)
    if (reqUrl.startsWith('/get.php') && upstreamRes.statusCode === 200) {
      const chunks = [];
      upstreamRes.on('data', c => chunks.push(c));
      upstreamRes.on('end', () => {
        const isHttps = req.headers['x-forwarded-proto'] === 'https';
        const hostHeader = (req.headers['host'] || '').split(':')[0] || DEFAULT_HOST;
        const hostUrl = hostHeader || DEFAULT_HOST || '127.0.0.1';
        const hostPort = isHttps ? '443' : String(PROXY_PORT);
        const proto = isHttps ? 'https' : 'http';
        const gatewayOrigin = `${proto}://${hostUrl}${((isHttps && hostPort === '443') || (!isHttps && hostPort === '80')) ? '' : ':' + hostPort}`;

        let body = Buffer.concat(chunks).toString('utf8');
        const upOrigin = upstreamUrl.replace(/\/+$/, '');
        if (matchedAs === 'virtual') {
          const streamRegex = new RegExp(`${upOrigin}(?::\\d+)?/(live|movie|series)/${upstreamUser}/${upstreamPass}/`, 'g');
          body = body.replace(streamRegex, `${gatewayOrigin}/$1/${clientUser}/${clientPass}/`);
          const epgRegex = new RegExp(`${upOrigin}(?::\\d+)?/xmltv\\.php\\?[^"'\r\n\s]+`, 'g');
          body = body.replace(epgRegex, `${gatewayOrigin}/xmltv.php?username=${clientUser}&password=${clientPass}`);
        } else {
          body = body.replace(new RegExp(`${upOrigin}(?::\\d+)?`, 'g'), gatewayOrigin);
        }

        setCorsHeaders(res);
        res.writeHead(upstreamRes.statusCode, {
          'Content-Type': upstreamRes.headers['content-type'] || 'audio/x-mpegurl',
          'Content-Length': Buffer.byteLength(body),
          'Access-Control-Allow-Origin': '*',
        });
        res.end(body);
      });
      return;
    }

    setCorsHeaders(res);
    const outHeaders = { ...upstreamRes.headers };
    delete outHeaders['transfer-encoding'];
    res.writeHead(upstreamRes.statusCode, outHeaders);
    pipeline(upstreamRes, res, () => {});
  });

  upstreamReq.on('error', (err) => {
    console.error('[FALLBACK ERROR]', err.message);
    if (!res.headersSent) res.writeHead(502);
    res.end('502 Bad Gateway');
  });

  if (translatedBody) upstreamReq.write(translatedBody);
  upstreamReq.end();
}

if (require.main === module) {
  server.listen(PROXY_PORT, '0.0.0.0', () => {
    console.log(`Xtream Gateway listening on 0.0.0.0:${PROXY_PORT}`);
  });
}

module.exports = {
  server,
  extractCredentials,
  findProvider,
  getProviders,
  translateUrlAndBody,
  getCdnToken,
  isPrivateHost,
  getFwdUserAgent,
};
