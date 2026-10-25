const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const {
  extractCredentials,
  translateUrlAndBody,
  rewriteM3u8Playlist,
  findProvider,
  parseHlsSegments,
  normalizeHlsPlaylist,
  hlsLiveSessions,
  server,
} = require('../server.js');

test('extractCredentials handles all authentication mechanisms', (t) => {
  // Query params username/password
  assert.deepStrictEqual(
    extractCredentials({ url: '/xmltv.php?username=myuser&password=mypass' }, null),
    { user: 'myuser', pass: 'mypass' }
  );

  // Query params user/pass
  assert.deepStrictEqual(
    extractCredentials({ url: '/xmltv.php?user=myuser&pass=mypass' }, null),
    { user: 'myuser', pass: 'mypass' }
  );

  // Stream path (/live/USER/PASS/...)
  assert.deepStrictEqual(
    extractCredentials({ url: '/live/streamuser/streampass/12345.ts' }, null),
    { user: 'streamuser', pass: 'streampass' }
  );

  // Basic Auth header
  const basicAuth = 'Basic ' + Buffer.from('basicuser:basicpass').toString('base64');
  assert.deepStrictEqual(
    extractCredentials({ url: '/xmltv.php', headers: { authorization: basicAuth } }, null),
    { user: 'basicuser', pass: 'basicpass' }
  );

  // POST body (URLSearchParams)
  assert.deepStrictEqual(
    extractCredentials({ url: '/player_api.php' }, 'username=bodyuser&password=bodypass'),
    { user: 'bodyuser', pass: 'bodypass' }
  );

  // POST body (JSON)
  assert.deepStrictEqual(
    extractCredentials({ url: '/player_api.php' }, JSON.stringify({ username: 'jsonuser', password: 'jsonpass' })),
    { user: 'jsonuser', pass: 'jsonpass' }
  );
});

test('translateUrlAndBody rewrites credentials while preserving other parameters', (t) => {
  const result = translateUrlAndBody(
    '/xmltv.php?username=virtualUser&password=virtualPass&next_days=7&type=m3u_plus',
    null,
    'realUpstreamUser',
    'realUpstreamPass'
  );

  const parsed = new URL(result.translatedUrl, 'http://localhost');
  assert.strictEqual(parsed.pathname, '/xmltv.php');
  assert.strictEqual(parsed.searchParams.get('username'), 'realUpstreamUser');
  assert.strictEqual(parsed.searchParams.get('password'), 'realUpstreamPass');
  assert.strictEqual(parsed.searchParams.get('next_days'), '7');
  assert.strictEqual(parsed.searchParams.get('type'), 'm3u_plus');

  // Also handles user/pass parameter names
  const altResult = translateUrlAndBody(
    '/epg.php?user=virtualUser&pass=virtualPass',
    null,
    'realUpstreamUser',
    'realUpstreamPass'
  );
  const altParsed = new URL(altResult.translatedUrl, 'http://localhost');
  assert.strictEqual(altParsed.searchParams.get('user'), 'realUpstreamUser');
  assert.strictEqual(altParsed.searchParams.get('pass'), 'realUpstreamPass');
});

test('rewriteM3u8Playlist rewrites relative, absolute and full-URL segments to HMAC signed /cdn/...', (t) => {
  const locationUrl = new URL('http://cdn.example.com/live/play/token/12345');
  const playlist = `#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:10
#EXTINF:10.0,
/hls/abc/1.ts
#EXTINF:10.0,
http://other-cdn.example.com/hls/abc/2.ts
#EXTINF:10.0,
segment3.ts
#EXT-X-KEY:METHOD=AES-128,URI="http://cdn.example.com/key.bin"`;

  const rewritten = rewriteM3u8Playlist(playlist, locationUrl);
  assert.match(rewritten, /^\/cdn\/[0-9a-f]{16}\/cdn\.example\.com\/hls\/abc\/1\.ts$/m);
  assert.match(rewritten, /^\/cdn\/[0-9a-f]{16}\/other-cdn\.example\.com\/hls\/abc\/2\.ts$/m);
  assert.match(rewritten, /^\/cdn\/[0-9a-f]{16}\/cdn\.example\.com\/live\/play\/token\/segment3\.ts$/m);
  assert.match(rewritten, /URI="\/cdn\/[0-9a-f]{16}\/cdn\.example\.com\/key\.bin"/);
});

test('EPG download end-to-end integration via proxy', async (t) => {
  // 1. Create a mock upstream server
  let upstreamPort;
  const mockUpstream = http.createServer((req, res) => {
    const parsed = new URL(req.url, 'http://localhost');
    const u = parsed.searchParams.get('username') || parsed.searchParams.get('user');
    const p = parsed.searchParams.get('password') || parsed.searchParams.get('pass');

    if (u === 'real_up_user' && p === 'real_up_pass') {
      if (parsed.pathname === '/xmltv.php') {
        res.writeHead(200, { 'Content-Type': 'application/xml; charset=utf-8' });
        res.end('<?xml version="1.0"?><tv><channel id="test"><display-name>Test</display-name></channel></tv>');
        return;
      }
      if (parsed.pathname === '/get.php') {
        res.writeHead(200, { 'Content-Type': 'audio/x-mpegurl' });
        res.end(
          `#EXTM3U url-tvg="http://127.0.0.1:${upstreamPort}/xmltv.php?username=real_up_user&password=real_up_pass"\n` +
          '#EXTINF:-1,Test Channel\n' +
          `http://127.0.0.1:${upstreamPort}/live/real_up_user/real_up_pass/100.ts\n`
        );
        return;
      }
    }

    res.writeHead(513, { 'Content-Type': 'text/plain' });
    res.end('Auth failed upstream');
  });

  await new Promise((resolve) => mockUpstream.listen(0, '127.0.0.1', () => resolve()));
  upstreamPort = mockUpstream.address().port;

  // 2. Start proxy server
  const fs = require('fs');
  const path = require('path');
  const tmpProvidersPath = path.join(__dirname, 'tmp_providers.json');
  fs.writeFileSync(tmpProvidersPath, JSON.stringify([
    {
      id: 'test-virt',
      clientUser: 'client_virt',
      clientPass: 'virt_pass',
      upstream: {
        url: `http://127.0.0.1:${upstreamPort}`,
        user: 'real_up_user',
        pass: 'real_up_pass',
      }
    }
  ]));

  process.env.PROVIDERS_FILE = tmpProvidersPath;
  const { getProviders } = require('../server.js');
  getProviders(); // reload providers

  await new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
  const proxyPort = server.address().port;

  try {
    // 3. Request EPG (/xmltv.php) with virtual credentials through gateway
    const epgRes = await new Promise((resolve, reject) => {
      http.get(`http://127.0.0.1:${proxyPort}/xmltv.php?username=client_virt&password=virt_pass`, (res) => {
        let body = '';
        res.on('data', chunk => body += chunk);
        res.on('end', () => resolve({ statusCode: res.statusCode, headers: res.headers, body }));
      }).on('error', reject);
    });

    assert.strictEqual(epgRes.statusCode, 200);
    assert.match(epgRes.headers['content-type'], /application\/xml/);
    assert.match(epgRes.body, /<tv><channel id="test">/);

    // 4. Request /get.php (M3U playlist) through gateway
    const m3uRes = await new Promise((resolve, reject) => {
      http.get(`http://127.0.0.1:${proxyPort}/get.php?username=client_virt&password=virt_pass`, (res) => {
        let body = '';
        res.on('data', chunk => body += chunk);
        res.on('end', () => resolve({ statusCode: res.statusCode, body }));
      }).on('error', reject);
    });

    assert.strictEqual(m3uRes.statusCode, 200);
    assert.match(m3uRes.body, /xmltv\.php\?username=client_virt&password=virt_pass/);
    assert.match(m3uRes.body, /\/live\/client_virt\/virt_pass\/100\.ts/);

    // 5. Test invalid virtual credentials
    const badRes = await new Promise((resolve, reject) => {
      http.get(`http://127.0.0.1:${proxyPort}/xmltv.php?username=invalid&password=wrong`, (res) => {
        resolve({ statusCode: res.statusCode });
      }).on('error', reject);
    });
    assert.strictEqual(badRes.statusCode, 403);

  } finally {
    mockUpstream.close();
    server.close();
    if (fs.existsSync(tmpProvidersPath)) fs.unlinkSync(tmpProvidersPath);
  }
});

test('parseHlsSegments extracts header lines, segments and sequence number', (t) => {
  const m3u8 = `#EXTM3U
#EXT-X-VERSION:3
#EXT-X-MEDIA-SEQUENCE:500
#EXT-X-TARGETDURATION:10
#EXTINF:10.0,
segment_500.ts
#EXTINF:10.0,
segment_501.ts`;

  const parsed = parseHlsSegments(m3u8);
  assert.strictEqual(parsed.mediaSequence, 500);
  assert.strictEqual(parsed.segments.length, 2);
  assert.match(parsed.segments[0][0], /#EXTINF:10\.0/);
  assert.match(parsed.segments[0][1], /segment_500\.ts/);
  assert.match(parsed.segments[1][1], /segment_501\.ts/);
});

test('normalizeHlsPlaylist protects against sequence regression across CDN edges', (t) => {
  const session = {
    lastMediaSequence: 502,
    lastRewrittenBody: 'FALLBACK_BODY',
  };

  // Upstream edge returns regressed sequence (500 instead of 502)
  const regressedM3u8 = `#EXTM3U
#EXT-X-VERSION:3
#EXT-X-MEDIA-SEQUENCE:500
#EXT-X-TARGETDURATION:10
#EXTINF:10.0,
segment_500.ts
#EXTINF:10.0,
segment_501.ts
#EXTINF:10.0,
segment_502.ts
#EXTINF:10.0,
segment_503.ts`;

  const normalized = normalizeHlsPlaylist(regressedM3u8, session);
  assert.strictEqual(normalized.sequence, 502);
  assert.strictEqual(normalized.useLastBody, false);
  // Segments 500 and 501 were dropped, starts at 502
  assert.match(normalized.body, /#EXT-X-MEDIA-SEQUENCE:502/);
  assert.ok(!normalized.body.includes('segment_500.ts'), 'segment_500 should be dropped');
  assert.ok(!normalized.body.includes('segment_501.ts'), 'segment_501 should be dropped');
  assert.ok(normalized.body.includes('segment_502.ts'), 'segment_502 should be present');
  assert.ok(normalized.body.includes('segment_503.ts'), 'segment_503 should be present');

  // If new edge is completely lagged behind (all segments older than 505)
  const completelyLagged = `#EXTM3U
#EXT-X-VERSION:3
#EXT-X-MEDIA-SEQUENCE:500
#EXT-X-TARGETDURATION:10
#EXTINF:10.0,
segment_500.ts`;
  session.lastMediaSequence = 505;
  const laggedResult = normalizeHlsPlaylist(completelyLagged, session);
  assert.strictEqual(laggedResult.useLastBody, true);
});

test('HLS live stream sticky edge and monotonic playback end-to-end', async (t) => {
  let edgeRequests = 0;
  let upstreamRequests = 0;
  let edgePort;

  // 1. Mock CDN Edge Server
  const mockEdge = http.createServer((req, res) => {
    edgeRequests++;
    res.writeHead(200, { 'Content-Type': 'application/x-mpegURL' });
    res.end(
      '#EXTM3U\n' +
      '#EXT-X-VERSION:3\n' +
      '#EXT-X-MEDIA-SEQUENCE:100\n' +
      '#EXT-X-TARGETDURATION:10\n' +
      '#EXTINF:10.0,\n' +
      'seg_100.ts\n' +
      '#EXTINF:10.0,\n' +
      'seg_101.ts\n'
    );
  });
  await new Promise(r => mockEdge.listen(0, '127.0.0.1', r));
  edgePort = mockEdge.address().port;

  // 2. Mock Upstream Balancer
  const mockUpstream = http.createServer((req, res) => {
    upstreamRequests++;
    res.writeHead(302, {
      'Location': `http://127.0.0.1:${edgePort}/live/play/tok123/9999.m3u8`,
    });
    res.end();
  });
  await new Promise(r => mockUpstream.listen(0, '127.0.0.1', r));
  const upstreamPort = mockUpstream.address().port;

  // 3. Setup temporary providers config
  const fs = require('fs');
  const path = require('path');
  const tmpProvidersPath = path.join(__dirname, 'tmp_hls_providers.json');
  fs.writeFileSync(tmpProvidersPath, JSON.stringify([
    {
      id: 'hls-test',
      clientUser: 'tv_user',
      clientPass: 'tv_pass',
      upstream: {
        url: `http://127.0.0.1:${upstreamPort}`,
        user: 'real_hls_user',
        pass: 'real_hls_pass',
      }
    }
  ]));

  process.env.PROVIDERS_FILE = tmpProvidersPath;
  const { getProviders } = require('../server.js');
  getProviders();

  await new Promise(r => server.listen(0, '127.0.0.1', r));
  const proxyPort = server.address().port;

  try {
    // 4. First HLS poll: hits upstream (302) -> hits edge (200) -> establishes sticky affinity
    const poll1 = await new Promise((resolve, reject) => {
      http.get(`http://127.0.0.1:${proxyPort}/live/tv_user/tv_pass/9999.m3u8`, (res) => {
        let b = '';
        res.on('data', c => b += c);
        res.on('end', () => resolve({ status: res.statusCode, body: b }));
      }).on('error', reject);
    });

    assert.strictEqual(poll1.status, 200);
    assert.match(poll1.body, /#EXT-X-MEDIA-SEQUENCE:100/);
    assert.match(poll1.body, /\/cdn\/[0-9a-f]{16}\/127\.0\.0\.1/);
    assert.strictEqual(upstreamRequests, 1);
    assert.strictEqual(edgeRequests, 1);

    // Wait slightly so burst cache doesn't kick in, but sticky edge is used
    await new Promise(r => setTimeout(r, 1300));

    // 5. Second HLS poll: sticky affinity should hit edge directly, skipping upstream!
    const poll2 = await new Promise((resolve, reject) => {
      http.get(`http://127.0.0.1:${proxyPort}/live/tv_user/tv_pass/9999.m3u8`, (res) => {
        let b = '';
        res.on('data', c => b += c);
        res.on('end', () => resolve({ status: res.statusCode, body: b }));
      }).on('error', reject);
    });

    assert.strictEqual(poll2.status, 200);
    assert.match(poll2.body, /#EXT-X-MEDIA-SEQUENCE:100/);
    // Crucial check: upstreamRequests must still be 1 (bypassed upstream load-balancer!)
    assert.strictEqual(upstreamRequests, 1);
    // Edge requests increased to 2
    assert.strictEqual(edgeRequests, 2);

  } finally {
    mockEdge.close();
    mockUpstream.close();
    server.close();
    if (fs.existsSync(tmpProvidersPath)) fs.unlinkSync(tmpProvidersPath);
  }
});
