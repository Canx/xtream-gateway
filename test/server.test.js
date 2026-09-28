const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const { extractCredentials, translateUrlAndBody, findProvider, server } = require('../server.js');

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
