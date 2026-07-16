/*
 * 사업소 장기미납세대 현황 보고 시스템 - 백엔드(Cloudflare Worker)
 *
 * 이 파일은 브라우저(정적 사이트)와 GitHub 저장소 사이의 유일한 중개자입니다.
 * GitHub에 쓰기 권한이 있는 토큰은 이 Worker의 환경변수(Secret)에만 저장되고,
 * 브라우저에는 절대 전달되지 않습니다. 브라우저는 이 Worker가 제공하는
 * HTTP API만 호출합니다.
 *
 * 데이터는 이 저장소의 `data/` 폴더 아래 JSON 파일로 저장됩니다.
 *   data/users.json                    - 계정 목록 (아이디, 비밀번호 해시, 역할, 소속 사업소)
 *   data/sites/{siteId}/reports.json   - 사업소별 "장기미납세대 현황" 보고 이력
 *   data/notices.json                  - 본사 → 사업소 지시사항/공지 목록
 *
 * 필요한 환경변수(Secret/Var)는 server/README.md 를 참고하세요.
 */

const JSON_HEADERS = { 'Content-Type': 'application/json; charset=utf-8' };

function corsHeaders(env) {
  return {
    'Access-Control-Allow-Origin': env.ALLOWED_ORIGIN || '*',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  };
}

function jsonResponse(env, data, status) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: Object.assign({}, JSON_HEADERS, corsHeaders(env)),
  });
}

function errorResponse(env, message, status) {
  return jsonResponse(env, { error: message }, status || 400);
}

/* ---------- base64url / crypto 유틸 ---------- */

function bytesToBase64Url(bytes) {
  var bin = '';
  for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function base64UrlToBytes(b64url) {
  var b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';
  var bin = atob(b64);
  var bytes = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
function utf8ToBytes(str) { return new TextEncoder().encode(str); }
function bytesToUtf8(bytes) { return new TextDecoder().decode(bytes); }

async function pbkdf2Hash(password, saltBytes) {
  var keyMaterial = await crypto.subtle.importKey('raw', utf8ToBytes(password), { name: 'PBKDF2' }, false, ['deriveBits']);
  var bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: saltBytes, iterations: 100000, hash: 'SHA-256' },
    keyMaterial, 256
  );
  return new Uint8Array(bits);
}

async function hashPassword(password) {
  var salt = crypto.getRandomValues(new Uint8Array(16));
  var hash = await pbkdf2Hash(password, salt);
  return bytesToBase64Url(salt) + '.' + bytesToBase64Url(hash);
}

async function verifyPassword(password, stored) {
  var parts = String(stored || '').split('.');
  if (parts.length !== 2) return false;
  var salt = base64UrlToBytes(parts[0]);
  var expected = base64UrlToBytes(parts[1]);
  var actual = await pbkdf2Hash(password, salt);
  if (actual.length !== expected.length) return false;
  var diff = 0;
  for (var i = 0; i < actual.length; i++) diff |= actual[i] ^ expected[i];
  return diff === 0;
}

async function hmacSign(env, data) {
  var key = await crypto.subtle.importKey('raw', utf8ToBytes(env.SESSION_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  var sig = await crypto.subtle.sign('HMAC', key, utf8ToBytes(data));
  return bytesToBase64Url(new Uint8Array(sig));
}

async function signToken(env, payload) {
  var body = bytesToBase64Url(utf8ToBytes(JSON.stringify(payload)));
  var sig = await hmacSign(env, body);
  return body + '.' + sig;
}

async function verifyToken(env, token) {
  if (!token) return null;
  var parts = String(token).split('.');
  if (parts.length !== 2) return null;
  var expectedSig = await hmacSign(env, parts[0]);
  if (expectedSig !== parts[1]) return null;
  var payload;
  try { payload = JSON.parse(bytesToUtf8(base64UrlToBytes(parts[0]))); } catch (e) { return null; }
  if (!payload.exp || Date.now() > payload.exp) return null;
  return payload;
}

function getBearerToken(request) {
  var h = request.headers.get('Authorization') || '';
  var m = h.match(/^Bearer\s+(.+)$/);
  return m ? m[1] : null;
}

async function requireAuth(env, request) {
  var payload = await verifyToken(env, getBearerToken(request));
  if (!payload) return null;
  return payload;
}

/* ---------- GitHub Contents API ---------- */

function githubApiUrl(env, path) {
  return 'https://api.github.com/repos/' + env.GITHUB_OWNER + '/' + env.GITHUB_REPO + '/contents/' + path;
}

function githubHeaders(env) {
  return {
    'Authorization': 'token ' + env.GITHUB_TOKEN,
    'Accept': 'application/vnd.github+json',
    'User-Agent': 'multi-location-report-worker',
  };
}

// returns { data, sha } or { data: null, sha: null } if file doesn't exist yet
async function readJsonFile(env, path) {
  var res = await fetch(githubApiUrl(env, path) + '?ref=' + (env.DATA_BRANCH || 'main'), { headers: githubHeaders(env) });
  if (res.status === 404) return { data: null, sha: null };
  if (!res.ok) throw new Error('GitHub read failed (' + res.status + '): ' + path);
  var body = await res.json();
  var contentStr;
  if (body.content) {
    contentStr = bytesToUtf8(standardBase64ToBytes(body.content));
  } else {
    // GitHub Contents API leaves `content` empty for files over 1MB — fall back to the raw media type
    var rawRes = await fetch(githubApiUrl(env, path) + '?ref=' + (env.DATA_BRANCH || 'main'), {
      headers: Object.assign({}, githubHeaders(env), { 'Accept': 'application/vnd.github.raw+json' }),
    });
    if (!rawRes.ok) throw new Error('GitHub raw read failed (' + rawRes.status + '): ' + path);
    contentStr = await rawRes.text();
  }
  if (!contentStr) return { data: [], sha: body.sha };
  return { data: JSON.parse(contentStr), sha: body.sha };
}

// GitHub returns standard base64 (with newlines), not base64url — decode accordingly
function standardBase64ToBytes(b64) {
  var clean = b64.replace(/\n/g, '');
  var bin = atob(clean);
  var bytes = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

async function writeRawContent(env, path, contentB64, message, sha) {
  var body = {
    message: message,
    content: contentB64,
    branch: env.DATA_BRANCH || 'main',
  };
  if (sha) body.sha = sha;
  var res = await fetch(githubApiUrl(env, path), {
    method: 'PUT',
    headers: Object.assign({ 'Content-Type': 'application/json' }, githubHeaders(env)),
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    var errText = await res.text();
    throw new Error('GitHub write failed (' + res.status + '): ' + path + ' - ' + errText);
  }
  var result = await res.json();
  return result.content.sha;
}

async function writeJsonFile(env, path, dataObj, message, sha) {
  var contentStr = JSON.stringify(dataObj, null, 2);
  var contentB64 = btoa(unescape(encodeURIComponent(contentStr)));
  return await writeRawContent(env, path, contentB64, message, sha);
}

/* ---------- 데이터 헬퍼 ---------- */

async function loadUsers(env) {
  var r = await readJsonFile(env, 'data/users.json');
  return { users: r.data || [], sha: r.sha };
}

async function loadSiteReports(env, siteId) {
  var r = await readJsonFile(env, 'data/sites/' + siteId + '/reports.json');
  return { reports: r.data || [], sha: r.sha };
}

async function loadNotices(env) {
  var r = await readJsonFile(env, 'data/notices.json');
  return { notices: r.data || [], sha: r.sha };
}

function sanitizeSiteId(name) {
  var base = String(name || '').trim().toLowerCase()
    .replace(/[^a-z0-9가-힣\-]/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '');
  return (base || 'site') + '-' + Math.random().toString(36).slice(2, 8);
}

function toNumber(v) {
  var n = Number(String(v == null ? '' : v).replace(/,/g, ''));
  return isNaN(n) ? 0 : n;
}

function computeReportTotals(rows) {
  return rows.reduce(function (acc, r) {
    acc.chargedAmount += toNumber(r.chargedAmount);
    acc.overdueFee += toNumber(r.overdueFee);
    acc.unpaidAmount += toNumber(r.unpaidAmount);
    acc.unitCount += 1;
    return acc;
  }, { chargedAmount: 0, overdueFee: 0, unpaidAmount: 0, unitCount: 0 });
}

/* ---------- 라우트 핸들러: 인증/계정 ---------- */

async function handleLogin(env, request) {
  var body = await request.json().catch(function () { return {}; });
  var id = String(body.id || '').trim();
  var password = String(body.password || '');
  if (!id || !password) return errorResponse(env, '아이디와 비밀번호를 입력하세요.', 400);

  var { users } = await loadUsers(env);
  var user = users.find(function (u) { return u.id === id; });
  if (!user) return errorResponse(env, '아이디 또는 비밀번호가 올바르지 않습니다.', 401);

  var ok = await verifyPassword(password, user.passwordHash);
  if (!ok) return errorResponse(env, '아이디 또는 비밀번호가 올바르지 않습니다.', 401);

  var token = await signToken(env, {
    uid: user.id, role: user.role, siteId: user.siteId, siteName: user.siteName,
    exp: Date.now() + 1000 * 60 * 60 * 12, // 12시간
  });
  return jsonResponse(env, { token: token, role: user.role, siteId: user.siteId, siteName: user.siteName });
}

// 최초 1회: users.json 이 저장소에 아직 없을 때만 동작 (첫 관리자 계정 생성)
async function handleBootstrapAdmin(env, request) {
  var { users, sha } = await loadUsers(env);
  if (users.length) return errorResponse(env, '이미 초기화되었습니다. 관리자 계정으로 로그인해 사용자를 추가하세요.', 403);

  var body = await request.json().catch(function () { return {}; });
  var id = String(body.id || '').trim();
  var password = String(body.password || '');
  if (!id || !password) return errorResponse(env, '아이디와 비밀번호를 입력하세요.', 400);

  var passwordHash = await hashPassword(password);
  var adminUser = { id: id, passwordHash: passwordHash, role: 'admin', siteId: null, siteName: null, createdAt: new Date().toISOString() };
  await writeJsonFile(env, 'data/users.json', [adminUser], '최초 관리자 계정 생성: ' + id, sha);
  return jsonResponse(env, { ok: true });
}

async function handleCreateUser(env, request) {
  var auth = await requireAuth(env, request);
  if (!auth || auth.role !== 'admin') return errorResponse(env, '관리자만 사용할 수 있습니다.', 403);

  var body = await request.json().catch(function () { return {}; });
  var siteName = String(body.siteName || '').trim();
  var id = String(body.id || '').trim();
  var password = String(body.password || '');
  if (!siteName || !id || !password) return errorResponse(env, '사업소명, 아이디, 비밀번호를 모두 입력하세요.', 400);

  var { users, sha } = await loadUsers(env);
  if (users.some(function (u) { return u.id === id; })) return errorResponse(env, '이미 존재하는 아이디입니다.', 409);

  var siteId = sanitizeSiteId(siteName);
  var passwordHash = await hashPassword(password);
  var newUser = { id: id, passwordHash: passwordHash, role: 'user', siteId: siteId, siteName: siteName, createdAt: new Date().toISOString() };
  users.push(newUser);
  await writeJsonFile(env, 'data/users.json', users, '사업소 계정 생성: ' + id + ' (' + siteName + ')', sha);
  await writeJsonFile(env, 'data/sites/' + siteId + '/reports.json', [], '보고 이력 초기화: ' + siteName, null);

  return jsonResponse(env, { ok: true, siteId: siteId });
}

async function handleListUsers(env, request) {
  var auth = await requireAuth(env, request);
  if (!auth || auth.role !== 'admin') return errorResponse(env, '관리자만 사용할 수 있습니다.', 403);

  var { users } = await loadUsers(env);
  var list = users.filter(function (u) { return u.role !== 'admin'; }).map(function (u) {
    return { id: u.id, siteName: u.siteName, siteId: u.siteId, createdAt: u.createdAt };
  });
  return jsonResponse(env, { users: list });
}

/* ---------- 라우트 핸들러: 사업소 보고 ---------- */

async function handleGetSiteReports(env, request, url) {
  var auth = await requireAuth(env, request);
  if (!auth) return errorResponse(env, '로그인이 필요합니다.', 401);
  var siteId = (auth.role === 'admin' ? url.searchParams.get('siteId') : auth.siteId);
  if (!siteId) return errorResponse(env, 'siteId가 필요합니다.', 400);
  var { reports } = await loadSiteReports(env, siteId);
  reports = reports.slice().sort(function (a, b) { return (b.baseDate || '').localeCompare(a.baseDate || '') || (b.submittedAt || '').localeCompare(a.submittedAt || ''); });
  return jsonResponse(env, { reports: reports });
}

async function handleSubmitReport(env, request) {
  var auth = await requireAuth(env, request);
  if (!auth || auth.role !== 'user') return errorResponse(env, '사업소 계정만 사용할 수 있습니다.', 403);

  var body = await request.json().catch(function () { return {}; });
  var baseDate = String(body.baseDate || '').trim();
  var incomingRows = Array.isArray(body.rows) ? body.rows : [];
  if (!baseDate) return errorResponse(env, '기준일을 입력하세요.', 400);
  var rows = incomingRows.map(function (r) {
    return {
      unit: String(r.unit || '').trim(),
      company: String(r.company || '').trim(),
      unpaidMonths: toNumber(r.unpaidMonths),
      chargedAmount: toNumber(r.chargedAmount),
      overdueFee: toNumber(r.overdueFee),
      unpaidAmount: toNumber(r.unpaidAmount),
      actionPlan: String(r.actionPlan || '').trim(),
    };
  }).filter(function (r) { return r.unit || r.company; });
  if (!rows.length) return errorResponse(env, '미납세대를 1건 이상 입력하세요.', 400);

  var { reports, sha } = await loadSiteReports(env, auth.siteId);
  var nextId = reports.reduce(function (max, r) { return Math.max(max, r.id || 0); }, 0) + 1;
  var report = {
    id: nextId,
    baseDate: baseDate,
    rows: rows,
    totals: computeReportTotals(rows),
    note: String(body.note || ''),
    approvers: {
      staff: String((body.approvers && body.approvers.staff) || ''),
      manager: String((body.approvers && body.approvers.manager) || ''),
      chief: String((body.approvers && body.approvers.chief) || ''),
    },
    submittedAt: new Date().toISOString(),
    submittedBy: auth.uid,
  };
  reports.push(report);
  await writeJsonFile(env, 'data/sites/' + auth.siteId + '/reports.json', reports, '미납세대 현황 보고: ' + auth.siteId + ' (' + baseDate + ')', sha);
  return jsonResponse(env, { ok: true, report: report });
}

/* ---------- 라우트 핸들러: 본사 통계 ---------- */

async function handleAdminStats(env, request) {
  var auth = await requireAuth(env, request);
  if (!auth || auth.role !== 'admin') return errorResponse(env, '관리자만 사용할 수 있습니다.', 403);

  var { users } = await loadUsers(env);
  var sites = users.filter(function (u) { return u.role !== 'admin'; });

  var siteStats = [];
  var grandTotal = { chargedAmount: 0, overdueFee: 0, unpaidAmount: 0, unitCount: 0 };
  for (var i = 0; i < sites.length; i++) {
    var u = sites[i];
    var reports = [];
    try {
      var r = await loadSiteReports(env, u.siteId);
      reports = r.reports;
    } catch (e) { /* ignore, treat as no reports */ }
    reports = reports.slice().sort(function (a, b) { return (b.baseDate || '').localeCompare(a.baseDate || '') || (b.submittedAt || '').localeCompare(a.submittedAt || ''); });
    var latest = reports[0] || null;
    if (latest) {
      grandTotal.chargedAmount += latest.totals.chargedAmount;
      grandTotal.overdueFee += latest.totals.overdueFee;
      grandTotal.unpaidAmount += latest.totals.unpaidAmount;
      grandTotal.unitCount += latest.totals.unitCount;
    }
    siteStats.push({
      siteId: u.siteId, siteName: u.siteName,
      reportCount: reports.length,
      latestBaseDate: latest ? latest.baseDate : null,
      latestSubmittedAt: latest ? latest.submittedAt : null,
      totals: latest ? latest.totals : { chargedAmount: 0, overdueFee: 0, unpaidAmount: 0, unitCount: 0 },
    });
  }
  siteStats.sort(function (a, b) { return b.totals.unpaidAmount - a.totals.unpaidAmount; });

  return jsonResponse(env, {
    siteCount: sites.length,
    reportedSiteCount: siteStats.filter(function (s) { return s.reportCount > 0; }).length,
    grandTotal: grandTotal,
    sites: siteStats,
  });
}

/* ---------- 라우트 핸들러: 지시사항(공지) ---------- */

async function handleCreateNotice(env, request) {
  var auth = await requireAuth(env, request);
  if (!auth || auth.role !== 'admin') return errorResponse(env, '관리자만 사용할 수 있습니다.', 403);

  var body = await request.json().catch(function () { return {}; });
  var title = String(body.title || '').trim();
  var message = String(body.message || '').trim();
  var targetSiteId = body.targetSiteId ? String(body.targetSiteId) : null;
  if (!title || !message) return errorResponse(env, '제목과 내용을 입력하세요.', 400);

  var { notices, sha } = await loadNotices(env);
  var nextId = notices.reduce(function (max, n) { return Math.max(max, n.id || 0); }, 0) + 1;
  var targetSiteName = null;
  if (targetSiteId) {
    var { users } = await loadUsers(env);
    var targetUser = users.find(function (u) { return u.siteId === targetSiteId; });
    targetSiteName = targetUser ? targetUser.siteName : targetSiteId;
  }
  var notice = {
    id: nextId, title: title, message: message,
    targetSiteId: targetSiteId, targetSiteName: targetSiteName,
    createdAt: new Date().toISOString(), createdBy: auth.uid,
    ackedBy: [],
  };
  notices.push(notice);
  await writeJsonFile(env, 'data/notices.json', notices, '지시사항 등록: ' + title, sha);
  return jsonResponse(env, { ok: true, notice: notice });
}

async function handleListNoticesAdmin(env, request) {
  var auth = await requireAuth(env, request);
  if (!auth || auth.role !== 'admin') return errorResponse(env, '관리자만 사용할 수 있습니다.', 403);
  var { notices } = await loadNotices(env);
  notices = notices.slice().sort(function (a, b) { return (b.createdAt || '').localeCompare(a.createdAt || ''); });
  return jsonResponse(env, { notices: notices });
}

async function handleListNoticesSite(env, request) {
  var auth = await requireAuth(env, request);
  if (!auth || auth.role !== 'user') return errorResponse(env, '사업소 계정만 사용할 수 있습니다.', 403);
  var { notices } = await loadNotices(env);
  var mine = notices.filter(function (n) { return !n.targetSiteId || n.targetSiteId === auth.siteId; })
    .sort(function (a, b) { return (b.createdAt || '').localeCompare(a.createdAt || ''); })
    .map(function (n) {
      return {
        id: n.id, title: n.title, message: n.message,
        targetSiteId: n.targetSiteId, createdAt: n.createdAt,
        acked: n.ackedBy.indexOf(auth.siteId) !== -1,
      };
    });
  return jsonResponse(env, { notices: mine });
}

async function handleAckNotice(env, request) {
  var auth = await requireAuth(env, request);
  if (!auth || auth.role !== 'user') return errorResponse(env, '사업소 계정만 사용할 수 있습니다.', 403);
  var body = await request.json().catch(function () { return {}; });
  var id = Number(body.id);
  if (!id) return errorResponse(env, 'id가 필요합니다.', 400);

  var { notices, sha } = await loadNotices(env);
  var notice = notices.find(function (n) { return n.id === id; });
  if (!notice) return errorResponse(env, '지시사항을 찾을 수 없습니다.', 404);
  if (notice.targetSiteId && notice.targetSiteId !== auth.siteId) return errorResponse(env, '대상이 아닙니다.', 403);
  if (notice.ackedBy.indexOf(auth.siteId) === -1) notice.ackedBy.push(auth.siteId);
  await writeJsonFile(env, 'data/notices.json', notices, '지시사항 확인: ' + auth.siteId + ' -> #' + id, sha);
  return jsonResponse(env, { ok: true });
}

/* ---------- 진입점 ---------- */

export default {
  async fetch(request, env) {
    var url = new URL(request.url);
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders(env) });
    }
    try {
      if (url.pathname === '/api/login' && request.method === 'POST') return await handleLogin(env, request);
      if (url.pathname === '/api/bootstrap-admin' && request.method === 'POST') return await handleBootstrapAdmin(env, request);
      if (url.pathname === '/api/admin/users' && request.method === 'GET') return await handleListUsers(env, request);
      if (url.pathname === '/api/admin/users' && request.method === 'POST') return await handleCreateUser(env, request);
      if (url.pathname === '/api/admin/stats' && request.method === 'GET') return await handleAdminStats(env, request);
      if (url.pathname === '/api/admin/reports' && request.method === 'GET') return await handleGetSiteReports(env, request, url);
      if (url.pathname === '/api/admin/notices' && request.method === 'GET') return await handleListNoticesAdmin(env, request);
      if (url.pathname === '/api/admin/notices' && request.method === 'POST') return await handleCreateNotice(env, request);
      if (url.pathname === '/api/site/reports' && request.method === 'GET') return await handleGetSiteReports(env, request, url);
      if (url.pathname === '/api/site/reports' && request.method === 'POST') return await handleSubmitReport(env, request);
      if (url.pathname === '/api/site/notices' && request.method === 'GET') return await handleListNoticesSite(env, request);
      if (url.pathname === '/api/site/notices/ack' && request.method === 'POST') return await handleAckNotice(env, request);
      return errorResponse(env, 'Not found', 404);
    } catch (err) {
      return errorResponse(env, '서버 오류: ' + (err && err.message ? err.message : String(err)), 500);
    }
  },
};
