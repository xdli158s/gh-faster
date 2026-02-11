/**
 * Gi-tHub 加速代理 - Cloudflare Worker
 * 基于 gh-pro-xy 改进，增加访问控制和现代化特性
 */

// ==================== 配置区域 ====================
// 默认配置（可通过 Worker 环境变量覆盖）
const DEFAULT_CONFIG = {
  AUTH_ENABLED: true,                    // 是否启用认证
  AUTH_PASSWORD: 'ghproxy2026',          // 网页密码（建议用环境变量）
  API_KEY: 'sk-ghproxy-your-secret-key', // API Key（建议用环境变量）
  GITHUB_TOKEN: '',                      // GitHub Personal Access Token（解决 API 403）
  COOKIE_NAME: 'gh_proxy_auth',
  COOKIE_MAX_AGE: 604800,
  RATE_LIMIT_ENABLED: false,
  RATE_LIMIT_PER_MIN: 60,
  PREFIX: '/',
  WHITELIST: [],
  BLACKLIST: [],
};

// 从环境变量获取配置（优先级：环境变量 > 默认值）
function getConfig(env) {
  return {
    AUTH_ENABLED: env.AUTH_ENABLED !== 'false',  // 除非明确设为 'false'，否则启用
    AUTH_PASSWORD: env.AUTH_PASSWORD || DEFAULT_CONFIG.AUTH_PASSWORD,
    API_KEY: env.API_KEY || DEFAULT_CONFIG.API_KEY,
    GITHUB_TOKEN: env.GITHUB_TOKEN || DEFAULT_CONFIG.GITHUB_TOKEN,
    COOKIE_NAME: env.COOKIE_NAME || DEFAULT_CONFIG.COOKIE_NAME,
    COOKIE_MAX_AGE: parseInt(env.COOKIE_MAX_AGE) || DEFAULT_CONFIG.COOKIE_MAX_AGE,
    RATE_LIMIT_ENABLED: env.RATE_LIMIT_ENABLED === 'true',
    RATE_LIMIT_PER_MIN: parseInt(env.RATE_LIMIT_PER_MIN) || DEFAULT_CONFIG.RATE_LIMIT_PER_MIN,
    PREFIX: env.PREFIX || DEFAULT_CONFIG.PREFIX,
    WHITELIST: env.WHITELIST ? env.WHITELIST.split(',').map(s => s.trim()) : DEFAULT_CONFIG.WHITELIST,
    BLACKLIST: env.BLACKLIST ? env.BLACKLIST.split(',').map(s => s.trim()) : DEFAULT_CONFIG.BLACKLIST,
  };
}

// ==================== GitHub URL 匹配规则 ====================
const PATTERNS = {
  // https://github.com/user/repo/releases/download/tag/file
  release: /^(?:https?:\/\/)?github\.com\/(?<user>[^\/]+)\/(?<repo>[^\/]+)\/releases\/download\/(?<tag>[^\/]+)\/(?<file>[^\/]+)$/i,
  // https://github.com/user/repo/archive/ref.zip
  archive: /^(?:https?:\/\/)?github\.com\/(?<user>[^\/]+)\/(?<repo>[^\/]+)\/archive\/(?<ref>[^\/]+)$/i,
  // https://github.com/user/repo/blob/ref/path
  blob: /^(?:https?:\/\/)?github\.com\/(?<user>[^\/]+)\/(?<repo>[^\/]+)\/(?:blob|raw)\/(?<ref>[^\/]+)\/(?<path>.+)$/i,
  // https://github.com/user/repo/info/refs?service=xxx
  git: /^(?:https?:\/\/)?github\.com\/(?<user>[^\/]+)\/(?<repo>[^\/]+)\/info\/refs/i,
  // https://github.com/user/repo/git-upload-pack
  gitUpload: /^(?:https?:\/\/)?github\.com\/(?<user>[^\/]+)\/(?<repo>[^\/]+)\/git-upload-pack/i,
  // https://raw.githubusercontent.com/user/repo/ref/path
  raw: /^(?:https?:\/\/)?raw\.githubusercontent\.com\/(?<user>[^\/]+)\/(?<repo>[^\/]+)\/(?<ref>[^\/]+)\/(?<path>.+)$/i,
  // https://gist.githubusercontent.com/user/id/raw/file
  gist: /^(?:https?:\/\/)?gist\.(?:github\.com|githubusercontent\.com)\/(?<path>.+)$/i,
  // https://github.com/user/repo (clone)
  clone: /^(?:https?:\/\/)?github\.com\/(?<user>[^\/]+)\/(?<repo>[^\/]+?)(?:\.git)?(?:\/)?$/i,
};

// ==================== 主处理函数 ====================
export default {
  async fetch(request, env, ctx) {
    const CONFIG = getConfig(env);  // 从环境变量获取配置
    const url = new URL(request.url);
    const path = url.pathname;

    // 处理 favicon
    if (path === '/favicon.ico') {
      return new Response(null, { status: 204 });
    }

    // 处理密码验证页面提交
    if (path === '/auth' && request.method === 'POST') {
      return handleAuth(request, CONFIG);
    }

    // 检查访问控制
    if (CONFIG.AUTH_ENABLED) {
      const authResult = checkAuth(request, CONFIG);
      if (!authResult.passed) {
        return authResult.response;
      }
    }

    // 检查限流
    if (CONFIG.RATE_LIMIT_ENABLED && env.RATE_LIMIT) {
      const rateLimitResult = await checkRateLimit(request, env, CONFIG);
      if (!rateLimitResult.passed) {
        return rateLimitResult.response;
      }
    }

    // API: 获取仓库最新 Release 的加速链接
    // 用法: /api/releases/user/repo 或 /api/releases?repo=user/repo
    if (path.startsWith('/api/releases')) {
      return handleReleasesApi(request, url, CONFIG);
    }

    // 首页
    if (path === CONFIG.PREFIX || path === CONFIG.PREFIX.slice(0, -1)) {
      return getHomePage();
    }

    // 获取要代理的 GitHub URL
    let ghUrl = path.replace(CONFIG.PREFIX, '');
    if (url.search) {
      ghUrl += url.search;
    }

    // 移除开头的斜杠
    ghUrl = ghUrl.replace(/^\/+/, '');

    if (!ghUrl) {
      return getHomePage();
    }

    // 确保 URL 有协议
    if (!ghUrl.startsWith('http://') && !ghUrl.startsWith('https://')) {
      ghUrl = 'https://' + ghUrl;
    }

    // 检查是否是有效的 GitHub URL
    if (!isValidGitHubUrl(ghUrl)) {
      return errorResponse(400, '无效的 GitHub URL');
    }

    // 检查黑白名单
    const urlInfo = parseGitHubUrl(ghUrl);
    if (urlInfo) {
      if (CONFIG.WHITELIST.length > 0 && !CONFIG.WHITELIST.includes(urlInfo.user)) {
        return errorResponse(403, '该用户/组织不在白名单中');
      }
      if (CONFIG.BLACKLIST.includes(urlInfo.user) || CONFIG.BLACKLIST.includes(`${urlInfo.user}/${urlInfo.repo}`)) {
        return errorResponse(403, '该用户/仓库已被禁止访问');
      }
    }

    // 代理请求
    return proxyRequest(request, ghUrl);
  }
};

// ==================== 认证相关 ====================
function checkAuth(request, CONFIG) {
  // 1. 检查 API Key（代码调用方式）
  const apiKey = request.headers.get('X-API-Key') || request.headers.get('Authorization')?.replace('Bearer ', '');
  if (apiKey && apiKey === CONFIG.API_KEY) {
    return { passed: true };
  }

  // 2. 检查 Cookie（网页访问方式）
  const cookies = parseCookies(request.headers.get('Cookie') || '');
  const authToken = cookies[CONFIG.COOKIE_NAME];
  if (authToken && authToken === generateAuthToken(CONFIG.AUTH_PASSWORD)) {
    return { passed: true };
  }

  // 3. 判断返回类型：API 请求返回 JSON，浏览器返回登录页
  const accept = request.headers.get('Accept') || '';
  const isApiRequest = !accept.includes('text/html') || request.headers.has('X-API-Key') || request.headers.has('Authorization');

  if (isApiRequest) {
    return {
      passed: false,
      response: new Response(JSON.stringify({ error: '未授权访问，请提供有效的 API Key' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json; charset=utf-8' }
      })
    };
  }

  // 返回登录页面
  return {
    passed: false,
    response: getAuthPage()
  };
}

function handleAuth(request, CONFIG) {
  return request.formData().then(formData => {
    const password = formData.get('password');

    if (password === CONFIG.AUTH_PASSWORD) {
      const token = generateAuthToken(password);
      const response = new Response(null, {
        status: 302,
        headers: {
          'Location': '/',
          'Set-Cookie': `${CONFIG.COOKIE_NAME}=${token}; Path=/; Max-Age=${CONFIG.COOKIE_MAX_AGE}; HttpOnly; SameSite=Strict`
        }
      });
      return response;
    }

    return getAuthPage('密码错误，请重试');
  });
}

function generateAuthToken(password) {
  // 简单的 token 生成（生产环境建议使用更安全的方式）
  let hash = 0;
  const str = password + 'gh-proxy-salt-2024';
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return Math.abs(hash).toString(36);
}

function parseCookies(cookieStr) {
  const cookies = {};
  cookieStr.split(';').forEach(cookie => {
    const [name, value] = cookie.trim().split('=');
    if (name) cookies[name] = value;
  });
  return cookies;
}

// ==================== 限流相关 ====================
async function checkRateLimit(request, env, CONFIG) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const key = `rate:${ip}:${Math.floor(Date.now() / 60000)}`; // 每分钟一个 key

  try {
    const current = parseInt(await env.RATE_LIMIT.get(key) || '0');

    if (current >= CONFIG.RATE_LIMIT_PER_MIN) {
      return {
        passed: false,
        response: errorResponse(429, '请求过于频繁，请稍后再试')
      };
    }

    // 增加计数
    await env.RATE_LIMIT.put(key, String(current + 1), { expirationTtl: 120 });

    return { passed: true };
  } catch (e) {
    // KV 出错时放行
    return { passed: true };
  }
}

// ==================== Releases API ====================
async function handleReleasesApi(request, url, CONFIG) {
  // 判断是否是浏览器请求
  const accept = request.headers.get('Accept') || '';
  const isBrowser = accept.includes('text/html');

  // 解析仓库路径: /api/releases/user/repo 或 ?repo=user/repo
  let repoPath = url.pathname.replace('/api/releases', '').replace(/^\/+/, '');

  if (!repoPath) {
    repoPath = url.searchParams.get('repo') || '';
  }

  // 清理路径
  repoPath = repoPath.replace(/^https?:\/\/github\.com\//i, '').replace(/\.git$/, '').replace(/\/+$/, '');

  // 如果没有提供仓库，显示输入页面
  if (!repoPath || !repoPath.includes('/')) {
    if (isBrowser) {
      return getReleasesInputPage();
    }
    return new Response(JSON.stringify({
      error: '请提供有效的仓库地址',
      usage: '/api/releases/user/repo 或 /api/releases?repo=user/repo',
      example: '/api/releases/bepass-org/oblivion-desktop'
    }), {
      status: 400,
      headers: { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
    });
  }

  const [owner, repo] = repoPath.split('/');

  try {
    // 调用 GitHub API 获取最新 Release
    const apiUrl = `https://api.github.com/repos/${owner}/${repo}/releases/latest`;
    const headers = {
      'User-Agent': 'gh-proxy-worker',
      'Accept': 'application/vnd.github.v3+json'
    };

    // 如果配置了 GitHub Token，添加到请求头（解决 403 限流问题）
    if (CONFIG.GITHUB_TOKEN) {
      headers['Authorization'] = `Bearer ${CONFIG.GITHUB_TOKEN}`;
    }

    const response = await fetch(apiUrl, { headers });

    if (!response.ok) {
      if (response.status === 404) {
        const errMsg = { error: '仓库不存在或没有 Release', repo: `${owner}/${repo}` };
        if (isBrowser) {
          return getReleasesInputPage(`仓库 ${owner}/${repo} 不存在或没有 Release`);
        }
        return new Response(JSON.stringify(errMsg), {
          status: 404,
          headers: { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
        });
      }
      if (response.status === 403) {
        const errMsg = {
          error: 'GitHub API 访问受限（403）',
          repo: `${owner}/${repo}`,
          solution: '请在 Worker 环境变量中配置 GITHUB_TOKEN 以提高 API 限额'
        };
        if (isBrowser) {
          return getReleasesInputPage(`GitHub API 返回 403 - 请求受限。建议配置 GitHub Token 以提高限额。`);
        }
        return new Response(JSON.stringify(errMsg), {
          status: 403,
          headers: { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
        });
      }
      throw new Error(`GitHub API 返回 ${response.status}`);
    }

    const release = await response.json();
    const baseUrl = new URL(request.url).origin;

    // 构建加速链接数据
    const result = {
      repo: `${owner}/${repo}`,
      tag: release.tag_name,
      name: release.name || release.tag_name,
      published_at: release.published_at,
      body: release.body?.substring(0, 500) || '',
      html_url: release.html_url,
      assets: release.assets.map(asset => ({
        name: asset.name,
        size: asset.size,
        size_formatted: formatBytes(asset.size),
        download_count: asset.download_count,
        original_url: asset.browser_download_url,
        proxy_url: `${baseUrl}/${asset.browser_download_url}`
      })),
      source_code: {
        zip: {
          original_url: release.zipball_url,
          proxy_url: `${baseUrl}/${release.zipball_url}`
        },
        tar: {
          original_url: release.tarball_url,
          proxy_url: `${baseUrl}/${release.tarball_url}`
        }
      }
    };

    // 浏览器请求返回 HTML 页面
    if (isBrowser) {
      return getReleasesHtmlPage(result, baseUrl);
    }

    return new Response(JSON.stringify(result, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
    });

  } catch (error) {
    const errMsg = { error: '获取 Release 信息失败', message: error.message, repo: `${owner}/${repo}` };
    if (isBrowser) {
      return getReleasesInputPage(`获取失败: ${error.message}`);
    }
    return new Response(JSON.stringify(errMsg), {
      status: 500,
      headers: { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
    });
  }
}

// Releases 输入页面
function getReleasesInputPage(error = '') {
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>获取 Release 加速链接</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      min-height: 100vh;
      background: linear-gradient(135deg, #0d1117 0%, #161b22 50%, #21262d 100%);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      color: #c9d1d9;
      padding: 40px 20px;
    }
    .container { max-width: 600px; margin: 0 auto; }
    h1 { color: #fff; text-align: center; margin-bottom: 10px; }
    .subtitle { text-align: center; color: #8b949e; margin-bottom: 40px; }
    .card {
      background: rgba(255,255,255,0.05);
      border-radius: 16px;
      padding: 30px;
      border: 1px solid rgba(255,255,255,0.1);
    }
    .error {
      background: rgba(239,68,68,0.2);
      border: 1px solid rgba(239,68,68,0.5);
      color: #fca5a5;
      padding: 12px;
      border-radius: 10px;
      margin-bottom: 20px;
      text-align: center;
    }
    input {
      width: 100%;
      padding: 16px 20px;
      border: 2px solid rgba(255,255,255,0.1);
      border-radius: 12px;
      background: rgba(0,0,0,0.3);
      color: #fff;
      font-size: 16px;
      margin-bottom: 15px;
    }
    input:focus { outline: none; border-color: #58a6ff; }
    input::placeholder { color: #6e7681; }
    button {
      width: 100%;
      padding: 16px;
      border: none;
      border-radius: 12px;
      background: linear-gradient(135deg, #238636 0%, #2ea043 100%);
      color: #fff;
      font-size: 16px;
      font-weight: 600;
      cursor: pointer;
    }
    button:hover { opacity: 0.9; }
    .examples { margin-top: 30px; }
    .examples h3 { color: #8b949e; font-size: 14px; margin-bottom: 10px; }
    .example-link {
      display: block;
      color: #58a6ff;
      text-decoration: none;
      padding: 8px 0;
      font-size: 14px;
    }
    .example-link:hover { text-decoration: underline; }
    .back { text-align: center; margin-top: 30px; }
    .back a { color: #58a6ff; text-decoration: none; }
  </style>
</head>
<body>
  <div class="container">
    <h1>📦 获取 Release 加速链接</h1>
    <p class="subtitle">输入 GitHub 仓库地址，获取最新版本的所有下载链接</p>
    <div class="card">
      ${error ? `<div class="error">${error}</div>` : ''}
      <form method="GET" action="/api/releases">
        <input type="text" name="repo" placeholder="输入仓库地址，如: microsoft/vscode" required autofocus>
        <button type="submit">获取加速链接</button>
      </form>
      <div class="examples">
        <h3>热门示例：</h3>
        <a class="example-link" href="/api/releases/bepass-org/oblivion-desktop">bepass-org/oblivion-desktop</a>
        <a class="example-link" href="/api/releases/nicegram/nicegram-ios">nicegram/nicegram-ios</a>
        <a class="example-link" href="/api/releases/AIDotNet/AIdotNet.API">AIDotNet/AIdotNet.API</a>
      </div>
    </div>
    <div class="back"><a href="/">← 返回首页</a></div>
  </div>
</body>
</html>`;
  return new Response(html, {
    status: error ? 400 : 200,
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  });
}

// Releases 结果页面
function getReleasesHtmlPage(data, baseUrl) {
  const assetsHtml = data.assets.map(asset => `
      <div class="asset">
        <div class="asset-info">
          <span class="asset-name">${asset.name}</span>
          <span class="asset-meta">${asset.size_formatted} · ${asset.download_count} 次下载</span>
        </div>
        <div class="asset-actions">
          <a href="${asset.proxy_url}" class="btn btn-primary">⚡ 加速下载</a>
          <button class="btn btn-copy" onclick="copyUrl('${asset.proxy_url}')">📋 复制链接</button>
        </div>
      </div>
    `).join('');

  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${data.repo} - Release ${data.tag}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      min-height: 100vh;
      background: linear-gradient(135deg, #0d1117 0%, #161b22 50%, #21262d 100%);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      color: #c9d1d9;
      padding: 40px 20px;
    }
    .container { max-width: 900px; margin: 0 auto; }
    .header { text-align: center; margin-bottom: 40px; }
    .repo-name { color: #58a6ff; font-size: 14px; margin-bottom: 5px; }
    .repo-name a { color: #58a6ff; text-decoration: none; }
    h1 { color: #fff; font-size: 32px; margin-bottom: 10px; }
    .tag { 
      display: inline-block;
      background: rgba(56,139,253,0.15);
      color: #58a6ff;
      padding: 6px 12px;
      border-radius: 20px;
      font-size: 14px;
    }
    .published { color: #8b949e; font-size: 14px; margin-top: 15px; }
    .card {
      background: rgba(255,255,255,0.05);
      border-radius: 16px;
      padding: 25px;
      margin-bottom: 20px;
      border: 1px solid rgba(255,255,255,0.1);
    }
    .card h2 { color: #fff; font-size: 18px; margin-bottom: 20px; }
    .asset {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 15px;
      background: rgba(0,0,0,0.2);
      border-radius: 10px;
      margin-bottom: 10px;
    }
    .asset:last-child { margin-bottom: 0; }
    .asset-info { flex: 1; }
    .asset-name { display: block; color: #fff; font-weight: 500; margin-bottom: 4px; word-break: break-all; }
    .asset-meta { color: #8b949e; font-size: 13px; }
    .asset-actions { display: flex; gap: 10px; flex-shrink: 0; margin-left: 15px; }
    .btn {
      padding: 10px 16px;
      border: none;
      border-radius: 8px;
      font-size: 14px;
      cursor: pointer;
      text-decoration: none;
      white-space: nowrap;
    }
    .btn-primary { background: linear-gradient(135deg, #238636 0%, #2ea043 100%); color: #fff; }
    .btn-copy { background: rgba(255,255,255,0.1); color: #c9d1d9; }
    .btn:hover { opacity: 0.85; }
    .source-code { display: flex; gap: 15px; }
    .source-code a { flex: 1; text-align: center; }
    .toast {
      position: fixed;
      bottom: 30px;
      left: 50%;
      transform: translateX(-50%);
      background: #238636;
      color: #fff;
      padding: 12px 24px;
      border-radius: 8px;
      display: none;
    }
    .back { text-align: center; margin-top: 30px; }
    .back a { color: #58a6ff; text-decoration: none; }
    @media (max-width: 600px) {
      .asset { flex-direction: column; align-items: flex-start; }
      .asset-actions { margin: 10px 0 0 0; width: 100%; }
      .asset-actions .btn { flex: 1; text-align: center; }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="repo-name"><a href="https://github.com/${data.repo}" target="_blank">📦 ${data.repo}</a></div>
      <h1>${data.name}</h1>
      <span class="tag">${data.tag}</span>
      <div class="published">发布于 ${new Date(data.published_at).toLocaleString('zh-CN')}</div>
    </div>
    
    <div class="card">
      <h2>📥 下载文件 (${data.assets.length})</h2>
      ${assetsHtml || '<p style="color:#8b949e">该版本没有附件文件</p>'}
    </div>
    
    <div class="card">
      <h2>📦 源代码</h2>
      <div class="source-code">
        <a href="${data.source_code.zip.proxy_url}" class="btn btn-primary">⚡ ZIP 加速下载</a>
        <a href="${data.source_code.tar.proxy_url}" class="btn btn-primary">⚡ TAR.GZ 加速下载</a>
      </div>
    </div>
    
    <div class="back">
      <a href="/api/releases">← 查询其他仓库</a> · <a href="/">返回首页</a>
    </div>
  </div>
  
  <div class="toast" id="toast">✅ 链接已复制</div>
  
  <script>
    function copyUrl(url) {
      navigator.clipboard.writeText(url).then(() => {
        const toast = document.getElementById('toast');
        toast.style.display = 'block';
        setTimeout(() => toast.style.display = 'none', 2000);
      });
    }
  </script>
</body>
</html>`;
  return new Response(html, {
    status: 200,
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  });
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// ==================== URL 处理 ====================
function isValidGitHubUrl(url) {
  return Object.values(PATTERNS).some(pattern => pattern.test(url));
}

function parseGitHubUrl(url) {
  for (const pattern of Object.values(PATTERNS)) {
    const match = url.match(pattern);
    if (match && match.groups) {
      return match.groups;
    }
  }
  return null;
}

// ==================== 代理请求 ====================
async function proxyRequest(request, targetUrl) {
  // 构造新的请求头
  const headers = new Headers(request.headers);

  // 移除可能导致问题的头
  headers.delete('host');
  headers.delete('cf-connecting-ip');
  headers.delete('cf-ipcountry');
  headers.delete('cf-ray');
  headers.delete('cf-visitor');

  // 创建新请求
  const newRequest = new Request(targetUrl, {
    method: request.method,
    headers: headers,
    body: request.body,
    redirect: 'follow'
  });

  try {
    const response = await fetch(newRequest);

    // 构造响应头
    const responseHeaders = new Headers(response.headers);
    responseHeaders.set('Access-Control-Allow-Origin', '*');
    responseHeaders.delete('content-security-policy');
    responseHeaders.delete('content-security-policy-report-only');
    responseHeaders.delete('x-frame-options');

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders
    });
  } catch (error) {
    return errorResponse(502, `代理请求失败: ${error.message}`);
  }
}

// ==================== 页面响应 ====================
function errorResponse(status, message) {
  return new Response(JSON.stringify({ error: message }), {
    status: status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Access-Control-Allow-Origin': '*'
    }
  });
}

function getAuthPage(error = '') {
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>访问验证 - GitHub 加速</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    }
    .card {
      background: rgba(255,255,255,0.05);
      backdrop-filter: blur(10px);
      border-radius: 20px;
      padding: 40px;
      width: 90%;
      max-width: 400px;
      border: 1px solid rgba(255,255,255,0.1);
      box-shadow: 0 25px 50px rgba(0,0,0,0.3);
    }
    h1 {
      color: #fff;
      text-align: center;
      margin-bottom: 10px;
      font-size: 28px;
    }
    .subtitle {
      color: rgba(255,255,255,0.6);
      text-align: center;
      margin-bottom: 30px;
      font-size: 14px;
    }
    .error {
      background: rgba(239,68,68,0.2);
      border: 1px solid rgba(239,68,68,0.5);
      color: #fca5a5;
      padding: 12px;
      border-radius: 10px;
      margin-bottom: 20px;
      text-align: center;
      font-size: 14px;
    }
    input {
      width: 100%;
      padding: 15px 20px;
      border: 1px solid rgba(255,255,255,0.15);
      border-radius: 12px;
      background: rgba(255,255,255,0.05);
      color: #fff;
      font-size: 16px;
      margin-bottom: 20px;
      transition: all 0.3s;
    }
    input:focus {
      outline: none;
      border-color: #60a5fa;
      box-shadow: 0 0 0 3px rgba(96,165,250,0.2);
    }
    input::placeholder { color: rgba(255,255,255,0.4); }
    button {
      width: 100%;
      padding: 15px;
      border: none;
      border-radius: 12px;
      background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
      color: #fff;
      font-size: 16px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.3s;
    }
    button:hover {
      transform: translateY(-2px);
      box-shadow: 0 10px 20px rgba(59,130,246,0.3);
    }
    .icon {
      text-align: center;
      font-size: 48px;
      margin-bottom: 20px;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">🔐</div>
    <h1>访问验证</h1>
    <p class="subtitle">请输入访问密码以继续</p>
    ${error ? `<div class="error">${error}</div>` : ''}
    <form method="POST" action="/auth">
      <input type="password" name="password" placeholder="请输入访问密码" required autofocus>
      <button type="submit">验证</button>
    </form>
  </div>
</body>
</html>`;
  return new Response(html, {
    status: 401,
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  });
}

function getHomePage() {
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>GitHub 加速下载服务</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      min-height: 100vh;
      background: linear-gradient(135deg, #0d1117 0%, #161b22 50%, #21262d 100%);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      color: #c9d1d9;
      padding: 20px;
    }
    .container {
      max-width: 900px;
      margin: 0 auto;
      padding-top: 40px;
    }
    .header {
      text-align: center;
      margin-bottom: 40px;
    }
    .logo {
      font-size: 56px;
      margin-bottom: 15px;
      animation: pulse 2s infinite;
    }
    @keyframes pulse {
      0%, 100% { transform: scale(1); }
      50% { transform: scale(1.05); }
    }
    h1 {
      font-size: 32px;
      color: #fff;
      margin-bottom: 8px;
    }
    .subtitle {
      font-size: 16px;
      color: #8b949e;
    }
    
    /* Tab 切换样式 */
    .tabs {
      display: flex;
      gap: 10px;
      margin-bottom: 20px;
      border-bottom: 2px solid rgba(255,255,255,0.1);
    }
    .tab {
      padding: 12px 24px;
      background: transparent;
      border: none;
      color: #8b949e;
      font-size: 16px;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.3s;
      border-bottom: 3px solid transparent;
      margin-bottom: -2px;
    }
    .tab:hover {
      color: #c9d1d9;
    }
    .tab.active {
      color: #58a6ff;
      border-bottom-color: #58a6ff;
    }
    
    /* 内容区域 */
    .tab-content {
      display: none;
    }
    .tab-content.active {
      display: block;
    }
    
    .card {
      background: rgba(255,255,255,0.05);
      backdrop-filter: blur(10px);
      border-radius: 16px;
      padding: 30px;
      margin-bottom: 30px;
      border: 1px solid rgba(255,255,255,0.1);
    }
    
    .input-group {
      display: flex;
      gap: 12px;
      margin-bottom: 15px;
    }
    input[type="text"] {
      flex: 1;
      padding: 16px 20px;
      border: 2px solid rgba(255,255,255,0.1);
      border-radius: 12px;
      background: rgba(0,0,0,0.3);
      color: #fff;
      font-size: 16px;
      transition: all 0.3s;
    }
    input[type="text"]:focus {
      outline: none;
      border-color: #58a6ff;
      box-shadow: 0 0 0 3px rgba(88,166,255,0.2);
    }
    input[type="text"]::placeholder { color: #6e7681; }
    
    button {
      padding: 16px 32px;
      border: none;
      border-radius: 12px;
      background: linear-gradient(135deg, #238636 0%, #2ea043 100%);
      color: #fff;
      font-size: 16px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.3s;
      white-space: nowrap;
    }
    button:hover {
      transform: translateY(-2px);
      box-shadow: 0 10px 25px rgba(46,160,67,0.3);
    }
    
    .result {
      margin-top: 15px;
      padding: 16px;
      background: rgba(88,166,255,0.1);
      border: 1px solid rgba(88,166,255,0.3);
      border-radius: 10px;
      display: none;
      word-break: break-all;
    }
    .result a {
      color: #58a6ff;
      text-decoration: none;
    }
    .result a:hover { text-decoration: underline; }
    
    .error {
      background: rgba(239,68,68,0.2);
      border: 1px solid rgba(239,68,68,0.5);
      color: #fca5a5;
      padding: 12px;
      border-radius: 10px;
      margin-top: 15px;
      display: none;
    }
    
    .loading {
      text-align: center;
      padding: 20px;
      color: #8b949e;
      display: none;
    }
    
    .example-links {
      margin-top: 20px;
      padding-top: 20px;
      border-top: 1px solid rgba(255,255,255,0.1);
    }
    .example-links h3 {
      color: #8b949e;
      font-size: 14px;
      margin-bottom: 10px;
    }
    .example-link {
      display: inline-block;
      color: #58a6ff;
      text-decoration: none;
      padding: 6px 12px;
      margin: 4px;
      background: rgba(88,166,255,0.1);
      border-radius: 6px;
      font-size: 13px;
      transition: all 0.2s;
    }
    .example-link:hover {
      background: rgba(88,166,255,0.2);
    }
    
    .section {
      background: rgba(255,255,255,0.03);
      border-radius: 16px;
      padding: 25px;
      margin-bottom: 20px;
      border: 1px solid rgba(255,255,255,0.06);
    }
    .section h2 {
      color: #fff;
      font-size: 18px;
      margin-bottom: 15px;
    }
    .section ul {
      list-style: none;
      color: #8b949e;
    }
    .section li {
      padding: 8px 0;
      border-bottom: 1px solid rgba(255,255,255,0.05);
      font-size: 14px;
    }
    .section li:last-child { border-bottom: none; }
    code {
      background: rgba(110,118,129,0.2);
      padding: 3px 8px;
      border-radius: 6px;
      font-family: 'SF Mono', Monaco, monospace;
      font-size: 13px;
      color: #79c0ff;
    }
    
    .footer {
      text-align: center;
      margin-top: 40px;
      padding: 20px;
      color: #6e7681;
      font-size: 14px;
    }
    
    @media (max-width: 600px) {
      .input-group { flex-direction: column; }
      h1 { font-size: 24px; }
      .tab { padding: 10px 16px; font-size: 14px; }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="logo">📦</div>
      <h1>GitHub 加速下载服务</h1>
      <p class="subtitle">快速下载 GitHub 文件、Release、Archive</p>
    </div>
    
    <!-- Tab 切换 -->
    <div class="tabs">
      <button class="tab active" onclick="switchTab('file')">📥 文件加速</button>
      <button class="tab" onclick="switchTab('release')">📦 Release 查询</button>
    </div>
    
    <!-- 文件加速 Tab -->
    <div id="file-tab" class="tab-content active">
      <div class="card">
        <div class="input-group">
          <input type="text" id="url-input" placeholder="粘贴 GitHub 文件链接，如: github.com/user/repo/releases/download/...">
          <button onclick="convertUrl()">加速下载</button>
        </div>
        <div class="result" id="file-result"></div>
        
        <div class="example-links">
          <h3>💡 支持的链接格式：</h3>
          <span style="color: #8b949e; font-size: 13px; display: block; margin-top: 8px;">
            Release 文件 · 源码包 · Raw 文件 · Blob 文件 · Gist 文件
          </span>
        </div>
      </div>
      
      <div class="section">
        <h2>📖 使用说明</h2>
        <ul>
          <li>直接在 GitHub 文件 URL 前添加本站地址即可加速</li>
          <li>支持 <code>releases</code>、<code>archive</code>、<code>raw</code>、<code>blob</code> 等链接</li>
          <li>支持 <code>git clone</code> 加速: <code>git clone <span class="origin"></span>/https://github.com/user/repo</code></li>
          <li>支持私有仓库: <code>git clone https://user:TOKEN@<span class="host"></span>/https://github.com/user/repo</code></li>
        </ul>
      </div>
    </div>
    
    <!-- Release 查询 Tab -->
    <div id="release-tab" class="tab-content">
      <div class="card">
        <div class="input-group">
          <input type="text" id="repo-input" placeholder="输入仓库地址，如: microsoft/vscode">
          <button onclick="fetchRelease()">获取加速链接</button>
        </div>
        <div class="loading" id="release-loading">⏳ 正在获取 Release 信息...</div>
        <div class="error" id="release-error"></div>
        <div class="result" id="release-result"></div>
        
        <div class="example-links">
          <h3>🔥 热门示例：</h3>
          <a class="example-link" href="#" onclick="fillRepo('bepass-org/oblivion-desktop'); return false;">bepass-org/oblivion-desktop</a>
          <a class="example-link" href="#" onclick="fillRepo('microsoft/vscode'); return false;">microsoft/vscode</a>
          <a class="example-link" href="#" onclick="fillRepo('nodejs/node'); return false;">nodejs/node</a>
        </div>
      </div>
      
      <div class="section">
        <h2>📖 使用说明</h2>
        <ul>
          <li>输入 GitHub 仓库地址（格式：<code>owner/repo</code>）</li>
          <li>自动获取最新 Release 版本的所有下载链接</li>
          <li>所有链接均为加速链接，可直接下载</li>
          <li>如遇到 403 错误，请在 Worker 环境变量中配置 <code>GITHUB_TOKEN</code></li>
        </ul>
      </div>
    </div>
    
    <div class="footer">
      <p>⚡ Powered by Cloudflare Workers</p>
    </div>
  </div>
  
  <script>
    // Tab 切换
    function switchTab(tab) {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      
      if (tab === 'file') {
        document.querySelectorAll('.tab')[0].classList.add('active');
        document.getElementById('file-tab').classList.add('active');
      } else {
        document.querySelectorAll('.tab')[1].classList.add('active');
        document.getElementById('release-tab').classList.add('active');
      }
    }
    
    // 文件加速
    function convertUrl() {
      const input = document.getElementById('url-input').value.trim();
      const result = document.getElementById('file-result');
      
      if (!input) {
        alert('请输入 GitHub 链接');
        return;
      }
      
      let url = input;
      if (!url.startsWith('http://') && !url.startsWith('https://')) {
        url = 'https://' + url;
      }
      
      const proxyUrl = location.origin + '/' + url;
      result.innerHTML = '✅ 加速链接: <a href="' + proxyUrl + '" target="_blank">' + proxyUrl + '</a>';
      result.style.display = 'block';
    }
    
    // Release 查询
    async function fetchRelease() {
      const input = document.getElementById('repo-input').value.trim();
      const loading = document.getElementById('release-loading');
      const error = document.getElementById('release-error');
      const result = document.getElementById('release-result');
      
      // 重置状态
      loading.style.display = 'none';
      error.style.display = 'none';
      result.style.display = 'none';
      
      if (!input) {
        error.textContent = '请输入仓库地址';
        error.style.display = 'block';
        return;
      }
      
      // 清理输入
      let repo = input.replace(/^https?:\\/\\/github\\.com\\//i, '').replace(/\\.git$/, '').replace(/\\/+$/, '');
      
      if (!repo.includes('/')) {
        error.textContent = '仓库地址格式错误，应为: owner/repo';
        error.style.display = 'block';
        return;
      }
      
      loading.style.display = 'block';
      
      try {
        const response = await fetch('/api/releases/' + repo);
        const data = await response.json();
        
        loading.style.display = 'none';
        
        if (!response.ok) {
          error.textContent = data.error || '获取失败';
          if (data.solution) {
            error.textContent += ' - ' + data.solution;
          }
          error.style.display = 'block';
          return;
        }
        
        // 显示结果
        let html = '<div style="margin-bottom: 15px;">';
        html += '<strong style="color: #fff; font-size: 16px;">' + data.name + '</strong><br>';
        html += '<span style="color: #8b949e; font-size: 13px;">版本: ' + data.tag + ' · 发布于 ' + new Date(data.published_at).toLocaleString('zh-CN') + '</span>';
        html += '</div>';
        
        if (data.assets && data.assets.length > 0) {
          html += '<div style="margin-bottom: 10px; color: #fff; font-weight: 500;">📥 下载文件 (' + data.assets.length + '):</div>';
          data.assets.forEach(asset => {
            html += '<div style="margin: 8px 0; padding: 10px; background: rgba(0,0,0,0.2); border-radius: 8px;">';
            html += '<div style="color: #fff; margin-bottom: 4px;">' + asset.name + '</div>';
            html += '<div style="color: #8b949e; font-size: 12px; margin-bottom: 6px;">' + asset.size_formatted + ' · ' + asset.download_count + ' 次下载</div>';
            html += '<a href="' + asset.proxy_url + '" style="color: #58a6ff; font-size: 13px;">⚡ 加速下载</a>';
            html += '</div>';
          });
        }
        
        html += '<div style="margin-top: 15px; padding-top: 15px; border-top: 1px solid rgba(255,255,255,0.1);">';
        html += '<div style="color: #fff; font-weight: 500; margin-bottom: 8px;">📦 源代码:</div>';
        html += '<a href="' + data.source_code.zip.proxy_url + '" style="color: #58a6ff; margin-right: 15px;">⚡ ZIP</a>';
        html += '<a href="' + data.source_code.tar.proxy_url + '" style="color: #58a6ff;">⚡ TAR.GZ</a>';
        html += '</div>';
        
        result.innerHTML = html;
        result.style.display = 'block';
        
      } catch (err) {
        loading.style.display = 'none';
        error.textContent = '请求失败: ' + err.message;
        error.style.display = 'block';
      }
    }
    
    // 填充示例仓库
    function fillRepo(repo) {
      document.getElementById('repo-input').value = repo;
      fetchRelease();
    }
    
    // 回车提交
    document.getElementById('url-input').addEventListener('keypress', function(e) {
      if (e.key === 'Enter') convertUrl();
    });
    document.getElementById('repo-input').addEventListener('keypress', function(e) {
      if (e.key === 'Enter') fetchRelease();
    });
    
    // 填充域名信息
    document.querySelectorAll('.origin').forEach(el => el.textContent = location.origin);
    document.querySelectorAll('.host').forEach(el => el.textContent = location.host);
  </script>
</body>
</html>`;
  return new Response(html, {
    status: 200,
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  });
}
