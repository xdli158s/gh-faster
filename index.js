/**
 * GitHub 加速代理 - Cloudflare Worker
 * 基于 gh-proxy 改进，增加访问控制和现代化特性
 */

// ==================== 配置区域 ====================
// 默认配置（可通过 Worker 环境变量覆盖）
const DEFAULT_CONFIG = {
    AUTH_ENABLED: true,                    // 是否启用认证
    AUTH_PASSWORD: 'ghproxy2026',          // 网页密码（建议用环境变量）
    API_KEY: 'sk-ghproxy-your-secret-key', // API Key（建议用环境变量）
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
  <title>GitHub 加速 - 文件下载加速服务</title>
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
      max-width: 800px;
      margin: 0 auto;
      padding-top: 60px;
    }
    .header {
      text-align: center;
      margin-bottom: 50px;
    }
    .logo {
      font-size: 64px;
      margin-bottom: 20px;
      animation: pulse 2s infinite;
    }
    @keyframes pulse {
      0%, 100% { transform: scale(1); }
      50% { transform: scale(1.05); }
    }
    h1 {
      font-size: 36px;
      color: #fff;
      margin-bottom: 10px;
    }
    .subtitle {
      font-size: 18px;
      color: #8b949e;
    }
    .input-box {
      background: rgba(255,255,255,0.05);
      backdrop-filter: blur(10px);
      border-radius: 16px;
      padding: 30px;
      margin-bottom: 40px;
      border: 1px solid rgba(255,255,255,0.1);
    }
    .input-group {
      display: flex;
      gap: 12px;
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
      margin-top: 20px;
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
    .section {
      background: rgba(255,255,255,0.03);
      border-radius: 16px;
      padding: 25px;
      margin-bottom: 20px;
      border: 1px solid rgba(255,255,255,0.06);
    }
    .section h2 {
      color: #fff;
      font-size: 20px;
      margin-bottom: 15px;
      display: flex;
      align-items: center;
      gap: 10px;
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
    .features {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 15px;
      margin-top: 30px;
    }
    .feature {
      background: rgba(255,255,255,0.03);
      padding: 20px;
      border-radius: 12px;
      text-align: center;
      border: 1px solid rgba(255,255,255,0.06);
      transition: all 0.3s;
    }
    .feature:hover {
      transform: translateY(-3px);
      border-color: rgba(88,166,255,0.3);
    }
    .feature-icon { font-size: 32px; margin-bottom: 10px; }
    .feature h3 { color: #fff; font-size: 16px; margin-bottom: 5px; }
    .feature p { color: #8b949e; font-size: 13px; }
    .footer {
      text-align: center;
      margin-top: 50px;
      padding: 20px;
      color: #6e7681;
      font-size: 14px;
    }
    @media (max-width: 600px) {
      .input-group { flex-direction: column; }
      h1 { font-size: 28px; }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="logo">🚀</div>
      <h1>GitHub 加速</h1>
      <p class="subtitle">快速下载 GitHub 文件、Release、Archive</p>
    </div>
    
    <div class="input-box">
      <div class="input-group">
        <input type="text" id="url-input" placeholder="粘贴 GitHub 文件链接，例如: github.com/user/repo/releases/...">
        <button onclick="convert()">加速下载</button>
      </div>
      <div class="result" id="result"></div>
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
    
    <div class="section">
      <h2>✅ 支持的链接格式</h2>
      <ul>
        <li><code>github.com/user/repo/releases/download/tag/file</code> - Release 文件</li>
        <li><code>github.com/user/repo/archive/ref.zip</code> - 源码压缩包</li>
        <li><code>github.com/user/repo/blob/ref/path</code> - 仓库文件</li>
        <li><code>raw.githubusercontent.com/user/repo/ref/path</code> - Raw 文件</li>
        <li><code>gist.githubusercontent.com/...</code> - Gist 文件</li>
      </ul>
    </div>
    
    <div class="features">
      <div class="feature">
        <div class="feature-icon">⚡</div>
        <h3>极速下载</h3>
        <p>Cloudflare 全球 CDN</p>
      </div>
      <div class="feature">
        <div class="feature-icon">🔒</div>
        <h3>安全可靠</h3>
        <p>支持 HTTPS 加密</p>
      </div>
      <div class="feature">
        <div class="feature-icon">💯</div>
        <h3>完全免费</h3>
        <p>无需注册登录</p>
      </div>
      <div class="feature">
        <div class="feature-icon">🌐</div>
        <h3>无限制</h3>
        <p>不限文件大小</p>
      </div>
    </div>
    
    <div class="footer">
      <p>Powered by Cloudflare Workers</p>
    </div>
  </div>
  
  <script>
    function convert() {
      const input = document.getElementById('url-input').value.trim();
      const result = document.getElementById('result');
      
      if (!input) {
        alert('请输入 GitHub 链接');
        return;
      }
      
      let url = input;
      if (!url.startsWith('http://') && !url.startsWith('https://')) {
        url = 'https://' + url;
      }
      
      const proxyUrl = location.origin + '/' + url;
      result.innerHTML = '加速链接: <a href="' + proxyUrl + '" target="_blank">' + proxyUrl + '</a>';
      result.style.display = 'block';
    }
    
    // 回车提交
    document.getElementById('url-input').addEventListener('keypress', function(e) {
      if (e.key === 'Enter') convert();
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
