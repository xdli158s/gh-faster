# GitHub 加速代理 (gh-proxy-worker)

基于 Cloudflare Workers 的 GitHub 文件加速服务，支持 releases、archive、raw 文件下载加速。

## ✨ 功能特性

- 🚀 **文件加速** - releases、archive、raw、blob 文件下载加速
- 🔐 **访问控制** - 密码验证保护，防止未授权访问
- 🛡️ **限流保护** - IP 请求频率限制，防止恶意刷量
- 🎨 **现代 UI** - 美观的暗色主题界面
- 📦 **Git Clone** - 支持 git clone 加速
- 🔑 **私有仓库** - 通过 Token 访问私有仓库

## 🚀 快速部署

### 方式一：Cloudflare Dashboard 部署

1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com/)
2. 进入 **Workers & Pages**
3. 点击 **Create application** → **Create Worker**
4. 给 Worker 命名（如 `gh-proxy`）
5. 点击 **Deploy**
6. 点击 **Edit code**，将 `index.js` 内容粘贴进去
7. 点击 **Deploy** 保存

### 方式二：Wrangler CLI 部署

```bash
# 安装 wrangler
npm install -g wrangler

# 登录 Cloudflare
wrangler login

# 创建项目
cd gh-proxy-worker
wrangler init

# 部署
wrangler deploy
```

## ⚙️ 配置说明

在 `index.js` 顶部的 `CONFIG` 对象中修改配置：

```javascript
const CONFIG = {
  // 访问控制
  AUTH_ENABLED: true,           // 是否启用密码验证
  AUTH_PASSWORD: 'your-pwd',    // 访问密码（务必修改！）
  COOKIE_MAX_AGE: 604800,       // Cookie 有效期（秒，默认7天）
  
  // 限流设置（需要先创建 KV 命名空间）
  RATE_LIMIT_ENABLED: false,    // 是否启用限流
  RATE_LIMIT_PER_MIN: 60,       // 每分钟最大请求数
  
  // 黑白名单
  WHITELIST: [],                // 白名单用户/组织
  BLACKLIST: [],                // 黑名单用户/仓库
};
```

## 🔧 启用限流功能（可选）

1. 在 Cloudflare Dashboard 创建 KV 命名空间：
   - 进入 **Workers & Pages** → **KV**
   - 点击 **Create a namespace**
   - 命名为 `RATE_LIMIT`

2. 绑定 KV 到 Worker：
   - 进入 Worker 设置
   - 点击 **Settings** → **Variables**
   - 在 **KV Namespace Bindings** 添加绑定
   - Variable name: `RATE_LIMIT`，选择刚创建的命名空间

3. 在 `CONFIG` 中设置 `RATE_LIMIT_ENABLED: true`

## 📖 使用方式

### 网页使用
访问你的 Worker 地址，在输入框粘贴 GitHub 链接即可获取加速链接。

### 直接拼接
在 GitHub URL 前加上你的 Worker 地址：

```
https://your-worker.workers.dev/https://github.com/user/repo/releases/download/v1.0/file.zip
```

### Git Clone 加速
```bash
git clone https://your-worker.workers.dev/https://github.com/user/repo.git
```

### 私有仓库
```bash
git clone https://user:TOKEN@your-worker.workers.dev/https://github.com/user/private-repo.git
```

## 📝 支持的链接格式

| 类型 | 格式 |
|------|------|
| Release 文件 | `github.com/user/repo/releases/download/tag/file` |
| 源码包 | `github.com/user/repo/archive/ref.zip` |
| 仓库文件 | `github.com/user/repo/blob/ref/path` |
| Raw 文件 | `raw.githubusercontent.com/user/repo/ref/path` |
| Gist | `gist.githubusercontent.com/...` |

## 📊 免费额度

Cloudflare Workers 免费版：
- 每天 **10 万次** 请求
- 每分钟 **1000 次** 请求限制

对于个人使用完全足够。如需更大额度，可升级付费版。

## 🔒 安全建议

1. **务必修改默认密码** - 部署后立即修改 `AUTH_PASSWORD`
2. **使用自定义域名** - 可绑定自己的域名，更加稳定
3. **定期检查使用量** - 在 Cloudflare Dashboard 监控请求量

## 📄 许可证

MIT License
