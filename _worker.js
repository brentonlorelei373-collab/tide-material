// ============ TIDE Material API v2 ============
// Cloudflare Pages _worker.js
// 功能: 用户认证, Pexels搜索代理, 频率限制, Session过期, 登录保护, 收藏

// ============ 配置 ============
const PEXELS_API_KEY = 'QzRQUCCS2KSutNKlsXUE81M0zkPm56V01Nh0DrTW4nZZQOY939KBxhct';
const SESSION_EXPIRY_DAYS = 7;
const SEARCH_LIMIT_PER_HOUR = 30;
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_MINUTES = 15;

// ============ 工具函数 ============

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    }
  });
}

function generateSalt() {
  const arr = new Uint8Array(16);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

function generateToken() {
  const arr = new Uint8Array(32);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function hashPassword(password, salt) {
  const data = new TextEncoder().encode(password + salt);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ============ 数据库初始化 ============

async function ensureDB(env) {
  try {
    // 快速检查：如果 rate_limits 表已存在则跳过
    const check = await env.DB.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='rate_limits'"
    ).first();
    if (check) return;

    // 创建新表
    await env.DB.exec(`
      CREATE TABLE IF NOT EXISTS rate_limits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        action TEXT NOT NULL,
        window_key TEXT NOT NULL,
        count INTEGER DEFAULT 1,
        UNIQUE(user_id, action, window_key)
      );

      CREATE TABLE IF NOT EXISTS login_attempts (
        username TEXT PRIMARY KEY,
        attempts INTEGER DEFAULT 0,
        first_attempt_at TEXT,
        locked_until TEXT
      );

      CREATE TABLE IF NOT EXISTS favorites (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        photo_id TEXT NOT NULL,
        photo_url TEXT NOT NULL,
        photo_thumb TEXT NOT NULL,
        photographer TEXT NOT NULL,
        width INTEGER,
        height INTEGER,
        original_url TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        UNIQUE(user_id, photo_id)
      );
    `);

    // 尝试给 sessions 表添加过期字段（已存在则忽略）
    try {
      await env.DB.exec("ALTER TABLE sessions ADD COLUMN created_at TEXT DEFAULT (datetime('now'))");
    } catch (e) { /* 列可能已存在 */ }
    try {
      await env.DB.exec("ALTER TABLE sessions ADD COLUMN expires_at TEXT");
    } catch (e) { /* 列可能已存在 */ }
  } catch (e) {
    console.error('DB init error:', e);
  }
}

// ============ Session 管理（含过期检查）============

async function getUser(request, env) {
  const token = request.headers.get('Authorization')?.replace('Bearer ', '');
  if (!token) return null;

  const session = await env.DB.prepare(
    'SELECT user_id, created_at, expires_at FROM sessions WHERE token = ?'
  ).bind(token).first();

  if (!session) return null;

  // 检查 Session 是否过期
  const expiresAt = session.expires_at
    ? new Date(session.expires_at)
    : session.created_at
      ? new Date(new Date(session.created_at).getTime() + SESSION_EXPIRY_DAYS * 86400000)
      : null;

  if (expiresAt && new Date() > expiresAt) {
    await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
    return null;
  }

  const user = await env.DB.prepare(
    'SELECT id, username, created_at FROM users WHERE id = ?'
  ).bind(session.user_id).first();

  return user;
}

async function createSession(env, userId) {
  const token = generateToken();
  const now = new Date().toISOString();
  const expiresAt = new Date(Date.now() + SESSION_EXPIRY_DAYS * 86400000).toISOString();

  await env.DB.prepare(
    'INSERT INTO sessions (user_id, token, created_at, expires_at) VALUES (?, ?, ?, ?)'
  ).bind(userId, token, now, expiresAt).run();

  return token;
}

// ============ 频率限制 ============

async function checkRateLimit(env, userId, action, maxCount) {
  const windowKey = new Date().toISOString().slice(0, 13); // 按小时窗口 "2026-03-02T07"

  const existing = await env.DB.prepare(
    'SELECT count FROM rate_limits WHERE user_id = ? AND action = ? AND window_key = ?'
  ).bind(userId, action, windowKey).first();

  if (existing) {
    if (existing.count >= maxCount) {
      return { allowed: false, remaining: 0, limit: maxCount };
    }
    await env.DB.prepare(
      'UPDATE rate_limits SET count = count + 1 WHERE user_id = ? AND action = ? AND window_key = ?'
    ).bind(userId, action, windowKey).run();
    return { allowed: true, remaining: maxCount - existing.count - 1, limit: maxCount };
  }

  // 清理旧窗口记录
  await env.DB.prepare(
    'DELETE FROM rate_limits WHERE user_id = ? AND action = ? AND window_key != ?'
  ).bind(userId, action, windowKey).run();

  await env.DB.prepare(
    'INSERT INTO rate_limits (user_id, action, window_key, count) VALUES (?, ?, ?, 1)'
  ).bind(userId, action, windowKey).run();

  return { allowed: true, remaining: maxCount - 1, limit: maxCount };
}

// ============ 登录保护 ============

async function isLoginLocked(env, username) {
  const record = await env.DB.prepare(
    'SELECT attempts, locked_until FROM login_attempts WHERE username = ?'
  ).bind(username).first();

  if (!record) return { locked: false };

  if (record.locked_until) {
    const lockedUntil = new Date(record.locked_until);
    if (new Date() < lockedUntil) {
      const minutesLeft = Math.ceil((lockedUntil - new Date()) / 60000);
      return { locked: true, minutesLeft };
    }
    // 锁定已过期，重置
    await env.DB.prepare(
      'UPDATE login_attempts SET attempts = 0, locked_until = NULL WHERE username = ?'
    ).bind(username).run();
  }

  return { locked: false };
}

async function recordFailedLogin(env, username) {
  const record = await env.DB.prepare(
    'SELECT attempts FROM login_attempts WHERE username = ?'
  ).bind(username).first();

  if (record) {
    const newAttempts = record.attempts + 1;
    if (newAttempts >= MAX_LOGIN_ATTEMPTS) {
      const lockedUntil = new Date(Date.now() + LOCKOUT_MINUTES * 60000).toISOString();
      await env.DB.prepare(
        'UPDATE login_attempts SET attempts = ?, locked_until = ? WHERE username = ?'
      ).bind(newAttempts, lockedUntil, username).run();
      return { locked: true, minutesLeft: LOCKOUT_MINUTES };
    }
    await env.DB.prepare(
      'UPDATE login_attempts SET attempts = ? WHERE username = ?'
    ).bind(newAttempts, username).run();
    return { locked: false, attemptsLeft: MAX_LOGIN_ATTEMPTS - newAttempts };
  }

  await env.DB.prepare(
    'INSERT INTO login_attempts (username, attempts, first_attempt_at) VALUES (?, 1, ?)'
  ).bind(username, new Date().toISOString()).run();
  return { locked: false, attemptsLeft: MAX_LOGIN_ATTEMPTS - 1 };
}

async function clearLoginAttempts(env, username) {
  await env.DB.prepare('DELETE FROM login_attempts WHERE username = ?').bind(username).run();
}

// ============ 注册 ============

async function handleRegister(request, env) {
  try {
    const { username, password } = await request.json();

    if (!username || !password) {
      return json({ error: '用户名和密码不能为空' }, 400);
    }
    if (username.length < 3 || username.length > 20) {
      return json({ error: '用户名长度需要 3-20 个字符' }, 400);
    }
    if (password.length < 6) {
      return json({ error: '密码至少需要 6 个字符' }, 400);
    }

    const existing = await env.DB.prepare(
      'SELECT id FROM users WHERE username = ?'
    ).bind(username).first();

    if (existing) {
      return json({ error: '用户名已被注册' }, 409);
    }

    const salt = generateSalt();
    const passwordHash = await hashPassword(password, salt);

    const result = await env.DB.prepare(
      'INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)'
    ).bind(username, passwordHash, salt).run();

    const token = await createSession(env, result.meta.last_row_id);

    return json({ success: true, message: '注册成功', token, username });
  } catch (error) {
    return json({ error: '注册失败: ' + error.message }, 500);
  }
}

// ============ 登录（含防暴力破解）============

async function handleLogin(request, env) {
  try {
    const { username, password } = await request.json();

    if (!username || !password) {
      return json({ error: '用户名和密码不能为空' }, 400);
    }

    // 检查是否被锁定
    const lockStatus = await isLoginLocked(env, username);
    if (lockStatus.locked) {
      return json({
        error: `登录已被锁定，请 ${lockStatus.minutesLeft} 分钟后再试`,
        locked: true,
        minutesLeft: lockStatus.minutesLeft
      }, 429);
    }

    const user = await env.DB.prepare(
      'SELECT id, username, password_hash, salt FROM users WHERE username = ?'
    ).bind(username).first();

    if (!user) {
      const result = await recordFailedLogin(env, username);
      if (result.locked) {
        return json({ error: `连续登录失败 ${MAX_LOGIN_ATTEMPTS} 次，账户已锁定 ${LOCKOUT_MINUTES} 分钟`, locked: true }, 429);
      }
      return json({ error: `用户名或密码错误（还可尝试 ${result.attemptsLeft} 次）` }, 401);
    }

    const passwordHash = await hashPassword(password, user.salt);
    if (passwordHash !== user.password_hash) {
      const result = await recordFailedLogin(env, username);
      if (result.locked) {
        return json({ error: `连续登录失败 ${MAX_LOGIN_ATTEMPTS} 次，账户已锁定 ${LOCKOUT_MINUTES} 分钟`, locked: true }, 429);
      }
      return json({ error: `用户名或密码错误（还可尝试 ${result.attemptsLeft} 次）` }, 401);
    }

    // 登录成功，清除失败记录
    await clearLoginAttempts(env, username);

    const token = await createSession(env, user.id);

    return json({ success: true, token, username: user.username });
  } catch (error) {
    return json({ error: '登录失败: ' + error.message }, 500);
  }
}

// ============ 登出 ============

async function handleLogout(request, env) {
  try {
    const token = request.headers.get('Authorization')?.replace('Bearer ', '');
    if (token) {
      await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
    }
    return json({ success: true });
  } catch (error) {
    return json({ error: '登出失败' }, 500);
  }
}

// ============ 获取当前用户 ============

async function handleMe(request, env) {
  try {
    const user = await getUser(request, env);
    if (!user) return json({ error: '未登录' }, 401);
    return json({ username: user.username, created_at: user.created_at });
  } catch (error) {
    return json({ error: '获取用户信息失败' }, 500);
  }
}

// ============ Pexels 搜索代理（含频率限制）============

async function handleSearch(request, env, url) {
  try {
    const user = await getUser(request, env);
    if (!user) return json({ error: '未登录' }, 401);

    // 频率限制检查
    const rateCheck = await checkRateLimit(env, user.id, 'search', SEARCH_LIMIT_PER_HOUR);
    if (!rateCheck.allowed) {
      return json({
        error: '本小时搜索次数已用完，请稍后再试',
        rate: { remaining: 0, limit: rateCheck.limit }
      }, 429);
    }

    const query = url.searchParams.get('query') || '';
    const page = url.searchParams.get('page') || '1';
    const perPage = url.searchParams.get('per_page') || '20';

    if (!query.trim()) {
      return json({ error: '搜索词不能为空' }, 400);
    }

    const pexelsUrl = `https://api.pexels.com/v1/search?query=${encodeURIComponent(query)}&per_page=${perPage}&page=${page}`;
    const pexelsRes = await fetch(pexelsUrl, {
      headers: { 'Authorization': PEXELS_API_KEY }
    });

    if (!pexelsRes.ok) {
      if (pexelsRes.status === 429) {
        return json({ error: 'Pexels API 配额已达上限，请稍后再试' }, 429);
      }
      throw new Error('Pexels API 返回 ' + pexelsRes.status);
    }

    const data = await pexelsRes.json();

    return json({
      ...data,
      _rate: { remaining: rateCheck.remaining, limit: rateCheck.limit }
    });
  } catch (error) {
    return json({ error: '搜索失败: ' + error.message }, 500);
  }
}

// ============ 搜索历史 ============

async function handleGetHistory(request, env) {
  try {
    const user = await getUser(request, env);
    if (!user) return json({ error: '未登录' }, 401);

    const { results } = await env.DB.prepare(
      'SELECT id, query, created_at FROM search_history WHERE user_id = ? ORDER BY created_at DESC LIMIT 50'
    ).bind(user.id).all();

    return json({ history: results });
  } catch (error) {
    return json({ error: '获取历史失败' }, 500);
  }
}

async function handleSaveHistory(request, env) {
  try {
    const user = await getUser(request, env);
    if (!user) return json({ error: '未登录' }, 401);

    const { query } = await request.json();
    if (!query) return json({ error: '搜索词不能为空' }, 400);

    const last = await env.DB.prepare(
      'SELECT query FROM search_history WHERE user_id = ? ORDER BY created_at DESC LIMIT 1'
    ).bind(user.id).first();

    if (!last || last.query !== query) {
      await env.DB.prepare(
        'INSERT INTO search_history (user_id, query) VALUES (?, ?)'
      ).bind(user.id, query).run();
    }

    return json({ success: true });
  } catch (error) {
    return json({ error: '保存历史失败' }, 500);
  }
}

// ============ 收藏功能 ============

async function handleGetFavorites(request, env) {
  try {
    const user = await getUser(request, env);
    if (!user) return json({ error: '未登录' }, 401);

    const { results } = await env.DB.prepare(
      'SELECT id, photo_id, photo_url, photo_thumb, photographer, width, height, original_url, created_at FROM favorites WHERE user_id = ? ORDER BY created_at DESC LIMIT 200'
    ).bind(user.id).all();

    return json({ favorites: results });
  } catch (error) {
    return json({ error: '获取收藏失败' }, 500);
  }
}

async function handleAddFavorite(request, env) {
  try {
    const user = await getUser(request, env);
    if (!user) return json({ error: '未登录' }, 401);

    const { photo_id, photo_url, photo_thumb, photographer, width, height, original_url } = await request.json();

    if (!photo_id || !photo_url) {
      return json({ error: '参数缺失' }, 400);
    }

    await env.DB.prepare(
      'INSERT OR IGNORE INTO favorites (user_id, photo_id, photo_url, photo_thumb, photographer, width, height, original_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
    ).bind(user.id, String(photo_id), photo_url, photo_thumb || photo_url, photographer || '', width || 0, height || 0, original_url || photo_url).run();

    return json({ success: true });
  } catch (error) {
    return json({ error: '收藏失败: ' + error.message }, 500);
  }
}

async function handleRemoveFavorite(request, env) {
  try {
    const user = await getUser(request, env);
    if (!user) return json({ error: '未登录' }, 401);

    const { photo_id } = await request.json();
    if (!photo_id) return json({ error: '参数缺失' }, 400);

    await env.DB.prepare(
      'DELETE FROM favorites WHERE user_id = ? AND photo_id = ?'
    ).bind(user.id, String(photo_id)).run();

    return json({ success: true });
  } catch (error) {
    return json({ error: '取消收藏失败' }, 500);
  }
}

// ============ API 路由 ============

async function handleApi(request, env, url) {
  const path = url.pathname.replace('/api/', '');
  const method = request.method;

  // CORS 预检
  if (method === 'OPTIONS') {
    return new Response(null, {
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      }
    });
  }

  // 检查 D1 绑定
  if (!env.DB) {
    return json({ error: '数据库未绑定，请检查 Cloudflare D1 Binding 配置（变量名需为 DB）' }, 500);
  }

  // 自动初始化数据库表
  await ensureDB(env);

  // 路由分发
  if (path === 'register' && method === 'POST') return await handleRegister(request, env);
  if (path === 'login' && method === 'POST') return await handleLogin(request, env);
  if (path === 'logout' && method === 'POST') return await handleLogout(request, env);
  if (path === 'me' && method === 'GET') return await handleMe(request, env);
  if (path === 'search' && method === 'GET') return await handleSearch(request, env, url);
  if (path === 'history' && method === 'GET') return await handleGetHistory(request, env);
  if (path === 'history' && method === 'POST') return await handleSaveHistory(request, env);
  if (path === 'favorites' && method === 'GET') return await handleGetFavorites(request, env);
  if (path === 'favorites' && method === 'POST') return await handleAddFavorite(request, env);
  if (path === 'favorites' && method === 'DELETE') return await handleRemoveFavorite(request, env);

  return json({ error: 'API 路由不存在' }, 404);
}

// ============ 主入口 ============

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);

      if (url.pathname.startsWith('/api/')) {
        return await handleApi(request, env, url);
      }

      return env.ASSETS.fetch(request);
    } catch (error) {
      return new Response('Internal Server Error: ' + error.message, { status: 500 });
    }
  }
};
