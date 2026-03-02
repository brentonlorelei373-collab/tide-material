// ============ TIDE Material API ============
// Cloudflare Pages Functions + D1 Database

// ============ 工具函数 ============

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });
}

function generateSalt() {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');
}

function generateToken() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function hashPassword(password, salt) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password + salt);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function getUser(request, env) {
  const token = request.headers.get('Authorization')?.replace('Bearer ', '');
  if (!token) return null;

  const session = await env.DB.prepare(
    'SELECT user_id FROM sessions WHERE token = ?'
  ).bind(token).first();

  if (!session) return null;

  const user = await env.DB.prepare(
    'SELECT id, username, created_at FROM users WHERE id = ?'
  ).bind(session.user_id).first();

  return user;
}

// ============ 注册 ============

async function handleRegister(request, env) {
  try {
    const { username, password } = await request.json();

    if (!username || !password) {
      return jsonResponse({ error: '用户名和密码不能为空' }, 400);
    }

    if (username.length < 3 || username.length > 20) {
      return jsonResponse({ error: '用户名长度需要 3-20 个字符' }, 400);
    }

    if (password.length < 6) {
      return jsonResponse({ error: '密码至少需要 6 个字符' }, 400);
    }

    const existing = await env.DB.prepare(
      'SELECT id FROM users WHERE username = ?'
    ).bind(username).first();

    if (existing) {
      return jsonResponse({ error: '用户名已被注册' }, 409);
    }

    const salt = generateSalt();
    const passwordHash = await hashPassword(password, salt);

    const result = await env.DB.prepare(
      'INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)'
    ).bind(username, passwordHash, salt).run();

    // 注册后自动登录
    const token = generateToken();
    await env.DB.prepare(
      'INSERT INTO sessions (user_id, token) VALUES (?, ?)'
    ).bind(result.meta.last_row_id, token).run();

    return jsonResponse({
      success: true,
      message: '注册成功',
      token,
      username
    });
  } catch (error) {
    return jsonResponse({ error: '注册失败: ' + error.message }, 500);
  }
}

// ============ 登录 ============

async function handleLogin(request, env) {
  try {
    const { username, password } = await request.json();

    if (!username || !password) {
      return jsonResponse({ error: '用户名和密码不能为空' }, 400);
    }

    const user = await env.DB.prepare(
      'SELECT id, username, password_hash, salt FROM users WHERE username = ?'
    ).bind(username).first();

    if (!user) {
      return jsonResponse({ error: '用户名或密码错误' }, 401);
    }

    const passwordHash = await hashPassword(password, user.salt);

    if (passwordHash !== user.password_hash) {
      return jsonResponse({ error: '用户名或密码错误' }, 401);
    }

    const token = generateToken();
    await env.DB.prepare(
      'INSERT INTO sessions (user_id, token) VALUES (?, ?)'
    ).bind(user.id, token).run();

    return jsonResponse({
      success: true,
      token,
      username: user.username
    });
  } catch (error) {
    return jsonResponse({ error: '登录失败: ' + error.message }, 500);
  }
}

// ============ 登出 ============

async function handleLogout(request, env) {
  const token = request.headers.get('Authorization')?.replace('Bearer ', '');
  if (token) {
    await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
  }
  return jsonResponse({ success: true });
}

// ============ 获取当前用户 ============

async function handleMe(request, env) {
  const user = await getUser(request, env);
  if (!user) {
    return jsonResponse({ error: '未登录' }, 401);
  }
  return jsonResponse({ username: user.username, created_at: user.created_at });
}

// ============ 获取搜索历史 ============

async function handleGetHistory(request, env) {
  const user = await getUser(request, env);
  if (!user) {
    return jsonResponse({ error: '未登录' }, 401);
  }

  const { results } = await env.DB.prepare(
    'SELECT id, query, created_at FROM search_history WHERE user_id = ? ORDER BY created_at DESC LIMIT 50'
  ).bind(user.id).all();

  return jsonResponse({ history: results });
}

// ============ 保存搜索历史 ============

async function handleSaveHistory(request, env) {
  const user = await getUser(request, env);
  if (!user) {
    return jsonResponse({ error: '未登录' }, 401);
  }

  const { query } = await request.json();
  if (!query) {
    return jsonResponse({ error: '搜索词不能为空' }, 400);
  }

  // 避免重复保存相同的搜索词（最近一条如果相同就跳过）
  const last = await env.DB.prepare(
    'SELECT query FROM search_history WHERE user_id = ? ORDER BY created_at DESC LIMIT 1'
  ).bind(user.id).first();

  if (!last || last.query !== query) {
    await env.DB.prepare(
      'INSERT INTO search_history (user_id, query) VALUES (?, ?)'
    ).bind(user.id, query).run();
  }

  return jsonResponse({ success: true });
}

// ============ 主路由 ============

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = url.pathname.replace('/api/', '');
  const method = request.method;

  // CORS 预检
  if (method === 'OPTIONS') {
    return new Response(null, {
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      }
    });
  }

  // 路由分发
  if (path === 'register' && method === 'POST') return handleRegister(request, env);
  if (path === 'login' && method === 'POST') return handleLogin(request, env);
  if (path === 'logout' && method === 'POST') return handleLogout(request, env);
  if (path === 'me' && method === 'GET') return handleMe(request, env);
  if (path === 'history' && method === 'GET') return handleGetHistory(request, env);
  if (path === 'history' && method === 'POST') return handleSaveHistory(request, env);

  return jsonResponse({ error: 'Not Found' }, 404);
}
