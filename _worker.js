// ============ TIDE Material API v3 — 超级素材搜索 ============
// Cloudflare Pages _worker.js
// 功能: 用户认证, 多API搜索代理(Pexels/Pixabay/GIPHY/GNews), 频率限制, Session过期, 登录保护, 收藏

// ============ 配置 ============
// API Keys 从 Cloudflare 环境变量读取（通过 wrangler secret put 设置）
// 在 handleApi 中从 env 读取并传递给各 handler

const SESSION_EXPIRY_DAYS = 7;
const SEARCH_LIMIT_PER_HOUR = 50; // 提升到50次，因为现在有更多搜索类型
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
    try {
      const cols = await env.DB.prepare("PRAGMA table_info(sessions)").all();
      const hasExpires = cols.results.some(c => c.name === 'expires_at');
      if (!hasExpires) {
        await env.DB.prepare("ALTER TABLE sessions ADD COLUMN expires_at TEXT").run();
      }
    } catch (e) { /* ignore */ }

    const check = await env.DB.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='login_attempts'"
    ).first();
    if (check) return;

    await env.DB.batch([
      env.DB.prepare(`CREATE TABLE IF NOT EXISTS rate_limits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        action TEXT NOT NULL,
        window_key TEXT NOT NULL,
        count INTEGER DEFAULT 1,
        UNIQUE(user_id, action, window_key)
      )`),
      env.DB.prepare(`CREATE TABLE IF NOT EXISTS login_attempts (
        username TEXT PRIMARY KEY,
        attempts INTEGER DEFAULT 0,
        first_attempt_at TEXT,
        locked_until TEXT
      )`),
      env.DB.prepare(`CREATE TABLE IF NOT EXISTS favorites (
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
      )`)
    ]);
  } catch (e) {
    console.error('DB init error:', e);
  }
}

// ============ Session 管理 ============

async function getUser(request, env) {
  const token = request.headers.get('Authorization')?.replace('Bearer ', '');
  if (!token) return null;

  const session = await env.DB.prepare(
    'SELECT user_id, created_at, expires_at FROM sessions WHERE token = ?'
  ).bind(token).first();

  if (!session) return null;

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
  const windowKey = new Date().toISOString().slice(0, 13);

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

    if (!username || !password) return json({ error: '用户名和密码不能为空' }, 400);
    if (username.length < 3 || username.length > 20) return json({ error: '用户名长度需要 3-20 个字符' }, 400);
    if (password.length < 6) return json({ error: '密码至少需要 6 个字符' }, 400);

    const existing = await env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username).first();
    if (existing) return json({ error: '用户名已被注册' }, 409);

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

// ============ 登录 ============

async function handleLogin(request, env) {
  try {
    const { username, password } = await request.json();
    if (!username || !password) return json({ error: '用户名和密码不能为空' }, 400);

    const lockStatus = await isLoginLocked(env, username);
    if (lockStatus.locked) {
      return json({ error: `登录已被锁定，请 ${lockStatus.minutesLeft} 分钟后再试`, locked: true, minutesLeft: lockStatus.minutesLeft }, 429);
    }

    const user = await env.DB.prepare(
      'SELECT id, username, password_hash, salt FROM users WHERE username = ?'
    ).bind(username).first();

    if (!user) {
      const result = await recordFailedLogin(env, username);
      if (result.locked) return json({ error: `连续登录失败 ${MAX_LOGIN_ATTEMPTS} 次，账户已锁定 ${LOCKOUT_MINUTES} 分钟`, locked: true }, 429);
      return json({ error: `用户名或密码错误（还可尝试 ${result.attemptsLeft} 次）` }, 401);
    }

    const passwordHash = await hashPassword(password, user.salt);
    if (passwordHash !== user.password_hash) {
      const result = await recordFailedLogin(env, username);
      if (result.locked) return json({ error: `连续登录失败 ${MAX_LOGIN_ATTEMPTS} 次，账户已锁定 ${LOCKOUT_MINUTES} 分钟`, locked: true }, 429);
      return json({ error: `用户名或密码错误（还可尝试 ${result.attemptsLeft} 次）` }, 401);
    }

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
    if (token) await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
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

// ============ 搜索：Pexels 图片 ============

async function handleSearchPhoto(request, env, url) {
  try {
    const user = await getUser(request, env);
    if (!user) return json({ error: '未登录' }, 401);

    const rateCheck = await checkRateLimit(env, user.id, 'search', SEARCH_LIMIT_PER_HOUR);
    if (!rateCheck.allowed) return json({ error: '本小时搜索次数已用完，请稍后再试', rate: { remaining: 0, limit: rateCheck.limit } }, 429);

    const query = url.searchParams.get('query') || '';
    const page = url.searchParams.get('page') || '1';
    const perPage = url.searchParams.get('per_page') || '20';
    if (!query.trim()) return json({ error: '搜索词不能为空' }, 400);

    const pexelsUrl = `https://api.pexels.com/v1/search?query=${encodeURIComponent(query)}&per_page=${perPage}&page=${page}`;
    const pexelsRes = await fetch(pexelsUrl, { headers: { 'Authorization': env.PEXELS_API_KEY } });

    if (!pexelsRes.ok) {
      if (pexelsRes.status === 429) return json({ error: 'Pexels API 配额已达上限' }, 429);
      throw new Error('Pexels API 返回 ' + pexelsRes.status);
    }

    const data = await pexelsRes.json();
    return json({ ...data, _rate: { remaining: rateCheck.remaining, limit: rateCheck.limit } });
  } catch (error) {
    return json({ error: '搜索失败: ' + error.message }, 500);
  }
}

// ============ 搜索：Pexels 视频 ============

async function handleSearchVideo(request, env, url) {
  try {
    const user = await getUser(request, env);
    if (!user) return json({ error: '未登录' }, 401);

    const rateCheck = await checkRateLimit(env, user.id, 'search', SEARCH_LIMIT_PER_HOUR);
    if (!rateCheck.allowed) return json({ error: '本小时搜索次数已用完', rate: { remaining: 0, limit: rateCheck.limit } }, 429);

    const query = url.searchParams.get('query') || '';
    const page = url.searchParams.get('page') || '1';
    const perPage = url.searchParams.get('per_page') || '15';
    if (!query.trim()) return json({ error: '搜索词不能为空' }, 400);

    const pexelsUrl = `https://api.pexels.com/videos/search?query=${encodeURIComponent(query)}&per_page=${perPage}&page=${page}`;
    const pexelsRes = await fetch(pexelsUrl, { headers: { 'Authorization': env.PEXELS_API_KEY } });

    if (!pexelsRes.ok) {
      if (pexelsRes.status === 429) return json({ error: 'Pexels Video API 配额已达上限' }, 429);
      throw new Error('Pexels Video API 返回 ' + pexelsRes.status);
    }

    const data = await pexelsRes.json();
    return json({ ...data, _rate: { remaining: rateCheck.remaining, limit: rateCheck.limit } });
  } catch (error) {
    return json({ error: '视频搜索失败: ' + error.message }, 500);
  }
}

// ============ 搜索：Pixabay 插画 ============

async function handleSearchIllustration(request, env, url) {
  try {
    if (!env.PIXABAY_API_KEY) return json({ error: 'Pixabay API Key 未配置，请在 Cloudflare 环境变量中设置 PIXABAY_API_KEY' }, 503);

    const user = await getUser(request, env);
    if (!user) return json({ error: '未登录' }, 401);

    const rateCheck = await checkRateLimit(env, user.id, 'search', SEARCH_LIMIT_PER_HOUR);
    if (!rateCheck.allowed) return json({ error: '本小时搜索次数已用完', rate: { remaining: 0, limit: rateCheck.limit } }, 429);

    const query = url.searchParams.get('query') || '';
    const page = url.searchParams.get('page') || '1';
    const perPage = url.searchParams.get('per_page') || '20';
    if (!query.trim()) return json({ error: '搜索词不能为空' }, 400);

    const pixabayUrl = `https://pixabay.com/api/?key=${env.PIXABAY_API_KEY}&q=${encodeURIComponent(query)}&per_page=${perPage}&page=${page}&image_type=illustration&safesearch=true`;
    const pixRes = await fetch(pixabayUrl);

    if (!pixRes.ok) throw new Error('Pixabay API 返回 ' + pixRes.status);

    const data = await pixRes.json();
    return json({ ...data, _rate: { remaining: rateCheck.remaining, limit: rateCheck.limit } });
  } catch (error) {
    return json({ error: '插画搜索失败: ' + error.message }, 500);
  }
}

// ============ 搜索：GIPHY GIF ============

async function handleSearchGif(request, env, url) {
  try {
    if (!env.GIPHY_API_KEY) return json({ error: 'GIPHY API Key 未配置，请在 Cloudflare 环境变量中设置 GIPHY_API_KEY' }, 503);

    const user = await getUser(request, env);
    if (!user) return json({ error: '未登录' }, 401);

    const rateCheck = await checkRateLimit(env, user.id, 'search', SEARCH_LIMIT_PER_HOUR);
    if (!rateCheck.allowed) return json({ error: '本小时搜索次数已用完', rate: { remaining: 0, limit: rateCheck.limit } }, 429);

    const query = url.searchParams.get('query') || '';
    const offset = url.searchParams.get('offset') || '0';
    const limit = url.searchParams.get('limit') || '20';
    if (!query.trim()) return json({ error: '搜索词不能为空' }, 400);

    const giphyUrl = `https://api.giphy.com/v1/gifs/search?api_key=${env.GIPHY_API_KEY}&q=${encodeURIComponent(query)}&limit=${limit}&offset=${offset}&rating=g&lang=en`;
    const giphyRes = await fetch(giphyUrl);

    if (!giphyRes.ok) throw new Error('GIPHY API 返回 ' + giphyRes.status);

    const data = await giphyRes.json();
    return json({ ...data, _rate: { remaining: rateCheck.remaining, limit: rateCheck.limit } });
  } catch (error) {
    return json({ error: 'GIF搜索失败: ' + error.message }, 500);
  }
}

// ============ 搜索：GNews 新闻 ============

async function handleSearchNews(request, env, url) {
  try {
    if (!env.GNEWS_API_KEY) return json({ error: 'GNews API Key 未配置，请在 Cloudflare 环境变量中设置 GNEWS_API_KEY' }, 503);

    const user = await getUser(request, env);
    if (!user) return json({ error: '未登录' }, 401);

    const rateCheck = await checkRateLimit(env, user.id, 'search', SEARCH_LIMIT_PER_HOUR);
    if (!rateCheck.allowed) return json({ error: '本小时搜索次数已用完', rate: { remaining: 0, limit: rateCheck.limit } }, 429);

    const query = url.searchParams.get('query') || '';
    if (!query.trim()) return json({ error: '搜索词不能为空' }, 400);

    // 检测是否包含中文字符，自动选择语言
    const hasChinese = /[\u4e00-\u9fff]/.test(query);
    const lang = hasChinese ? 'zh' : 'en';
    const gnewsUrl = `https://gnews.io/api/v4/search?q=${encodeURIComponent(query)}&lang=${lang}&max=10&token=${env.GNEWS_API_KEY}`;
    const gnewsRes = await fetch(gnewsUrl);

    if (!gnewsRes.ok) throw new Error('GNews API 返回 ' + gnewsRes.status);

    const data = await gnewsRes.json();
    return json({ ...data, _rate: { remaining: rateCheck.remaining, limit: rateCheck.limit } });
  } catch (error) {
    return json({ error: '新闻搜索失败: ' + error.message }, 500);
  }
}

// ============ 搜索：名言（后端代理）============

async function handleSearchQuotes(request, env, url) {
  try {
    const query = url.searchParams.get('query') || '';
    if (!query.trim()) return json({ error: '搜索词不能为空' }, 400);

    let quotes = [];

    // 方案1: 尝试 Quotable API
    try {
      const res = await fetch(`https://api.quotable.io/search/quotes?query=${encodeURIComponent(query)}&limit=10`);
      if (res.ok) {
        const data = await res.json();
        quotes = (data.results || []).map(r => ({ content: r.content, author: r.author, tags: r.tags || [] }));
      }
    } catch (e) { /* fallback */ }

    // 方案2: 如果 Quotable 失败，用 ZenQuotes
    if (quotes.length === 0) {
      try {
        const res = await fetch('https://zenquotes.io/api/quotes');
        if (res.ok) {
          const data = await res.json();
          if (Array.isArray(data)) {
            const q = query.toLowerCase();
            // 过滤匹配关键词的名言
            const matched = data.filter(d => d.q && (d.q.toLowerCase().includes(q) || d.a?.toLowerCase().includes(q)));
            const source = matched.length > 0 ? matched : data;
            quotes = source.filter(d => d.q && d.a !== 'zenquotes.io').slice(0, 15).map(d => ({ content: d.q, author: d.a || 'Unknown', tags: [] }));
          }
        }
      } catch (e) { /* fallback */ }
    }

    // 方案3: 如果全部失败，用 Forismatic + 内置名言库
    if (quotes.length === 0) {
      quotes = getBuiltinQuotes(query);
    }

    return json({ quotes });
  } catch (error) {
    return json({ error: '名言搜索失败: ' + error.message }, 500);
  }
}

// 内置名言库（兜底）
function getBuiltinQuotes(query) {
  const allQuotes = [
    { content: "The only way to do great work is to love what you do.", author: "Steve Jobs", tags: ["success", "work", "inspirational"] },
    { content: "Innovation distinguishes between a leader and a follower.", author: "Steve Jobs", tags: ["success", "leadership"] },
    { content: "Life is what happens when you're busy making other plans.", author: "John Lennon", tags: ["life", "wisdom"] },
    { content: "The future belongs to those who believe in the beauty of their dreams.", author: "Eleanor Roosevelt", tags: ["inspirational", "success"] },
    { content: "It is during our darkest moments that we must focus to see the light.", author: "Aristotle", tags: ["inspirational", "wisdom"] },
    { content: "The only impossible journey is the one you never begin.", author: "Tony Robbins", tags: ["inspirational", "success"] },
    { content: "In the middle of difficulty lies opportunity.", author: "Albert Einstein", tags: ["wisdom", "success"] },
    { content: "Success is not final, failure is not fatal: it is the courage to continue that counts.", author: "Winston Churchill", tags: ["success", "courage"] },
    { content: "Believe you can and you're halfway there.", author: "Theodore Roosevelt", tags: ["inspirational", "success"] },
    { content: "The best time to plant a tree was 20 years ago. The second best time is now.", author: "Chinese Proverb", tags: ["wisdom", "life"] },
    { content: "Happiness is not something ready made. It comes from your own actions.", author: "Dalai Lama", tags: ["happiness", "wisdom"] },
    { content: "Be yourself; everyone else is already taken.", author: "Oscar Wilde", tags: ["life", "wisdom"] },
    { content: "Two things are infinite: the universe and human stupidity; and I'm not sure about the universe.", author: "Albert Einstein", tags: ["wisdom", "humor"] },
    { content: "You miss 100% of the shots you don't take.", author: "Wayne Gretzky", tags: ["success", "inspirational"] },
    { content: "The only limit to our realization of tomorrow will be our doubts of today.", author: "Franklin D. Roosevelt", tags: ["inspirational", "success"] },
    { content: "Do what you can, with what you have, where you are.", author: "Theodore Roosevelt", tags: ["inspirational", "life"] },
    { content: "Everything you've ever wanted is on the other side of fear.", author: "George Addair", tags: ["courage", "inspirational"] },
    { content: "The mind is everything. What you think you become.", author: "Buddha", tags: ["wisdom", "life"] },
    { content: "Strive not to be a success, but rather to be of value.", author: "Albert Einstein", tags: ["success", "life"] },
    { content: "The best revenge is massive success.", author: "Frank Sinatra", tags: ["success", "inspirational"] },
    { content: "Love all, trust a few, do wrong to none.", author: "William Shakespeare", tags: ["love", "wisdom"] },
    { content: "To love and be loved is to feel the sun from both sides.", author: "David Viscott", tags: ["love", "happiness"] },
    { content: "Where there is love there is life.", author: "Mahatma Gandhi", tags: ["love", "life"] },
    { content: "The greatest glory in living lies not in never falling, but in rising every time we fall.", author: "Nelson Mandela", tags: ["inspirational", "courage"] },
    { content: "It does not matter how slowly you go as long as you do not stop.", author: "Confucius", tags: ["wisdom", "success"] },
  ];
  const q = query.toLowerCase();
  const matched = allQuotes.filter(quote =>
    quote.content.toLowerCase().includes(q) ||
    quote.author.toLowerCase().includes(q) ||
    quote.tags.some(t => t.includes(q))
  );
  return matched.length > 0 ? matched : allQuotes.slice(0, 10);
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
      await env.DB.prepare('INSERT INTO search_history (user_id, query) VALUES (?, ?)').bind(user.id, query).run();
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
    if (!photo_id || !photo_url) return json({ error: '参数缺失' }, 400);
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
    await env.DB.prepare('DELETE FROM favorites WHERE user_id = ? AND photo_id = ?').bind(user.id, String(photo_id)).run();
    return json({ success: true });
  } catch (error) {
    return json({ error: '取消收藏失败' }, 500);
  }
}

// ============ AI 叙事生成 ============

async function handleGenerateNarrative(request, env) {
  try {
    const user = await getUser(request, env);
    if (!user) return json({ error: '未登录' }, 401);

    // AI 频率限制：每小时 20 次
    const rateCheck = await checkRateLimit(env, user.id, 'ai_narrative', 20);
    if (!rateCheck.allowed) return json({ error: '本小时 AI 生成次数已用完，请稍后再试' }, 429);

    const { keyword, materials } = await request.json();
    if (!keyword || !materials || materials.length === 0) {
      return json({ error: '关键词和素材不能为空' }, 400);
    }

    // 检查 AI binding 是否可用
    if (!env.AI) {
      return json({ error: 'AI 未配置', fallback: true }, 503);
    }

    // 组装素材上下文
    let context = '';

    const photos = materials.filter(m => ['photo','video','gif','illustration'].includes(m.type));
    const newsItems = materials.filter(m => m.type === 'news');
    const wikiItems = materials.filter(m => m.type === 'wiki');
    const bookItems = materials.filter(m => m.type === 'book');
    const quoteItems = materials.filter(m => m.type === 'quote');

    if (photos.length > 0) {
      context += '【视觉素材】\n';
      photos.forEach(p => { context += `- ${p.alt || '一张图片'} (摄影师: ${p.photographer || '未知'})\n`; });
      context += '\n';
    }

    if (wikiItems.length > 0) {
      context += '【百科背景】\n';
      wikiItems.forEach(w => { context += `${w.title}: ${(w.snippet || '').substring(0, 400)}\n`; });
      context += '\n';
    }

    if (bookItems.length > 0) {
      context += '【参考书目】\n';
      bookItems.forEach(b => { context += `《${b.title}》${b.author || ''} ${b.year ? '(' + b.year + ')' : ''} ${b.subjects ? '涉及领域: ' + b.subjects : ''}\n`; });
      context += '\n';
    }

    if (newsItems.length > 0) {
      context += '【相关新闻】\n';
      newsItems.forEach(n => { context += `${n.title}\n${n.description || ''}\n来源: ${n.source || '未知'}\n\n`; });
    }

    if (quoteItems.length > 0) {
      context += '【名言引用】\n';
      quoteItems.forEach(q => { context += `"${q.content}" —— ${q.author || '佚名'}\n`; });
      context += '\n';
    }

    const systemPrompt = `你是 TIDE 叙事卡片的创作引擎。你的任务是基于用户提供的主题关键词和多类型素材（图片、新闻、百科、书籍、名言），生成一段精炼、有叙事感的中文短文。

要求：
1. 返回严格 JSON 格式，包含以下字段：
   - "title": 叙事标题（10-20字，有文学感，与关键词相关）
   - "subtitle": 副标题（简短一句话）
   - "opening": 开场白（2-3句，引出主题，有画面感）
   - "background": 如果有百科/书籍素材，写一段知识性背景描述（2-4句）；没有则返回空字符串
   - "event": 如果有新闻素材，写一段将新闻事件融入叙事的段落（2-3句）；没有则返回空字符串
   - "reflection": 如果有名言素材，写一段融入名言的思考段落（2-3句，不要直接引用原文，用叙事方式呼应）；没有则返回空字符串
   - "closing": 收束语（1-2句，余韵悠长）
   - "toEvent": 从背景到事件的过渡句（1句）
   - "toReflection": 从事件到思考的过渡句（1句）
2. 文风：冷静、克制、有画面感、略带诗意
3. 不要使用 markdown 格式，纯文本
4. 只返回 JSON，不要任何额外说明`;

    const userPrompt = `主题关键词：${keyword}\n\n素材：\n${context}\n\n请生成叙事卡片内容（严格 JSON 格式）。`;

    const aiResponse = await env.AI.run('@cf/qwen/qwen1.5-7b-chat-awq', {
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userPrompt }
      ],
      max_tokens: 1200,
      temperature: 0.7,
    });

    const text = aiResponse.response || '';

    // 尝试解析 JSON
    let parsed = null;
    try {
      // 尝试直接解析
      parsed = JSON.parse(text);
    } catch (e) {
      // 尝试从文本中提取 JSON
      const jsonMatch = text.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        try { parsed = JSON.parse(jsonMatch[0]); } catch (e2) { /* fallback */ }
      }
    }

    if (parsed && parsed.title) {
      return json({
        success: true,
        narrative: {
          title: parsed.title || '',
          subtitle: parsed.subtitle || '',
          opening: parsed.opening || '',
          background: parsed.background || '',
          event: parsed.event || '',
          reflection: parsed.reflection || '',
          closing: parsed.closing || '',
          toEvent: parsed.toEvent || '',
          toReflection: parsed.toReflection || '',
        },
        _rate: { remaining: rateCheck.remaining, limit: 20 }
      });
    }

    // AI 返回格式异常，告知前端用模板降级
    return json({ error: 'AI 返回格式异常', fallback: true, raw: text.substring(0, 500) }, 200);

  } catch (error) {
    console.error('AI narrative error:', error);
    return json({ error: 'AI 生成失败: ' + error.message, fallback: true }, 200);
  }
}

// ============ AI 文生图 ============

async function handleGenerateImage(request, env) {
  try {
    const user = await getUser(request, env);
    if (!user) return json({ error: '未登录' }, 401);

    // 频率限制：每小时 10 次
    const rateCheck = await checkRateLimit(env, user.id, 'ai_image', 10);
    if (!rateCheck.allowed) return json({ error: '本小时 AI 绘图次数已用完，请稍后再试' }, 429);

    const { prompt } = await request.json();
    if (!prompt || !prompt.trim()) return json({ error: '绘图描述不能为空' }, 400);

    if (!env.AI) return json({ error: 'AI 未配置' }, 503);

    // 调用 Stable Diffusion XL
    const imageResponse = await env.AI.run('@cf/bytedance/stable-diffusion-xl-lightning', {
      prompt: prompt.trim(),
      num_steps: 4,
    });

    // imageResponse 是 ReadableStream（PNG 格式）
    return new Response(imageResponse, {
      headers: {
        'Content-Type': 'image/png',
        'Access-Control-Allow-Origin': '*',
        'X-Rate-Remaining': String(rateCheck.remaining),
        'X-Rate-Limit': '10',
      }
    });
  } catch (error) {
    console.error('AI image error:', error);
    return json({ error: 'AI 绘图失败: ' + error.message }, 500);
  }
}

// ============ Tool: 直接获取 YouTube 字幕/转录 ============

function extractVideoId(url) {
  const patterns = [
    /[?&]v=([a-zA-Z0-9_-]{11})/,
    /youtu\.be\/([a-zA-Z0-9_-]{11})/,
    /youtube\.com\/embed\/([a-zA-Z0-9_-]{11})/,
    /youtube\.com\/shorts\/([a-zA-Z0-9_-]{11})/,
  ];
  for (const p of patterns) {
    const m = url.match(p);
    if (m) return m[1];
  }
  return null;
}

async function fetchYoutubeTranscript(videoUrl) {
  const videoId = extractVideoId(videoUrl);
  if (!videoId) throw new Error('无效的 YouTube 链接，请确认格式正确');

  const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';

  // Step 1: 获取字幕列表
  const listUrl = `https://www.youtube.com/api/timedtext?type=list&v=${videoId}`;
  const listResp = await fetch(listUrl, { headers: { 'User-Agent': UA } });

  if (!listResp.ok) throw new Error('无法获取字幕信息，请检查视频链接');

  const listXml = await listResp.text();

  // 解析可用字幕轨道（包括自动生成字幕 kind="asr"）
  const tracks = [];
  const re = /<track[^>]+id="(\d+)"[^>]+name="([^"]*)"[^>]+lang_code="([^"]+)"[^>]*(?:kind="([^"]*)")?/g;
  let m;
  while ((m = re.exec(listXml)) !== null) {
    tracks.push({ id: m[1], name: m[2], lang: m[3], kind: m[4] || '' });
  }

  // 也尝试不带 kind 属性的格式
  const re2 = /<track[^>]+lang_code="([^"]+)"/g;
  const seen = new Set(tracks.map(t => t.lang));
  while ((m = re2.exec(listXml)) !== null) {
    if (!seen.has(m[1])) {
      tracks.push({ lang: m[1], kind: '' });
      seen.add(m[1]);
    }
  }

  if (tracks.length === 0) {
    throw new Error('该视频暂无字幕/转录文本，请切换到「上传音频」模式');
  }

  // 优先选择中文，其次英文，再选第一个
  const preferred = ['zh-Hans', 'zh-Hant', 'zh', 'zh-CN', 'zh-TW', 'en'];
  let selected = null;
  for (const lang of preferred) {
    selected = tracks.find(t => t.lang === lang);
    if (selected) break;
  }
  if (!selected) selected = tracks[0];

  // Step 2: 获取字幕内容（JSON3 格式）
  let transcriptUrl = `https://www.youtube.com/api/timedtext?v=${videoId}&lang=${selected.lang}&fmt=json3`;
  if (selected.kind === 'asr') transcriptUrl += '&kind=asr';

  const transResp = await fetch(transcriptUrl, { headers: { 'User-Agent': UA } });
  if (!transResp.ok) throw new Error('字幕文件获取失败，请稍后重试');

  const transData = await transResp.json();

  if (!transData.events || transData.events.length === 0) {
    throw new Error('字幕内容为空，请切换到「上传音频」模式');
  }

  // Step 3: 拼成纯文本
  const text = transData.events
    .filter(e => e.segs)
    .map(e => e.segs.map(s => (s.utf8 || '').replace(/\n/g, ' ')).join(''))
    .filter(t => t.trim())
    .join(' ')
    .replace(/\s+/g, ' ')
    .trim();

  if (!text) throw new Error('字幕内容为空，请切换到「上传音频」模式');

  return text;
}

// ============ Tool: 音频转录（Groq Whisper） ============

const RAILWAY_BACKEND = 'https://web-production-47b90.up.railway.app';

async function handleToolTranscribe(request) {
  try {
    const contentType = request.headers.get('Content-Type') || '';

    if (contentType.includes('multipart/form-data')) {
      // 模式 A：上传音频文件 → 直接调 Groq
      const formData = await request.formData();
      const apiKey = (formData.get('api_key') || '').trim();
      const audioFile = formData.get('audio');
      if (!audioFile) return json({ error: '请选择音频文件' }, 400);
      if (!apiKey) return json({ error: '请输入 Groq API Key' }, 400);

      const groqForm = new FormData();
      groqForm.append('file', audioFile, audioFile.name || 'audio.mp3');
      groqForm.append('model', 'whisper-large-v3');

      const groqResp = await fetch('https://api.groq.com/openai/v1/audio/transcriptions', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${apiKey}` },
        body: groqForm,
      });

      if (!groqResp.ok) {
        const err = await groqResp.json().catch(() => ({}));
        if (groqResp.status === 401) return json({ error: 'Groq API Key 无效，请检查后重试' }, 401);
        if (groqResp.status === 413) return json({ error: '文件过大，Groq 最大支持 25 MB' }, 413);
        return json({ error: err.error?.message || `转录失败 (HTTP ${groqResp.status})` }, groqResp.status);
      }

      const data = await groqResp.json();
      return json({ success: true, transcript: data.text });

    } else {
      // 模式 B：YouTube URL → 代理到 Railway（yt-dlp + Groq Whisper）
      const body = await request.json();
      const apiKey = (body.api_key || '').trim();
      const videoUrl = (body.url || '').trim();
      if (!videoUrl) return json({ error: '请提供视频链接' }, 400);
      if (!apiKey) return json({ error: '请输入 Groq API Key' }, 400);

      // 调用 Railway SSE 端点，收集事件直到 done/error
      const railwayResp = await fetch(`${RAILWAY_BACKEND}/transcribe`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: videoUrl, api_key: apiKey }),
      });

      if (!railwayResp.ok) {
        return json({ error: `后端服务异常 (HTTP ${railwayResp.status})` }, 502);
      }

      // 读取 SSE 流，提取最终结果
      const reader = railwayResp.body.getReader();
      const decoder = new TextDecoder();
      let buf = '';
      let transcript = null;
      let errorMsg = null;

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const lines = buf.split('\n');
        buf = lines.pop();
        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          try {
            const evt = JSON.parse(line.slice(6));
            if (evt.status === 'done') transcript = evt.transcript;
            if (evt.status === 'error') errorMsg = evt.message;
          } catch {}
        }
      }

      if (errorMsg) return json({ error: errorMsg }, 502);
      if (!transcript) return json({ error: '转录失败，未收到结果' }, 502);
      return json({ success: true, transcript });
    }
  } catch (error) {
    return json({ error: '转录失败: ' + error.message }, 500);
  }
}

// ============ Tool: 翻译（Groq LLaMA） ============

async function handleToolTranslate(request) {
  try {
    const { text, target = 'zh', api_key } = await request.json();
    if (!text?.trim()) return json({ error: '没有可翻译的内容' }, 400);
    if (!api_key?.trim()) return json({ error: '请输入 Groq API Key' }, 400);

    const langName = target === 'zh' ? 'Simplified Chinese (简体中文)' : 'English';
    const systemPrompt = `You are a professional translator.
Translate the user's text into ${langName}.
Rules:
1. If the text is already written in ${langName}, output exactly the token: ALREADY_TARGET_LANGUAGE — nothing else.
2. Otherwise output ONLY the translated text.
3. Preserve paragraph structure (blank lines between paragraphs).
4. Do NOT add any explanation, prefix, or notes.`;

    const groqResp = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${api_key}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'llama-3.3-70b-versatile',
        messages: [{ role: 'system', content: systemPrompt }, { role: 'user', content: text }],
        stream: false, max_tokens: 8192, temperature: 0.2,
      }),
    });

    if (!groqResp.ok) {
      if (groqResp.status === 401) return json({ error: 'Groq API Key 无效，请检查后重试' }, 401);
      return json({ error: '翻译失败，请稍后重试' }, groqResp.status);
    }

    const data = await groqResp.json();
    const result = data.choices[0]?.message?.content || '';
    if (result.includes('ALREADY_TARGET_LANGUAGE')) {
      const msg = target === 'zh' ? '已经是中文了，无需翻译' : 'Already in English, no translation needed.';
      return json({ already: true, message: msg });
    }
    return json({ success: true, result });
  } catch (error) {
    return json({ error: '翻译失败: ' + error.message }, 500);
  }
}

// ============ Tool: 格式化（Groq LLaMA） ============

async function handleToolFormat(request) {
  try {
    const { transcript, api_key } = await request.json();
    if (!transcript?.trim()) return json({ error: '没有可整理的内容' }, 400);
    if (!api_key?.trim()) return json({ error: '请输入 Groq API Key' }, 400);

    const systemPrompt = `You are a professional text editor.
I will give you a raw auto-transcribed transcript from a video. It may lack punctuation, have messy paragraphs, and contain spoken filler words.
Your tasks:
1. Add appropriate punctuation marks.
2. Split the content into logical paragraphs based on meaning; separate paragraphs with a blank line.
3. Remove obvious spoken fillers and repetitions (e.g. 'um', 'you know', 'like', '那个', '就是说', '嗯' etc.) to improve readability.
4. IMPORTANT: Keep the ORIGINAL LANGUAGE exactly as-is. If the transcript is in English, output English. If it is in Chinese, output Chinese. Do NOT translate.
5. Preserve the core meaning; do not add or remove content.
6. Output ONLY the edited text. No explanations, no prefixes.`;

    const groqResp = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${api_key}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'llama-3.3-70b-versatile',
        messages: [{ role: 'system', content: systemPrompt }, { role: 'user', content: transcript }],
        stream: false, max_tokens: 8192, temperature: 0.3,
      }),
    });

    if (!groqResp.ok) {
      if (groqResp.status === 401) return json({ error: 'Groq API Key 无效，请检查后重试' }, 401);
      return json({ error: '格式化失败，请稍后重试' }, groqResp.status);
    }

    const data = await groqResp.json();
    const result = data.choices[0]?.message?.content || '';
    return json({ success: true, result });
  } catch (error) {
    return json({ error: '格式化失败: ' + error.message }, 500);
  }
}

// ============ Tool: Google 实时热搜（Trends RSS） ============

async function handleToolTrends(url) {
  try {
    const geo = url.searchParams.get('geo') || 'US';
    const rssUrl = `https://trends.google.com/trending/rss?geo=${geo}`;

    const resp = await fetch(rssUrl, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
      },
    });

    if (!resp.ok) {
      if (resp.status === 404) return json({ error: 'Google Trends 该地区暂不支持热搜榜，请换其他地区' }, 404);
      throw new Error('HTTP ' + resp.status);
    }

    const xml = await resp.text();

    // 用正则从 XML 中提取 <title>
    const keywords = [];
    const re = /<item>[\s\S]*?<title>([\s\S]*?)<\/title>/g;
    let m;
    while ((m = re.exec(xml)) !== null) {
      const kw = m[1].replace(/<!\[CDATA\[|\]\]>/g, '').trim();
      if (kw) keywords.push(kw);
    }

    if (keywords.length === 0) return json({ error: '暂无热搜数据，请稍后重试' }, 500);
    return json({ status: 'ok', keywords: keywords.slice(0, 20) });
  } catch (error) {
    let msg = error.message;
    if (msg.includes('429') || msg.includes('Too Many Requests')) msg = 'Google Trends 请求过于频繁，请稍后重试（约 1 分钟）';
    else if (msg.toLowerCase().includes('timeout') || msg.toLowerCase().includes('timed out')) msg = '请求超时，请检查网络后重试';
    return json({ error: msg }, 500);
  }
}

// ============ API 路由 ============

async function handleApi(request, env, url) {
  const path = url.pathname.replace('/api/', '');
  const method = request.method;

  if (method === 'OPTIONS') {
    return new Response(null, {
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      }
    });
  }

  // ── Tool 路由（无需登录，用户自带 API Key）──────────────────────────────────
  if (path === 'tool/transcribe' && method === 'POST') return await handleToolTranscribe(request);
  if (path === 'tool/translate'  && method === 'POST') return await handleToolTranslate(request);
  if (path === 'tool/format'     && method === 'POST') return await handleToolFormat(request);
  if (path === 'tool/trends'     && method === 'GET')  return await handleToolTrends(url);

  if (!env.DB) return json({ error: '数据库未绑定，请检查 Cloudflare D1 Binding 配置（变量名需为 DB）' }, 500);

  await ensureDB(env);

  // 认证路由
  if (path === 'register' && method === 'POST') return await handleRegister(request, env);
  if (path === 'login' && method === 'POST') return await handleLogin(request, env);
  if (path === 'logout' && method === 'POST') return await handleLogout(request, env);
  if (path === 'me' && method === 'GET') return await handleMe(request, env);

  // 搜索路由（需要后端代理的）
  if (path === 'search' && method === 'GET') return await handleSearchPhoto(request, env, url);
  if (path === 'search/video' && method === 'GET') return await handleSearchVideo(request, env, url);
  if (path === 'search/illustration' && method === 'GET') return await handleSearchIllustration(request, env, url);
  if (path === 'search/gif' && method === 'GET') return await handleSearchGif(request, env, url);
  if (path === 'search/news' && method === 'GET') return await handleSearchNews(request, env, url);
  if (path === 'search/quotes' && method === 'GET') return await handleSearchQuotes(request, env, url);

  // 历史与收藏
  if (path === 'history' && method === 'GET') return await handleGetHistory(request, env);
  if (path === 'history' && method === 'POST') return await handleSaveHistory(request, env);
  if (path === 'favorites' && method === 'GET') return await handleGetFavorites(request, env);
  if (path === 'favorites' && method === 'POST') return await handleAddFavorite(request, env);
  if (path === 'favorites' && method === 'DELETE') return await handleRemoveFavorite(request, env);

  // AI 叙事生成 & 文生图
  if (path === 'narrative/generate' && method === 'POST') return await handleGenerateNarrative(request, env);
  if (path === 'image/generate' && method === 'POST') return await handleGenerateImage(request, env);

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
