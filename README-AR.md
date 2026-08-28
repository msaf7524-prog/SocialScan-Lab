# SocialScan Lab Backend v0.1

هذا الـBackend مخصص لربط TikTok رسميًا عبر OAuth/Login Kit، بدون وضع `Client Secret` أو Access Token داخل GitHub Pages.

## الملفات
- `worker.js` — Backend كامل لـ Cloudflare Worker.
- `wrangler.toml` — إعداد المشروع.

## المتغيرات السرية المطلوبة داخل Cloudflare
لا تضع هذه القيم داخل GitHub:
- `TIKTOK_CLIENT_KEY`
- `TIKTOK_CLIENT_SECRET`

ومتغيرات الإعداد:
- `TIKTOK_REDIRECT_URI`
- `FRONTEND_URL=https://msaf7524-prog.github.io/SocialScan-Lab/`
- `TIKTOK_SCOPES=user.info.basic,user.info.profile,user.info.stats,video.list`

## KV
أنشئ KV Namespace واربطه باسم:
`SESSIONS`

يخزن فقط جلسات OAuth والتوكنات على الخادم، ولا يرسل Access Token أو Refresh Token إلى الواجهة.

## المسارات
- `GET /health`
- `GET /auth/tiktok/start`
- `GET /auth/tiktok/callback`
- `GET /api/session`
- `GET /api/tiktok/me`
- `GET /api/tiktok/videos`
- `POST /auth/tiktok/logout`

الخطوة التالية بعد رفع الملفات إلى GitHub هي إنشاء TikTok Developer App ثم Cloudflare Worker وربط الأسرار.
