# Freedom Cry — Cloudflare Worker Edge Front

Этот сервис обеспечивает устойчивость Master API к блокировкам Роскомнадзора (ТСПУ) по IP-адресу.

## Как это работает
1. Клиенты обращаются к адресу воркера (например, `https://edge.freedomcry.net` или `https://freedom-cry-edge.workers.dev`).
2. Запрос обрабатывается Anycast-сетью Cloudflare с тысячами чистых IP-адресов.
3. Воркер удаляет заголовки `CF-Connecting-IP` и заменяет клиентский IP на `127.0.0.1` для сохранения приватности.
4. Воркер добавляет заголовок `X-Edge-Secret` и проксирует запрос на защищенный origin-сервер Freedom Cry.

## Развертывание в 1 команду
```bash
# 1. Установите wrangler (если не установлен)
npm install -g wrangler

# 2. Войдите в Cloudflare аккаунт
wrangler login

# 3. Отредактируйте ORIGIN_URL в wrangler.toml

# 4. Задеплойте воркер
wrangler deploy
```
