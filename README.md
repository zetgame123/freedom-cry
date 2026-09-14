# 🦅 Freedom Cry VPN Service

**Freedom Cry** — это высокопроизводительный, модульный бэкенд и распределенная система управления VPN-сервисом на языке Go, спроектированная специально для надежного обхода современных DPI-систем и ТСПУ блокировок.

---

## ⚡ Ключевые возможности

1. **Двухпротокольный анти-блокировочный стек**:
   - **VLESS + Reality (Xray)**: Маскировка трафика под легитимный TLS (SNI: `dl.google.com`, `gateway.icloud.com` и др.) с динамическим X25519 шифрованием. Не детектируется сигнатурным анализом DPI.
   - **AmneziaWG (Обособленный WireGuard)**: Полная устойчивость к блокировкам классического WireGuard благодаря обфускации:
     - `Jc`, `Jmin`, `Jmax` — мусорные пакеты (Junk packets) перед хэндшейком
     - `S1`, `S2` — рандомизированный размер паддинга
     - `H1`, `H2`, `H3`, `H4` — уникальные магические заголовки протокола вместо стандартных сигнатур WG
2. **Мульти-серверная архитектура (Node Agent)**:
   - Центральный API координирует неограниченное число серверов в любых локациях (Нидерланды, Германия, Швеция, США и т.д.).
   - Легковесный бинарный демон `agent`, разворачиваемый на серверах нод, автоматически запрашивает актуальный список клиентов через `X-Node-Secret`, обновляет конфиги Xray/AWG и перезагружает сервисы без простоя.
3. **Универсальные ссылки подписки (`/sub/:token`)**:
   - Единая ссылка подписки работает с: **v2rayN**, **Sing-box**, **Clash Verge**, **NekoBox**, **Streisand**, **Hiddify**.
   - При открытии в обычном браузере ссылка автоматически отображает стильную веб-страницу пользователя с QR-кодами, статусом тарифа и кнопкой скачивания готового файла `.conf` для **AmneziaVPN**.
   - Скачивание персональных файлов `.conf` напрямую по ссылке `/sub/:token/awg/:node_id`.
4. **Биллинг и пользователи**:
   - JWT-аутентификация, роли (User / Admin).
   - Поддержка Telegram ID для легкого подключения Telegram-ботов продаж.
   - Тарифные планы (лимиты по дням и гигабайтам трафика, безлимиты).
   - Внутренний баланс пользователей, транзакции, поддержка Stars / Crypto / ручного подтверждения.

---

## 📂 Структура проекта

```
Freedom Cry/
├── cmd/
│   ├── server/           # Главный API сервер Freedom Cry
│   │   └── main.go
│   └── agent/            # Агент ноды для удаленных VPN-серверов
│       └── main.go
├── internal/
│   ├── api/              # HTTP роутинг, middleware, контроллеры
│   │   ├── handler/      # Auth, User, Nodes, Subscriptions, Billing, Config
│   │   ├── middleware/   # JWT, Role Guard, Node Secret Guard
│   │   └── router.go
│   ├── cache/            # Redis клиент
│   ├── config/           # Конфигурация приложения
│   ├── database/         # PostgreSQL GORM подключение и авто-сиды
│   ├── models/           # Модели (User, Plan, ServerNode, Subscription, ClientKey, Transaction)
│   ├── protocol/         # Криптографические генераторы протоколов
│   │   ├── xray/         # VLESS + Reality X25519 генератор ключей и конфигов
│   │   └── amneziawg/    # AmneziaWG генератор ключей и .conf файлов
│   └── service/          # Бизнес-логика сервиса
├── config.example.yaml   # Пример конфигурации
├── Dockerfile.server     # Сборка сервера в Alpine
├── Dockerfile.agent      # Сборка агента для VPS
├── docker-compose.yml    # Запуск Postgres + Redis + API
└── README.md
```

---

## 🚀 Быстрый запуск (Docker Compose)

Запуск полного стека (PostgreSQL 16, Redis 7 и Freedom Cry API):

```bash
docker compose up -d --build
```

Проверка статуса:
```bash
curl http://localhost:8080/health
# {"service":"Freedom Cry VPN API","status":"ok"}
```

---

## 🛠 Локальная разработка и сборка

Требования:
- Go 1.22+
- PostgreSQL 14+
- Redis (опционально)

```bash
# Установка зависимостей
go mod download

# Сборка бинарников
go build -o server ./cmd/server
go build -o agent ./cmd/agent

# Запуск сервера
./server --config config.example.yaml
```

При первом запуске сервер автоматически создаст таблицы в базе данных и добавит демонстрационные данные:
- **Администратор по умолчанию**: `admin@freedomcry.net` / `admin123`
- **Тарифные планы**: 1 месяц (100 GB), 3 месяца (Безлимит), 1 год (Безлимит)
- **Тестовая нода**: Amsterdam #1 с автосгенерированными ключами Reality и AmneziaWG

---

## 📡 Основные эндпоинты API

### Публичные / Подписки:
| Метод | URL | Описание |
|---|---|---|
| `GET` | `/health` | Проверка здоровья API |
| `GET` | `/sub/:token` | **Ссылка подписки** (Base64 для клиентов v2rayN/Clash/Sing-box или HTML в браузере) |
| `GET` | `/sub/:token/vless` | Список `vless://` ссылок в открытом текстовом виде |
| `GET` | `/sub/:token/awg/:node_id` | Скачивание `.conf` файла для AmneziaVPN / WireGuard |
| `GET` | `/sub/:token/info` | JSON-информация о подписке и остатке трафика |

### Авторизация:
| Метод | URL | Описание |
|---|---|---|
| `POST` | `/api/v1/auth/register` | Регистрация нового пользователя |
| `POST` | `/api/v1/auth/login` | Вход и получение JWT-токена |

### Личный кабинет пользователя (требуется `Bearer <JWT>`):
| Метод | URL | Описание |
|---|---|---|
| `GET` | `/api/v1/user/me` | Профиль текущего пользователя, баланс и подписки |
| `GET` | `/api/v1/user/subscriptions` | Список активных подписок и ссылки на подключение |
| `POST` | `/api/v1/user/subscriptions/buy` | Покупка тарифа за баланс |
| `POST` | `/api/v1/user/billing/deposit` | Пополнение баланса |

### Ноды и Агенты:
| Метод | URL | Описание |
|---|---|---|
| `GET` | `/api/v1/nodes` | Список активных стран и локаций серверов |
| `POST` | `/api/v1/node/sync` | Эндпоинт синхронизации для агента на VPS (защищен `X-Node-Secret`) |

---

## 🌐 Развертывание узла (Node Agent на VPS)

На удаленный VPS сервер (с установленным Xray или AmneziaWG) достаточно скопировать бинарник `agent`:

```bash
./agent \
  --api "https://api.yourdomain.com" \
  --node-id "UUID_ВАШЕЙ_НОДЫ" \
  --secret "ВАШ_NODE_SECRET" \
  --xray-config "/usr/local/etc/xray/config.json" \
  --awg-config "/etc/amnezia/amneziawg/awg0.conf" \
  --dry-run=false
```

Агент каждые 15 секунд отправляет состояние ноды (CPU load), забирает список активных клиентов и автоматически обновляет конфигурационные файлы.

---

## 🔒 Лицензия
Freedom Cry создается под свободной лицензией MIT.
