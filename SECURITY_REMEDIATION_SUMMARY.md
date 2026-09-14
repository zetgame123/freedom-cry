# FREEDOM CRY — SECURITY REMEDIATION & HARDENING SUMMARY

**Дата выполнения:** 14 сентября 2026  
**Ветка:** `master`  
**Коммиты:**
- `292c43f`: `security: comprehensive vulnerability remediation and defense-in-depth hardening`
- `44ba2b5`: `security: patch body tampering, replay within window, token downgrade, and stream leak`

---

## 1. ВЫПОЛНЕННЫЕ РАБОТЫ И АРХИТЕКТУРНЫЕ ИЗМЕНЕНИЯ

### A. Zero-Trust Key Management (Ключевая безопасность)
1. **Удаление приватных ключей с Master-сервера**:
   - Master больше **не генерирует, не хранит и не передаёт** приватные ключи нод (Xray Reality `x25519`, AmneziaWG `x25519`).
   - Нода (`cmd/agent/main.go`) при первом старте генерирует ключевые пары локально в `/etc/freedom-cry/node-keys.json` с правами `0600`.
   - На Master отправляются только публичные ключи через защищённый эндпоинт `/api/v1/node/keys`.
   - В БД (`internal/database/db.go`) принудительно удалены legacy-колонки `reality_priv_key` и `awg_priv_key` из `server_nodes`, а также `awg_private_key` из `client_keys`.
   - Приватный ключ клиента генерируется на клиенте и никогда не сохраняется на сервере.

### B. Криптографическая аутентификация и идентичность нод
1. **Ed25519 криптографическая идентичность**:
   - Полностью устранён статический глобальный секрет `X-Node-Secret`.
   - Запросы ноды к Master подписываются ключом Ed25519 (`X-Node-Signature`, `X-Node-Timestamp`).
   - **Привязка к телу запроса**: строка подписи включает SHA-256 хэш тела запроса (`FC-NODE-AUTH:<nodeID>:<ts>:<method>:<path>:<bodyHashHex>`), что исключает подмену параметров на лету.
   - **Защита от Replay в 60с окне**: реализован кэш подписей с TTL 70 секунд, исключающий повтор запроса в пределах окна свежести.
   - **Одноразовый токен зачисления (Enrollment Token)**: `X-Node-Token` работает только при первичной регистрации ключей. После привязки Ed25519 ключа любые попытки даунгрейда на токен блокируются с `401 Unauthorized`.
   - **IDOR Protection**: `node_id` в теле запроса синхронизации строго валидируется против `authenticatedNodeID`.

### C. Харденинг протокола Covert (Аварийный транспорт)
1. **`SecureChannel` (ChaCha20-Poly1305 + HKDF)**:
   - Раздельные ключи направлений: `client-write` и `server-write` (защита от Reflection-атак).
   - Монотонные детерминированные nonces (`[Version][Direction][00][Sequence]`), предотвращающие повторное использование nonce.
   - 25-байтный заголовок фрейма включён в Authenticated Additional Data (AAD).
   - **128-битное скользящее окно повторов (RFC 6479)** с двухфазным коммитом (защита от отравления окна неподписанными пакетами).
2. **SSRF & DNS Rebinding Defense**:
   - Внедрён `safedial.SafeDialer`.
   - Блокируются IPv4/IPv6 Loopback, RFC 1918, CGNAT (`100.64.0.0/10`), Link-Local (`169.254.0.0/16`, `fe80::/10`), Cloud Metadata (`169.254.169.254`, `fd00:ec2::254`), мультикаст и IPv4-mapped IPv6.
   - Защита на уровне ядра ОС через сокетный хук `Control` перед системным вызовом `connect()`.
   - Поддержка fallback перебора всех валидированных IP адресов для dual-stack.
3. **Защита от утечки сокетов и петель пакетов**:
   - Проверка `inUse` на уровне ExitNode предотвращает утечку дескрипторов при дублирующихся `CmdConnect`.
   - Разделены обработчики закрытия: входящий `CmdClose` закрывает сокет локально без паразитного эхо `CmdClose` обратно.

### D. Конкурентность и целостность базы данных
1. **Аллокация IP-адресов VPN**:
   - Строчная транзакционная блокировка `SELECT ... FOR UPDATE` на строке ноды исключает race condition при одновременной покупке подписок.
   - Составной уникальный индекс `idx_node_awg_addr` на `(node_id, awg_address)` на уровне схемы PostgreSQL гарантирует отсутствие коллизий.

### E. Безопасность Web & API
1. **Защита от XSS**:
   - Страница подписки переведена с конкатенации строк на контекстный шаблонизатор `html/template`.
   - Внедрена строгая CSP (`default-src 'none'; style-src 'unsafe-inline'; script-src 'none'`), а также `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`.
2. **Пароль администратора**:
   - Удалён хардкод `admin123`. При первом старте генерируется случайный 32-символьный пароль (либо читается из переменной `ADMIN_INITIAL_PASSWORD`).

### F. Инфраструктура, Docker и Systemd
1. **Docker Compose**:
   - База данных PostgreSQL и кэш Redis полностью изолированы во внутренней сети `freedomcry-net`. Внешние порты `5432` и `6379` отключены.
   - Включён пароль Redis `--requirepass`.
   - API привязан к локальному интерфейсу `${API_BIND_ADDR:-127.0.0.1}:8080` (требует проксирования через Nginx/Caddy с TLS).
2. **Изоляция на уровне Linux (iptables & systemd)**:
   - `scripts/setup-node.sh`: настроена строгая изоляция клиентов (`FORWARD -s 10.8.0.0/16 -d 10.8.0.0/16 -j DROP`).
   - Клиенты не имеют доступа к хосту (`INPUT -s 10.8.0.0/16 -j DROP`), кроме DNS-запросов (порт 53).
   - Заблокирован доступ к облачным метаданным (`169.254.0.0/16`).
   - Systemd-юниты агента и covert-выхода запущены с песочницей: `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, урезаны capabilities.
   - Секреты больше не светятся в `ps aux` / `/proc` — передаются строго через `EnvironmentFile=/etc/freedom-cry/agent.env` (`chmod 600`).

---

## 2. СВОДКА РЕЗУЛЬТАТОВ ТЕСТИРОВАНИЯ

- **`go test -v ./...`**: Все тесты успешно пройдены (PASS).
- **`go test -race -count=1 ./...`**: **0 гонок данных (data races: 0)**.
- **`go test -fuzz=FuzzDecryptFrame -fuzztime=5s ./internal/protocol/covert`**: **2 877 685 итераций без сбоев**.
- **`go vet ./...`**: **0 предупреждений**.
- **`govulncheck ./...`**: **0 уязвимостей в используемом коде**.
- **Компиляция бинарников**:
  - `bin/freedom-cry-server` (OK)
  - `bin/freedom-cry-agent` (OK)
  - `bin/freedom-cry-covert` (OK)

---

## 3. СТАТУС ГОТОВНОСТИ

Проект прошёл комплексный цикл адверсариального аудита, все выявленные уязвимости и векторы обхода устранены на уровне архитектуры и кода.  
Репозиторий находится в чистом, скомпилированном и закоммиченном состоянии в ветке `master`.
