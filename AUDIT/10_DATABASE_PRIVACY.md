# Freedom Cry — Database Privacy Audit

## Schema Map

### Table: `users`

| Column | Type | Sensitive? | Can Identify User? | Retention |
|--------|------|-----------|-------------------|-----------|
| `id` | uuid | Yes (PK) | Indirect | Hard delete on user delete |
| `account_number` | varchar(32) | Yes | **YES — authentication credential** | Hard delete |
| `email` | string | **YES** | **YES — PII** | Hard delete |
| `password_hash` | string | Yes | Indirect | Hard delete |
| `telegram_id` | int64 | **CRITICAL YES** | **YES — directly identifies Telegram account** | Hard delete |
| `balance` | decimal | No | No | Hard delete |
| `role` | varchar(20) | No | No | Hard delete |
| `is_active` | bool | No | No | Hard delete |
| `created_at` | timestamp | Yes | Indirect (temporal correlation) | Hard delete |
| `updated_at` | timestamp | Yes | Indirect | Hard delete |
| `deleted_at` | timestamp | Yes | Indirect | Hard delete (Unscoped) |

### Table: `subscriptions`

| Column | Type | Sensitive? | Can Identify User? | Retention |
|--------|------|-----------|-------------------|-----------|
| `id` | uuid | Yes (PK) | Indirect | Hard delete |
| `user_id` | uuid (FK→users) | **YES** | **Links subscription to user** | Hard delete |
| `plan_id` | uuid | No | No | Hard delete |
| `token` | varchar(64) | **CRITICAL** | **YES — bearer credential & encryption key** | Hard delete |
| `status` | varchar(20) | No | No | Hard delete |
| `traffic_limit_bytes` | int64 | No | No | Hard delete |
| `traffic_used_bytes` | int64 | Yes | Indirect (usage pattern) | Hard delete |
| `expires_at` | timestamp | Yes | Indirect | Hard delete |
| `created_at` | timestamp | Yes | Indirect | Hard delete |

### Table: `client_keys`

| Column | Type | Sensitive? | Can Identify User? | Retention |
|--------|------|-----------|-------------------|-----------|
| `id` | uuid | Yes (PK) | Indirect | Hard delete |
| `subscription_id` | uuid (FK) | **YES** | **Links key to subscription→user** | Hard delete |
| `node_id` | uuid (FK) | Yes | Indirect (reveals node assignment) | Hard delete |
| `protocol` | varchar(20) | No | No | Hard delete |
| `vless_uuid` | varchar(64) | **YES** | **YES — VPN identity on Xray** | Hard delete |
| `previous_vless_uuid` | varchar(64) | **YES** | **YES — previous VPN identity** | Hard delete |
| `vless_rotated_at` | timestamp | Yes | Indirect | Hard delete |
| `awg_address` | varchar(100) | **YES** | **YES — VPN tunnel IP** | Hard delete |
| `awg_public_key` | varchar(100) | **YES** | **YES — WireGuard identity** | Hard delete |
| `awg_private_key_enc` | text | **CRITICAL** | **YES — encrypted VPN credential** | Hard delete |
| `awg_preshared_key` | varchar(100) | **CRITICAL (PLAINTEXT)** | **YES — WireGuard PSK** | Hard delete |

### Table: `server_nodes`

| Column | Type | Sensitive? | Can Identify User? | Retention |
|--------|------|-----------|-------------------|-----------|
| `host` | string | Yes | No (server IP) | Retained |
| `public_key` | varchar(128) | Yes | No (node identity) | Retained |
| `auth_token_hash` | varchar(64) | Yes | No (node auth) | Retained |
| `reality_pub_key` | string | Yes | No (public key) | Retained |
| `reality_short_id` | string | Yes | No (shared config) | Retained |
| `awg_pub_key` | string | Yes | No (server public key) | Retained |
| `awg_h1-h4` | uint32 | Yes | No (obfuscation params) | Retained |

### Table: `invite_codes`

| Column | Type | Sensitive? | Can Identify User? | Retention |
|--------|------|-----------|-------------------|-----------|
| `code` | varchar(64) | Yes | Indirect (distribution channel) | Soft delete |
| `uses_count` | int | Yes | Indirect (timing correlation) | Soft delete |
| `plan_id` | uuid | No | No | Soft delete |

### Table: `transactions`

| Column | Type | Sensitive? | Can Identify User? | Retention |
|--------|------|-----------|-------------------|-----------|
| `user_id` | uuid (FK) | **YES** | Links to user | Hard delete |

## Critical Finding: Full De-Anonymization Chain

```sql
-- This query reveals the COMPLETE identity of every user
SELECT 
    u.telegram_id,
    u.email,
    u.account_number,
    u.created_at as user_created,
    s.token as sub_token,
    s.status,
    s.expires_at,
    ck.vless_uuid,
    ck.awg_public_key,
    ck.awg_preshared_key,  -- PLAINTEXT!
    ck.awg_address,
    n.name as node_name,
    n.host as node_ip
FROM users u
JOIN subscriptions s ON s.user_id = u.id
JOIN client_keys ck ON ck.subscription_id = s.id
JOIN server_nodes n ON n.id = ck.node_id
WHERE u.deleted_at IS NULL;
```

This single query provides:
- **Who** (telegram_id, email)
- **What** (VPN credentials, keys)
- **Where** (node assignment, tunnel IP)
- **When** (timestamps)
