# Freedom Cry — Key Management Audit

## Key Lifecycle Summary

### AWG Client Private Key

| Phase | Implementation | Assessment |
|-------|---------------|------------|
| **Generate** | `crypto/rand` → 32 bytes → Curve25519 clamping | ✅ Correct |
| **Store** | AES-256-GCM encrypted with HKDF-SHA256(sub.Token) | ✅ Good |
| **Encrypt** | HKDF: IKM=token, salt=static, info=static → AES-256-GCM with random nonce | ✅ Acceptable |
| **Transmit** | Decrypted on-demand when client requests AWG config via /sub/:token | ⚠️ Token in URL |
| **Provision** | Generated server-side, encrypted immediately, plaintext never persisted | ✅ Good |
| **Rotate** | Re-encrypted with new token during token rotation | ✅ Good |
| **Revoke** | Hard deleted on subscription revocation | ✅ Good |
| **Delete** | Hard deleted on user account deletion | ✅ Good |

### HKDF Encryption Scheme Detail

```
IKM   = subscription.Token (256-bit hex string, 64 chars)
Salt  = "freedom-cry-awg-token-salt-v1" (constant)
Info  = "freedom-cry-client-privkey-encryption" (constant)
KDF   = HKDF-SHA256
Key   = 32 bytes (AES-256)
AEAD  = AES-256-GCM
Nonce = 12 bytes random (prepended to ciphertext)
AAD   = nil (⚠️ no binding to key ID or subscription ID)
```

### Security Assessment of Encryption:

1. **Can DB-only attacker decrypt?** NO — requires subscription token (not stored alongside encrypted data)
2. **Can app-compromise attacker decrypt?** YES — application has access to tokens in DB (subscriptions.token)
3. **Can backup attacker decrypt?** PARTIALLY — backup contains both encrypted keys AND tokens, so YES
4. **Is the salt per-key?** NO — static salt, but IKM (token) is unique per subscription
5. **Is the nonce unique?** YES — `crypto/rand` generated per encryption call

### VLESS UUID

| Phase | Implementation | Assessment |
|-------|---------------|------------|
| **Generate** | `uuid.New()` (crypto/rand-based UUID v4) | ✅ Correct |
| **Store** | Plaintext in client_keys table | ⚠️ Not encrypted |
| **Rotate** | Every 24 hours, previous UUID kept for 1-hour grace period | ✅ Good |
| **Provision** | Synced to node via NodeSync endpoint | ✅ Proper auth |

### Reality X25519 Keys

| Phase | Implementation | Assessment |
|-------|---------------|------------|
| **Generate** | `crypto/rand` → 32 bytes → Curve25519 clamping | ✅ Correct |
| **Store** | Private key on node only; public key in master DB | ✅ Good architecture |
| **Rotate** | NOT ROTATED | ⚠️ No rotation mechanism |

### Ed25519 Node Identity Keys

| Phase | Implementation | Assessment |
|-------|---------------|------------|
| **Generate** | Node-side (not reviewed — agent binary) | NOT TESTED |
| **Store** | Public key in server_nodes table | ✅ OK |
| **Verify** | Ed25519 signature over `FC-NODE-AUTH:nodeID:timestamp:method:path:bodyHash` | ✅ Good |
| **Replay** | 60-second window + in-memory signature cache | ⚠️ Cache lost on restart |
| **Rotate** | Not prevented — public key can be overwritten | ❌ Security issue |

### Enrollment Token

| Phase | Implementation | Assessment |
|-------|---------------|------------|
| **Generate** | `crypto/rand` → 32 bytes → SHA256 hash stored | ✅ Good |
| **Store** | Hash only (SHA256) | ✅ Correct |
| **Verify** | SHA256(provided) compared constant-time to stored hash | ✅ Good |
| **Disable** | Auto-disabled after Ed25519 key registration | ✅ Good |

### Blind Signature Keys (RSA-2048)

| Phase | Implementation | Assessment |
|-------|---------------|------------|
| **Generate** | `rsa.GenerateKey(rand.Reader, 2048)` | ✅ Correct |
| **Scheme** | Chaum blind signatures | ✅ Correct implementation |
| **Risk** | RSA-2048 with raw exponentiation (not PSS/PKCS1v15) | ⚠️ Non-standard |
