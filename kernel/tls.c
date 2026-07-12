/*
 * kernel/tls.c -- a TLS 1.2 client, scoped to exactly one cipher
 * suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (RFC 5246 + RFC 5288 +
 * RFC 8422's ECDHE key exchange). Built entirely on top of the
 * already-independently-verified primitives elsewhere in this
 * codebase (crypto.c's SHA-256/HMAC/PRF/AES-GCM/bignum/P-256/RSA,
 * x509.c's certificate parsing, roots.c's trusted root set, net.c's
 * TCP) -- this file's own job is just the protocol state machine:
 * message framing, the handshake sequence, key derivation, and
 * certificate chain validation.
 *
 * Client-only, single connection at a time (mirrors net.c's own
 * single-TCP-connection design) -- no renegotiation, no session
 * resumption, no client certificates. This is deliberately narrow:
 * one cipher suite, one curve, one signature scheme, because
 * verifying a wide protocol surface against this codebase's from-
 * scratch primitives is a much bigger undertaking than a lightweight
 * OS's HTTPS needs warrant. See SECURITY.md for what this does NOT
 * implement and why that's a real limitation, not just a TODO.
 */
#include "kernel.h"

#define TLS_CT_CHANGE_CIPHER_SPEC 20
#define TLS_CT_ALERT              21
#define TLS_CT_HANDSHAKE          22
#define TLS_CT_APPLICATION_DATA   23

#define TLS_HS_CLIENT_HELLO        1
#define TLS_HS_SERVER_HELLO        2
#define TLS_HS_CERTIFICATE        11
#define TLS_HS_SERVER_KEY_EXCHANGE 12
#define TLS_HS_SERVER_HELLO_DONE  14
#define TLS_HS_CLIENT_KEY_EXCHANGE 16
#define TLS_HS_FINISHED           20

/* the only cipher suite this file ever offers or accepts */
#define TLS_CIPHER_ECDHE_RSA_AES128_GCM_SHA256_HI 0xC0
#define TLS_CIPHER_ECDHE_RSA_AES128_GCM_SHA256_LO 0x2F

#define TLS_RECORD_MAX 16640  /* 2^14 plaintext + GCM overhead, rounded up */
#define TLS_HS_BUF_MAX 12288  /* generous for a realistic leaf+intermediate
                                  chain; a message that doesn't fit is a
                                  hard connection failure, not truncated */
#define TLS_MAX_CHAIN_CERTS 4

static u16 get_u16_be(const u8 *p) { return (u16)((p[0] << 8) | p[1]); }
static u32 get_u24_be(const u8 *p) { return ((u32)p[0] << 16) | ((u32)p[1] << 8) | p[2]; }
static void put_u16_be(u8 *p, u16 v) { p[0] = (u8)(v >> 8); p[1] = (u8)v; }
static void put_u24_be(u8 *p, u32 v) { p[0] = (u8)(v >> 16); p[1] = (u8)(v >> 8); p[2] = (u8)v; }
static void put_u64_be(u8 *p, u64 v) { for (int i = 0; i < 8; i++) p[i] = (u8)(v >> (56 - i * 8)); }

typedef struct {
    bool encrypted;             /* has ChangeCipherSpec been applied to this direction? */
    aes128_ctx_t write_ctx;
    u8 write_iv[4];              /* GCM fixed/salt portion, RFC 5288 */
    u64 seq;                    /* per-direction record sequence number */
} tls_cipher_state_t;

typedef struct {
    bool connected;
    tls_cipher_state_t tx, rx;  /* client-write and server-write (from
                                    our perspective: tx = what we
                                    encrypt with, rx = what we decrypt
                                    with) */
    sha256_ctx_t transcript;    /* running hash of every handshake
                                    message body, header included, in
                                    the exact order sent/received */
    u8 client_random[32];
    u8 server_random[32];
    u8 master_secret[48];

    /* handshake-message reassembly buffer: raw plaintext handshake
       bytes not yet consumed by hs_next(), possibly spanning more
       than one TLS record */
    u8 hs_buf[TLS_HS_BUF_MAX];
    u32 hs_len;
    u32 hs_pos;
} tls_conn_t;

static tls_conn_t tls;

/* ---- record layer -------------------------------------------------- */

static bool tls_read_exact(u8 *buf, u32 len, u32 timeout_ms)
{
    u32 got = 0;
    u32 start = uptime_ms();
    while (got < len) {
        if (uptime_ms() - start > timeout_ms)
            return false;
        u32 n = net_tcp_recv(buf + got, len - got, timeout_ms);
        if (!n) {
            if (net_tcp_eof())
                return false;
            continue;
        }
        got += n;
    }
    return true;
}

static bool tls_send_raw_record(u8 type, const u8 *payload, u32 len)
{
    u8 hdr[5];
    hdr[0] = type;
    hdr[1] = 0x03;
    hdr[2] = 0x03; /* TLS 1.2 */
    put_u16_be(hdr + 3, (u16)len);
    if (!net_tcp_send(hdr, 5))
        return false;
    if (len && !net_tcp_send(payload, len))
        return false;
    return true;
}

/* Pure AEAD framing math (RFC 5288 for the 8-byte explicit-nonce
   layout, RFC 5246 6.2.3.3 for the AAD), factored out of the
   network-coupled send/recv functions below so it can be exercised
   directly by tls_selftest() without a live TCP connection. `wire_out`
   must have room for 8 + plain_len + 16 bytes. */
static void tls_aead_seal(const tls_cipher_state_t *cs, u8 type,
                          const u8 *plain, u32 plain_len, u8 *wire_out)
{
    u8 nonce[12];
    memcpy(nonce, cs->write_iv, 4);
    put_u64_be(nonce + 4, cs->seq);

    u8 aad[13];
    put_u64_be(aad, cs->seq);
    aad[8] = type;
    aad[9] = 0x03;
    aad[10] = 0x03;
    put_u16_be(aad + 11, (u16)plain_len);

    memcpy(wire_out, nonce + 4, 8); /* explicit nonce prefix on the wire */
    u8 tag[16];
    aes128_gcm_encrypt(&cs->write_ctx, nonce, aad, sizeof(aad), plain,
                       plain_len, wire_out + 8, tag);
    memcpy(wire_out + 8 + plain_len, tag, 16);
}

/* wire holds [8-byte explicit nonce][ciphertext][16-byte tag],
   wire_len bytes total; plain_out must have room for wire_len-8-16
   bytes. Returns false on any authentication failure -- plain_out is
   only meaningful when this returns true. */
static bool tls_aead_open(const tls_cipher_state_t *cs, u8 type,
                          const u8 *wire, u32 wire_len, u8 *plain_out)
{
    if (wire_len < 8 + 16)
        return false;
    u32 plain_len = wire_len - 8 - 16;

    u8 nonce[12];
    memcpy(nonce, cs->write_iv, 4);
    memcpy(nonce + 4, wire, 8);

    u8 aad[13];
    put_u64_be(aad, cs->seq);
    aad[8] = type;
    aad[9] = 0x03;
    aad[10] = 0x03;
    put_u16_be(aad + 11, (u16)plain_len);

    return aes128_gcm_decrypt(&cs->write_ctx, nonce, aad, sizeof(aad),
                              wire + 8, plain_len, wire + 8 + plain_len, plain_out);
}

/* Encrypts `plain` (a full record's plaintext) under tx's current
   key/IV/sequence number, sends it as one record, and advances the
   sequence number. */
static bool tls_send_encrypted(u8 type, const u8 *plain, u32 plain_len)
{
    u8 out[8 + TLS_RECORD_MAX];
    tls_aead_seal(&tls.tx, type, plain, plain_len, out);
    tls.tx.seq++;
    return tls_send_raw_record(type, out, 8 + plain_len + 16);
}

/* Reads exactly one TLS record, decrypting it if rx.encrypted, and
   returns its content type and plaintext. A tampered or truncated
   ciphertext (bad tag) is a hard failure -- this never returns
   "plaintext" that didn't actually authenticate. */
static bool tls_recv_raw_record(u8 *type_out, u8 *buf, u32 buf_max, u32 *len_out)
{
    u8 hdr[5];
    if (!tls_read_exact(hdr, 5, 10000))
        return false;
    u8 type = hdr[0];
    u32 rec_len = get_u16_be(hdr + 3);
    if (rec_len == 0 || rec_len > TLS_RECORD_MAX)
        return false;

    u8 raw[TLS_RECORD_MAX];
    if (!tls_read_exact(raw, rec_len, 10000))
        return false;

    if (!tls.rx.encrypted) {
        if (rec_len > buf_max)
            return false;
        memcpy(buf, raw, rec_len);
        *type_out = type;
        *len_out = rec_len;
        return true;
    }

    if (rec_len < 8 + 16)
        return false; /* must at least hold the explicit nonce + tag */
    u32 plain_len = rec_len - 8 - 16;
    if (plain_len > buf_max)
        return false;

    if (!tls_aead_open(&tls.rx, type, raw, rec_len, buf))
        return false;

    tls.rx.seq++;
    *type_out = type;
    *len_out = plain_len;
    return true;
}

/* ---- handshake message layer ---------------------------------------- */

static void hs_compact(void)
{
    if (tls.hs_pos == 0)
        return;
    u32 remaining = tls.hs_len - tls.hs_pos;
    if (remaining)
        memmove(tls.hs_buf, tls.hs_buf + tls.hs_pos, remaining);
    tls.hs_len = remaining;
    tls.hs_pos = 0;
}

/* Pulls raw handshake-record bytes from the network until at least
   `need` bytes are available starting at hs_pos, reading and
   buffering additional TLS records as necessary (a single record
   commonly holds several handshake messages back-to-back; a large
   Certificate message can also need several records). Any alert
   record encountered is a hard failure. */
static bool hs_fill(u32 need)
{
    hs_compact();
    while (tls.hs_len - tls.hs_pos < need) {
        u8 type;
        u32 n;
        u8 tmp[TLS_RECORD_MAX];
        if (!tls_recv_raw_record(&type, tmp, sizeof(tmp), &n))
            return false;
        if (type == TLS_CT_ALERT)
            return false; /* server aborted or signaled an error */
        if (type != TLS_CT_HANDSHAKE)
            return false; /* only handshake records expected here */
        if (tls.hs_len + n > TLS_HS_BUF_MAX)
            return false; /* would overflow the reassembly buffer --
                              refuse rather than corrupt memory */
        memcpy(tls.hs_buf + tls.hs_len, tmp, n);
        tls.hs_len += n;
    }
    return true;
}

/* Yields the next handshake message (type + body, both pointing into
   tls.hs_buf) and folds its raw bytes (header included) into the
   running transcript hash, per RFC 5246's own definition of the
   Finished message's input. */
static bool hs_next(u8 *type_out, const u8 **body_out, u32 *body_len_out)
{
    if (!hs_fill(4))
        return false;
    u8 type = tls.hs_buf[tls.hs_pos];
    u32 len = get_u24_be(tls.hs_buf + tls.hs_pos + 1);
    if (!hs_fill(4 + len))
        return false;

    sha256_update(&tls.transcript, tls.hs_buf + tls.hs_pos, 4 + len);

    *type_out = type;
    *body_out = tls.hs_buf + tls.hs_pos + 4;
    *body_len_out = len;
    tls.hs_pos += 4 + len;
    return true;
}

/* Sends a handshake message: builds the 4-byte header, folds header+body
   into the transcript hash, then sends it (encrypted once tx.encrypted
   is set -- true only for the client's Finished message). */
static bool hs_send(u8 type, const u8 *body, u32 body_len)
{
    u8 hdr[4];
    hdr[0] = type;
    put_u24_be(hdr + 1, body_len);

    sha256_update(&tls.transcript, hdr, 4);
    sha256_update(&tls.transcript, body, body_len);

    u8 msg[4 + 512]; /* every message this file ever sends (ClientHello,
                         ClientKeyExchange, Finished) fits comfortably */
    if (4 + body_len > sizeof(msg))
        return false;
    memcpy(msg, hdr, 4);
    memcpy(msg + 4, body, body_len);

    if (tls.tx.encrypted)
        return tls_send_encrypted(TLS_CT_HANDSHAKE, msg, 4 + body_len);
    return tls_send_raw_record(TLS_CT_HANDSHAKE, msg, 4 + body_len);
}

/* ---- certificate chain validation ------------------------------------ */

static int time_cmp(u16 y1, u8 mo1, u8 d1, u8 h1, u8 mi1, u8 s1,
                    u16 y2, u8 mo2, u8 d2, u8 h2, u8 mi2, u8 s2)
{
    if (y1 != y2) return y1 < y2 ? -1 : 1;
    if (mo1 != mo2) return mo1 < mo2 ? -1 : 1;
    if (d1 != d2) return d1 < d2 ? -1 : 1;
    if (h1 != h2) return h1 < h2 ? -1 : 1;
    if (mi1 != mi2) return mi1 < mi2 ? -1 : 1;
    if (s1 != s2) return s1 < s2 ? -1 : 1;
    return 0;
}

/* Parses the Certificate handshake message body (a 3-byte total
   length followed by repeated 3-byte-length-prefixed DER certs, leaf
   first), validates the leaf's hostname and validity period against
   the RTC, verifies every signature down the chain (each cert signed
   by the next), and verifies the last presented cert against an
   embedded trusted root. On success, leaf_n and leaf_e hold the
   leaf's RSA public key (for verifying ServerKeyExchange next). Every
   failure mode here is a hard `return false` -- there is no partial
   trust, no "chain looked mostly right." */
static bool validate_chain(const u8 *chain_data, u32 chain_len,
                           const char *host, bignum_t *leaf_n, bignum_t *leaf_e)
{
    static x509_cert_t certs[TLS_MAX_CHAIN_CERTS];

    if (chain_len < 3)
        return false;
    u32 list_len = get_u24_be(chain_data);
    if (3 + list_len != chain_len)
        return false;

    u32 n_certs = 0;
    u32 off = 3;
    while (off < chain_len) {
        if (off + 3 > chain_len)
            return false;
        u32 cert_len = get_u24_be(chain_data + off);
        off += 3;
        if (cert_len == 0 || off + cert_len > chain_len)
            return false;
        if (n_certs >= TLS_MAX_CHAIN_CERTS)
            return false; /* chain longer than this client supports --
                              fail closed rather than trust a truncated
                              view of it */
        if (!x509_parse_certificate(chain_data + off, cert_len, &certs[n_certs]))
            return false;
        n_certs++;
        off += cert_len;
    }
    if (n_certs == 0)
        return false;

    x509_cert_t *leaf = &certs[0];
    rtc_time_t now;
    rtc_read(&now);
    if (time_cmp(now.year, now.month, now.day, now.hour, now.min, now.sec,
                leaf->not_before.year, leaf->not_before.month, leaf->not_before.day,
                leaf->not_before.hour, leaf->not_before.minute, leaf->not_before.second) < 0)
        return false; /* not yet valid */
    if (time_cmp(now.year, now.month, now.day, now.hour, now.min, now.sec,
                leaf->not_after.year, leaf->not_after.month, leaf->not_after.day,
                leaf->not_after.hour, leaf->not_after.minute, leaf->not_after.second) > 0)
        return false; /* expired */
    if (!leaf->has_rsa_key)
        return false;
    if (!x509_hostname_matches(leaf, host))
        return false;

    for (u32 i = 0; i + 1 < n_certs; i++) {
        if (!certs[i].sig_alg_is_sha256_rsa || !certs[i + 1].has_rsa_key)
            return false; /* only RSA/SHA-256 chain signatures are
                              supported -- see this file's header comment */
        if (certs[i].issuer_len != certs[i + 1].subject_len ||
            memcmp(certs[i].issuer_start, certs[i + 1].subject_start,
                   certs[i].issuer_len) != 0)
            return false;
        u8 h[32];
        sha256(certs[i].tbs_start, certs[i].tbs_len, h);
        bignum_t sig;
        bn_from_bytes_be(&sig, certs[i].sig_start, certs[i].sig_len);
        if (!rsa_verify_pkcs1v15_sha256(&certs[i + 1].rsa_n, &certs[i + 1].rsa_e,
                                        &sig, certs[i].sig_len, h))
            return false;
    }

    x509_cert_t *last = &certs[n_certs - 1];
    x509_cert_t root;
    if (!x509_find_trusted_root(last->issuer_start, last->issuer_len, &root))
        return false; /* chain doesn't terminate at any embedded root */
    if (!last->sig_alg_is_sha256_rsa || !root.has_rsa_key)
        return false;
    u8 h[32];
    sha256(last->tbs_start, last->tbs_len, h);
    bignum_t sig;
    bn_from_bytes_be(&sig, last->sig_start, last->sig_len);
    if (!rsa_verify_pkcs1v15_sha256(&root.rsa_n, &root.rsa_e, &sig,
                                    last->sig_len, h))
        return false;

    *leaf_n = leaf->rsa_n;
    *leaf_e = leaf->rsa_e;
    return true;
}

/* ---- handshake message construction ---------------------------------- */

static u32 build_client_hello(u8 *out, u32 out_max, const char *host)
{
    u32 host_len = (u32)strlen(host);
    u32 pos = 0;
    if (pos + 2 + 32 + 1 > out_max)
        return 0;
    out[pos++] = 0x03; out[pos++] = 0x03; /* client_version: TLS 1.2 */
    if (!crypto_random_bytes(tls.client_random, 32))
        return 0;
    memcpy(out + pos, tls.client_random, 32);
    pos += 32;
    out[pos++] = 0x00; /* session_id: empty */

    put_u16_be(out + pos, 2); pos += 2; /* cipher_suites length */
    out[pos++] = TLS_CIPHER_ECDHE_RSA_AES128_GCM_SHA256_HI;
    out[pos++] = TLS_CIPHER_ECDHE_RSA_AES128_GCM_SHA256_LO;

    out[pos++] = 1;    /* compression_methods length */
    out[pos++] = 0x00; /* null compression only */

    u32 ext_len_pos = pos;
    pos += 2; /* extensions length, filled in below */

    /* server_name (SNI) */
    put_u16_be(out + pos, 0x0000); pos += 2;
    put_u16_be(out + pos, (u16)(2 + 1 + 2 + host_len)); pos += 2;
    put_u16_be(out + pos, (u16)(1 + 2 + host_len)); pos += 2;
    out[pos++] = 0x00; /* host_name */
    put_u16_be(out + pos, (u16)host_len); pos += 2;
    if (pos + host_len > out_max)
        return 0;
    memcpy(out + pos, host, host_len);
    pos += host_len;

    /* supported_groups: secp256r1 only */
    put_u16_be(out + pos, 0x000a); pos += 2;
    put_u16_be(out + pos, 4); pos += 2;
    put_u16_be(out + pos, 2); pos += 2;
    put_u16_be(out + pos, 0x0017); pos += 2;

    /* ec_point_formats: uncompressed only */
    put_u16_be(out + pos, 0x000b); pos += 2;
    put_u16_be(out + pos, 2); pos += 2;
    out[pos++] = 1;
    out[pos++] = 0x00;

    /* signature_algorithms: rsa_pkcs1_sha256 only */
    put_u16_be(out + pos, 0x000d); pos += 2;
    put_u16_be(out + pos, 4); pos += 2;
    put_u16_be(out + pos, 2); pos += 2;
    out[pos++] = 0x04; /* hash: sha256 */
    out[pos++] = 0x01; /* signature: rsa */

    put_u16_be(out + ext_len_pos, (u16)(pos - ext_len_pos - 2));
    return pos;
}

/* ---- handshake message parsing ---------------------------------------- */

static bool parse_server_hello(const u8 *body, u32 len)
{
    if (len < 2 + 32 + 1)
        return false;
    u32 pos = 2; /* skip server_version -- accepted regardless, since
                     this client only ever completes the handshake if
                     the negotiated cipher suite below matches what it
                     offered, which already pins the protocol version
                     in practice */
    memcpy(tls.server_random, body + pos, 32);
    pos += 32;
    if (pos >= len)
        return false;
    u8 session_id_len = body[pos++];
    if (pos + session_id_len + 2 + 1 > len)
        return false;
    pos += session_id_len;
    if (body[pos] != TLS_CIPHER_ECDHE_RSA_AES128_GCM_SHA256_HI ||
        body[pos + 1] != TLS_CIPHER_ECDHE_RSA_AES128_GCM_SHA256_LO)
        return false; /* server picked something other than the one
                          suite we offered */
    pos += 2;
    if (body[pos] != 0x00)
        return false; /* compression must be null */
    return true;
}

/* Parses the ECDHE ServerKeyExchange body, verifies its signature
   against the leaf certificate's RSA key, and returns the server's
   uncompressed EC point. */
static bool parse_server_key_exchange(const u8 *body, u32 len,
                                      const bignum_t *leaf_n, const bignum_t *leaf_e,
                                      u8 peer_x[32], u8 peer_y[32])
{
    if (len < 1 + 2 + 1)
        return false;
    if (body[0] != 3) /* curve_type: named_curve */
        return false;
    if (get_u16_be(body + 1) != 0x0017) /* secp256r1 */
        return false;
    u8 point_len = body[3];
    if (point_len != 65 || 4 + 65 > len)
        return false;
    if (body[4] != 0x04) /* uncompressed point form */
        return false;
    memcpy(peer_x, body + 5, 32);
    memcpy(peer_y, body + 37, 32);

    u32 params_len = 4 + 65;
    if (params_len + 2 + 2 > len)
        return false;
    if (body[params_len] != 0x04 || body[params_len + 1] != 0x01)
        return false; /* only sha256+rsa signatures are supported */
    u32 sig_len = get_u16_be(body + params_len + 2);
    u32 sig_off = params_len + 4;
    if (sig_off + sig_len != len)
        return false;

    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, tls.client_random, 32);
    sha256_update(&ctx, tls.server_random, 32);
    sha256_update(&ctx, body, params_len);
    u8 hash[32];
    sha256_final(&ctx, hash);

    bignum_t sig;
    bn_from_bytes_be(&sig, body + sig_off, sig_len);
    return rsa_verify_pkcs1v15_sha256(leaf_n, leaf_e, &sig, sig_len, hash);
}

/* ---- key derivation (RFC 5246 section 6.3, RFC 5288 for GCM) --------- */

/* Derives master_secret from the ECDHE pre-master secret, then the
   key block (client_write_key, server_write_key, client_write_iv,
   server_write_iv -- no MAC keys, since GCM is an AEAD cipher with no
   separate MAC), and loads both cipher directions. */
static void derive_keys(const u8 pre_master_secret[32])
{
    u8 seed[64];
    memcpy(seed, tls.client_random, 32);
    memcpy(seed + 32, tls.server_random, 32);
    tls_prf(pre_master_secret, 32, "master secret", seed, 64,
           tls.master_secret, 48);

    u8 key_seed[64];
    memcpy(key_seed, tls.server_random, 32);
    memcpy(key_seed + 32, tls.client_random, 32);
    u8 key_block[40]; /* 16+16 keys, 4+4 IVs */
    tls_prf(tls.master_secret, 48, "key expansion", key_seed, 64,
           key_block, sizeof(key_block));

    aes128_set_key(&tls.tx.write_ctx, key_block);
    aes128_set_key(&tls.rx.write_ctx, key_block + 16);
    memcpy(tls.tx.write_iv, key_block + 32, 4);
    memcpy(tls.rx.write_iv, key_block + 36, 4);
}

/* verify_data = PRF(master_secret, label, SHA-256(handshake transcript
   so far))[0..12], per RFC 5246 7.4.9 */
static void compute_finished(const char *label, u8 out[12])
{
    sha256_ctx_t snapshot = tls.transcript; /* struct copy: hash the
        transcript as it stands right now without disturbing the live
        context, since more messages get folded into it afterward */
    u8 transcript_hash[32];
    sha256_final(&snapshot, transcript_hash);
    tls_prf(tls.master_secret, 48, label, transcript_hash, 32, out, 12);
}

/* ---- connection lifecycle --------------------------------------------- */

bool tls_connect(const char *host, const u8 ip[4], u16 port)
{
    memset(&tls, 0, sizeof(tls));

    if (!crypto_ok || !net_tcp_connect(ip, port, 5000))
        return false;

    sha256_init(&tls.transcript);

    u8 hello[512];
    u32 hello_len = build_client_hello(hello, sizeof(hello), host);
    if (!hello_len || !hs_send(TLS_HS_CLIENT_HELLO, hello, hello_len))
        goto fail;

    u8 type;
    const u8 *body;
    u32 body_len;

    if (!hs_next(&type, &body, &body_len) || type != TLS_HS_SERVER_HELLO)
        goto fail;
    if (!parse_server_hello(body, body_len))
        goto fail;

    if (!hs_next(&type, &body, &body_len) || type != TLS_HS_CERTIFICATE)
        goto fail;
    bignum_t leaf_n, leaf_e;
    if (!validate_chain(body, body_len, host, &leaf_n, &leaf_e))
        goto fail;

    if (!hs_next(&type, &body, &body_len) || type != TLS_HS_SERVER_KEY_EXCHANGE)
        goto fail;
    u8 peer_x[32], peer_y[32];
    if (!parse_server_key_exchange(body, body_len, &leaf_n, &leaf_e, peer_x, peer_y))
        goto fail;

    if (!hs_next(&type, &body, &body_len) || type != TLS_HS_SERVER_HELLO_DONE ||
        body_len != 0)
        goto fail;

    u8 our_priv[32], our_pub_x[32], our_pub_y[32];
    if (!p256_generate_keypair(our_priv, our_pub_x, our_pub_y))
        goto fail;
    u8 pre_master_secret[32];
    if (!p256_ecdh_shared_secret(our_priv, peer_x, peer_y, pre_master_secret))
        goto fail;

    u8 cke_body[1 + 65];
    cke_body[0] = 65;
    cke_body[1] = 0x04;
    memcpy(cke_body + 2, our_pub_x, 32);
    memcpy(cke_body + 34, our_pub_y, 32);
    if (!hs_send(TLS_HS_CLIENT_KEY_EXCHANGE, cke_body, sizeof(cke_body)))
        goto fail;

    derive_keys(pre_master_secret);
    memset(our_priv, 0, sizeof(our_priv)); /* done with the ephemeral
        private key -- no reason to leave it sitting in memory */
    memset(pre_master_secret, 0, sizeof(pre_master_secret));

    static const u8 ccs_body = 0x01;
    if (!tls_send_raw_record(TLS_CT_CHANGE_CIPHER_SPEC, &ccs_body, 1))
        goto fail;
    tls.tx.encrypted = true;
    tls.tx.seq = 0;

    u8 client_finished[12];
    compute_finished("client finished", client_finished);
    if (!hs_send(TLS_HS_FINISHED, client_finished, 12))
        goto fail;

    /* server's ChangeCipherSpec is a separate content type, not a
       handshake message -- read it directly off the record layer
       rather than through hs_next() */
    {
        u8 rtype;
        u8 rbuf[16];
        u32 rlen;
        if (!tls_recv_raw_record(&rtype, rbuf, sizeof(rbuf), &rlen))
            goto fail;
        if (rtype != TLS_CT_CHANGE_CIPHER_SPEC || rlen != 1 || rbuf[0] != 0x01)
            goto fail;
    }
    tls.rx.encrypted = true;
    tls.rx.seq = 0;

    if (!hs_next(&type, &body, &body_len) || type != TLS_HS_FINISHED || body_len != 12)
        goto fail;
    u8 expected_server_finished[12];
    compute_finished("server finished", expected_server_finished);
    u8 diff = 0;
    for (int i = 0; i < 12; i++)
        diff |= (u8)(body[i] ^ expected_server_finished[i]);
    if (diff != 0)
        goto fail; /* server's Finished didn't match -- handshake
                       transcript was tampered with or corrupted */

    tls.connected = true;
    return true;

fail:
    net_tcp_close();
    memset(&tls, 0, sizeof(tls));
    return false;
}

u32 tls_send(const u8 *data, u32 len)
{
    if (!tls.connected)
        return 0;
    u32 sent = 0;
    while (sent < len) {
        u32 chunk = len - sent;
        if (chunk > 16384)
            chunk = 16384;
        if (!tls_send_encrypted(TLS_CT_APPLICATION_DATA, data + sent, chunk))
            return sent;
        sent += chunk;
    }
    return sent;
}

u32 tls_recv(u8 *buf, u32 max_len, u32 timeout_ms)
{
    if (!tls.connected)
        return 0;
    u32 start = uptime_ms();
    while (uptime_ms() - start < timeout_ms) {
        u8 type;
        u32 n;
        if (!tls_recv_raw_record(&type, buf, max_len, &n)) {
            if (net_tcp_eof())
                return 0;
            continue;
        }
        if (type == TLS_CT_APPLICATION_DATA)
            return n;
        if (type == TLS_CT_ALERT)
            return 0; /* server closed or errored -- treat as EOF */
        /* anything else (stray handshake/CCS post-handshake) is
           ignored rather than treated as application data */
    }
    return 0;
}

bool tls_eof(void)
{
    return !tls.connected || net_tcp_eof();
}

void tls_close(void)
{
    if (tls.connected) {
        static const u8 close_notify[2] = { 0x01, 0x00 }; /* warning, close_notify */
        tls_send_encrypted(TLS_CT_ALERT, close_notify, 2);
    }
    net_tcp_close();
    memset(&tls, 0, sizeof(tls));
}

static u32 tls_str_append(char *dst, u32 dst_max, const char *src)
{
    u32 n = 0;
    while (src[n] && n + 1 < dst_max) {
        dst[n] = src[n];
        n++;
    }
    dst[n] = 0;
    return n;
}

/* net_http_get()'s exact structure (kernel/net.c), over TLS on port
   443 instead of plain TCP on port 80. Returns the number of response
   bytes written to `out` (0 on any failure: DNS, handshake, or an
   empty response). */
u32 net_https_get(const char *host, const char *path, u8 *out, u32 out_max)
{
    if (!net_ready())
        return 0;

    u8 ip[4];
    if (!net_dns_resolve(host, ip))
        return 0;
    if (!tls_connect(host, ip, 443))
        return 0;

    char req[512];
    u32 pos = 0;
    pos += tls_str_append(req + pos, sizeof(req) - pos, "GET ");
    pos += tls_str_append(req + pos, sizeof(req) - pos, *path ? path : "/");
    pos += tls_str_append(req + pos, sizeof(req) - pos, " HTTP/1.1\r\nHost: ");
    pos += tls_str_append(req + pos, sizeof(req) - pos, host);
    pos += tls_str_append(req + pos, sizeof(req) - pos,
                          "\r\nConnection: close\r\nUser-Agent: AlphaOS\r\n\r\n");

    u32 total = 0;
    if (tls_send((const u8 *)req, pos) == pos) {
        while (total < out_max && !tls_eof()) {
            u32 n = tls_recv(out + total, out_max - total, 5000);
            if (!n)
                break;
            total += n;
        }
    }
    tls_close();
    return total;
}

/* ---- self-test: known-answer vectors, checked at boot -------------------
 *
 * This runs at every boot, before crypto_ok even exists to check --
 * so tls_selftest() only ever verifies the logic *this file* adds on
 * top of the already-verified primitives elsewhere: message framing
 * (ClientHello, ServerKeyExchange), key derivation, Finished
 * computation, and the AEAD record framing. A live handshake against
 * a real server was also exercised during development -- every
 * layer through certificate chain parsing and two levels of RSA/
 * SHA-256 signature verification succeeded against a real (if
 * network-sandboxed) CA infrastructure, and chain validation
 * correctly refused to trust a root outside this file's embedded
 * set, exactly as it should. See SECURITY.md for that story in full;
 * it doesn't fit in a source comment.
 */
static bool tls_bytes_eq(const u8 *a, const u8 *b, u32 n)
{
    for (u32 i = 0; i < n; i++)
        if (a[i] != b[i])
            return false;
    return true;
}

static void tls_hex_decode(const char *hex, u8 *out, u32 n)
{
    for (u32 i = 0; i < n; i++) {
        u8 hi = (u8)hex[i * 2], lo = (u8)hex[i * 2 + 1];
        u8 hv = (hi <= '9') ? (u8)(hi - '0') : (u8)(hi - 'a' + 10);
        u8 lv = (lo <= '9') ? (u8)(lo - '0') : (u8)(lo - 'a' + 10);
        out[i] = (u8)((hv << 4) | lv);
    }
}

bool tls_selftest(void)
{
    /* ClientHello: structural checks against build_client_hello's own output */
    memset(&tls, 0, sizeof(tls));
    u8 hello[512];
    u32 hlen = build_client_hello(hello, sizeof(hello), "example.org");
    if (!hlen || hello[0] != 0x03 || hello[1] != 0x03 || hello[34] != 0x00)
        return false;
    if (hello[35] != 0 || hello[36] != 2 ||
        hello[37] != TLS_CIPHER_ECDHE_RSA_AES128_GCM_SHA256_HI ||
        hello[38] != TLS_CIPHER_ECDHE_RSA_AES128_GCM_SHA256_LO)
        return false;
    if (hello[39] != 1 || hello[40] != 0x00)
        return false;
    u32 ext_len = get_u16_be(hello + 41);
    if (43 + ext_len != hlen)
        return false;
    static const char sni_needle[] = "example.org";
    bool sni_found = false;
    for (u32 i = 43; i + sizeof(sni_needle) - 1 <= hlen; i++)
        if (tls_bytes_eq(hello + i, (const u8 *)sni_needle, sizeof(sni_needle) - 1)) {
            sni_found = true;
            break;
        }
    if (!sni_found)
        return false;

    /* ServerKeyExchange: a real RSA-2048 signature over synthetic
       ECDHE params (P-256 point 7*G), generated independently by
       PyCryptodome, plus a corrupted-signature negative case */
    static const char client_random_hex[] =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    static const char server_random_hex[] =
        "6465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80818283";
    static const char n_hex[] =
        "c922a1b64eab90531235f64872fe3d9e0362f74112188f08369a20d0402b92ee2adb452b8ccdd0d20d1eea528ed57c7d00ecec0f9ae4fa007f1f7662facd590693f5ef39de7a5e1ef960ee6c82f963cff3c58a0f75ff702ed72ddf6d426d52a1f3648dd2c55f88f7a07ce92910087b51fbc47e77a29e35a48968aceb1c05aec151c78f4f303b9d9e6bb88e46ecfd992ffb1598a035d3db569f7f4ea97a62722902dc1e4630466c8449996b484cb38c36b85668c0e77b06e98b77f05e8afe3dd27e0ef41093d297ecd13d60a6bfba2910756e06f07b0e616c95378b27ba8181a130096d5abf852cea4c014fea65d1331cda14c537a9d5911ea0412f43de906d71";
    static const char sig_hex[] =
        "1af51d895857605ad15663c10f8dab90ebea76a4a371294e7a9e7af7b5ce5c2ee3cb1b75746fa774dde8ba51fe5136824dc72a8175815042d3d7c5580dfcb3d352c8b49386ed9dae82625bed68efbeb491fa002f500abc60838acb9b0a7f7d9b7df813c0fe199c1d878d3b4f511808b41da97866777420ea550490afd7e081e35fcd9e76794cf1310d0f0c9b67bd2cf7d7d26d2aeaa72e4e733a7b2b73efbfe7634e39c26d3c462d0f143f7e6ab63eb0ba5d2bd666ee0aac7dcda3d6eea4b5179f31eb1a4d126c6244547cb6f3dd5a6e3a957461d356ae965c65532e2954b279f8f02e274de7054da5ef2726ecc5714a7f9e1bf9fd2a1861e34ff34eb59b523f";
    static const char params_hex[] =
        "03001741048e533b6fa0bf7b4625bb30667c01fb607ef9f8b8a80fef5b300628703187b2a373eb1dbde03318366d069f83a6f5900053c73633cb041b21c55e1a86c1f400b4";
    static const char peer_x_hex[] =
        "8e533b6fa0bf7b4625bb30667c01fb607ef9f8b8a80fef5b300628703187b2a3";
    static const char peer_y_hex[] =
        "73eb1dbde03318366d069f83a6f5900053c73633cb041b21c55e1a86c1f400b4";

    memset(&tls, 0, sizeof(tls));
    tls_hex_decode(client_random_hex, tls.client_random, 32);
    tls_hex_decode(server_random_hex, tls.server_random, 32);

    u8 params[4 + 65];
    tls_hex_decode(params_hex, params, sizeof(params));
    u8 sig[256];
    tls_hex_decode(sig_hex, sig, sizeof(sig));

    u8 ske_body[4 + 65 + 2 + 2 + 256];
    memcpy(ske_body, params, sizeof(params));
    u32 pos = sizeof(params);
    ske_body[pos++] = 0x04;
    ske_body[pos++] = 0x01;
    put_u16_be(ske_body + pos, sizeof(sig));
    pos += 2;
    memcpy(ske_body + pos, sig, sizeof(sig));
    pos += sizeof(sig);

    bignum_t leaf_n, leaf_e;
    u8 n_bytes[256];
    tls_hex_decode(n_hex, n_bytes, 256);
    bn_from_bytes_be(&leaf_n, n_bytes, 256);
    bn_zero(&leaf_e);
    leaf_e.limb[0] = 65537;

    u8 got_x[32], got_y[32], want_x[32], want_y[32];
    if (!parse_server_key_exchange(ske_body, pos, &leaf_n, &leaf_e, got_x, got_y))
        return false;
    tls_hex_decode(peer_x_hex, want_x, 32);
    tls_hex_decode(peer_y_hex, want_y, 32);
    if (!tls_bytes_eq(got_x, want_x, 32) || !tls_bytes_eq(got_y, want_y, 32))
        return false;

    ske_body[pos - 1] ^= 0x01;
    if (parse_server_key_exchange(ske_body, pos, &leaf_n, &leaf_e, got_x, got_y))
        return false; /* corrupted signature must NOT verify */

    /* key derivation + Finished, cross-checked against a from-scratch
       Python TLS 1.2 PRF implementation (HMAC-SHA256 based P_hash) */
    static const char pms_hex[] =
        "05162738495a6b7c8d9eafc0d1e2f30415263748596a7b8c9daebfd0e1f20314";
    static const char want_master_secret_hex[] =
        "0a5c584a538769f9f9a6b4a5091cf79b6ed8f9b862c60fde93d1d074ce0600e6bc31fb49652c61be7054b8cde94ef980";
    static const char want_key_block_hex[] =
        "83b813c84e1125eefeeb9ebef35f16e28f98667231bce968afb4cc12a2c93caf601f506ff58aeea7";
    static const char want_client_finished_hex[] = "3505e329f9a33824787bd928";
    static const char want_server_finished_hex[] = "deab1794b8a100c6afcd0ad8";

    memset(&tls, 0, sizeof(tls));
    tls_hex_decode(client_random_hex, tls.client_random, 32);
    tls_hex_decode(server_random_hex, tls.server_random, 32);
    u8 pms[32];
    tls_hex_decode(pms_hex, pms, 32);
    derive_keys(pms);

    u8 want_master_secret[48];
    tls_hex_decode(want_master_secret_hex, want_master_secret, 48);
    if (!tls_bytes_eq(tls.master_secret, want_master_secret, 48))
        return false;

    u8 key_seed[64];
    memcpy(key_seed, tls.server_random, 32);
    memcpy(key_seed + 32, tls.client_random, 32);
    u8 got_key_block[40], want_key_block[40];
    tls_prf(tls.master_secret, 48, "key expansion", key_seed, 64, got_key_block, 40);
    tls_hex_decode(want_key_block_hex, want_key_block, 40);
    if (!tls_bytes_eq(got_key_block, want_key_block, 40))
        return false;

    static const char transcript_msg[] = "synthetic handshake transcript for testing";
    sha256_init(&tls.transcript);
    sha256_update(&tls.transcript, (const u8 *)transcript_msg,
                  (u32)strlen(transcript_msg));
    u8 got_client_finished[12], want_client_finished[12];
    compute_finished("client finished", got_client_finished);
    tls_hex_decode(want_client_finished_hex, want_client_finished, 12);
    if (!tls_bytes_eq(got_client_finished, want_client_finished, 12))
        return false;
    u8 got_server_finished[12], want_server_finished[12];
    compute_finished("server finished", got_server_finished);
    tls_hex_decode(want_server_finished_hex, want_server_finished, 12);
    if (!tls_bytes_eq(got_server_finished, want_server_finished, 12))
        return false;

    /* AEAD record framing: round-trip through tls_aead_seal/open
       (the pure functions the network-coupled send/recv wrap), plus
       a tampered-ciphertext negative case */
    memset(&tls, 0, sizeof(tls));
    static const u8 test_key[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    static const u8 test_iv[4] = {0xaa,0xbb,0xcc,0xdd};
    aes128_set_key(&tls.tx.write_ctx, test_key);
    memcpy(tls.tx.write_iv, test_iv, 4);

    static const u8 app_msg[] = "GET / HTTP/1.1\r\nHost: example.org\r\n\r\n";
    u8 wire[8 + sizeof(app_msg) - 1 + 16];
    tls_aead_seal(&tls.tx, TLS_CT_APPLICATION_DATA, app_msg, sizeof(app_msg) - 1, wire);

    u8 opened[sizeof(app_msg) - 1];
    if (!tls_aead_open(&tls.tx, TLS_CT_APPLICATION_DATA, wire, sizeof(wire), opened))
        return false;
    if (!tls_bytes_eq(opened, app_msg, sizeof(app_msg) - 1))
        return false;

    wire[8 + 3] ^= 0x01; /* flip a ciphertext byte */
    if (tls_aead_open(&tls.tx, TLS_CT_APPLICATION_DATA, wire, sizeof(wire), opened))
        return false; /* tampered ciphertext must NOT verify */

    memset(&tls, 0, sizeof(tls));
    return true;
}
