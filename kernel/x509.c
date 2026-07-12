/*
 * kernel/x509.c -- a minimal ASN.1 DER parser and X.509 certificate
 * field extractor, scoped to exactly what TLS 1.2's
 * TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 needs: the leaf certificate's
 * RSA public key (to verify ServerKeyExchange), the raw
 * TBSCertificate bytes and signature (to verify the cert itself
 * against an issuer, chain-building being a later step), the raw
 * issuer/subject Name DER (for chain matching by byte comparison, not
 * full RDN parsing), the validity period, and Subject Alternative
 * Name dNSName entries (for hostname verification).
 *
 * This parses untrusted, attacker-controlled network data -- a
 * malicious or malformed certificate must never cause an
 * out-of-bounds read, regardless of how it's mangled. Every length in
 * asn1_parse_tlv() is checked against the actual remaining buffer
 * before being trusted, indefinite-length encoding (invalid in DER)
 * is rejected, and non-minimal long-form lengths (also invalid DER,
 * and a classic parser-confusion vector) are rejected too.
 */
#include "kernel.h"

#define ASN1_TAG_BOOLEAN          0x01
#define ASN1_TAG_INTEGER          0x02
#define ASN1_TAG_BIT_STRING       0x03
#define ASN1_TAG_OCTET_STRING     0x04
#define ASN1_TAG_OID              0x06
#define ASN1_TAG_UTCTIME          0x17
#define ASN1_TAG_GENERALIZEDTIME  0x18
#define ASN1_TAG_SEQUENCE         0x30
#define ASN1_TAG_CTX0             0xA0 /* context-specific [0] constructed -- version */
#define ASN1_TAG_CTX3             0xA3 /* context-specific [3] constructed -- extensions */
#define ASN1_TAG_CTX_DNSNAME      0x82 /* context-specific [2] primitive -- SAN dNSName */

typedef struct {
    u8 tag;
    u32 len;              /* length of value */
    const u8 *value;      /* points into the caller's buffer, never copied */
    const u8 *header_start;
    u32 header_len;
} asn1_tlv_t;

typedef struct {
    const u8 *ptr;
    u32 remaining;
} asn1_cursor_t;

/* Parses exactly one TLV starting at buf[0]; *consumed is set to the
   total header+value bytes on success. Every failure mode here is a
   `return false`, never a partial/best-effort result -- callers must
   not use *out unless this returns true. */
static bool asn1_parse_tlv(const u8 *buf, u32 buf_len, asn1_tlv_t *out, u32 *consumed)
{
    if (buf_len < 2)
        return false;
    out->header_start = buf;
    out->tag = buf[0];
    u8 len_byte = buf[1];
    u32 header_len, len;
    if ((len_byte & 0x80) == 0) {
        len = len_byte;
        header_len = 2;
    } else {
        u32 n = len_byte & 0x7f;
        if (n == 0 || n > 4) /* n==0 is BER indefinite-length, invalid in
                                 DER; cap at 4 bytes (up to 4GiB) -- far
                                 more than any cert or handshake message
                                 this parses could legitimately need */
            return false;
        if (buf_len < (u32)(2 + n))
            return false;
        len = 0;
        for (u32 i = 0; i < n; i++)
            len = (len << 8) | buf[2 + i];
        header_len = 2 + n;
        if (len < 0x80) /* DER requires minimal-length encoding: a value
                            under 0x80 must use short form, not long form */
            return false;
    }
    if (header_len > buf_len || len > buf_len - header_len)
        return false; /* value would run past the end of buf */
    out->len = len;
    out->value = buf + header_len;
    out->header_len = header_len;
    *consumed = header_len + len;
    return true;
}

static bool asn1_cursor_next(asn1_cursor_t *cur, asn1_tlv_t *out)
{
    if (cur->remaining == 0)
        return false;
    u32 consumed;
    if (!asn1_parse_tlv(cur->ptr, cur->remaining, out, &consumed))
        return false;
    cur->ptr += consumed;
    cur->remaining -= consumed;
    return true;
}

static bool x509_bytes_eq(const u8 *a, const u8 *b, u32 n)
{
    for (u32 i = 0; i < n; i++)
        if (a[i] != b[i])
            return false;
    return true;
}

static bool x509_parse_time(const asn1_tlv_t *t, x509_time_t *out)
{
    if (t->tag == ASN1_TAG_UTCTIME) {
        if (t->len != 13 || t->value[12] != 'Z')
            return false;
        for (int i = 0; i < 12; i++)
            if (t->value[i] < '0' || t->value[i] > '9')
                return false;
        u32 yy = (u32)(t->value[0]-'0')*10 + (u32)(t->value[1]-'0');
        out->year = (u16)(yy < 50 ? 2000+yy : 1900+yy); /* RFC 5280 4.1.2.5.1 */
        out->month  = (u8)((t->value[2]-'0')*10 + (t->value[3]-'0'));
        out->day    = (u8)((t->value[4]-'0')*10 + (t->value[5]-'0'));
        out->hour   = (u8)((t->value[6]-'0')*10 + (t->value[7]-'0'));
        out->minute = (u8)((t->value[8]-'0')*10 + (t->value[9]-'0'));
        out->second = (u8)((t->value[10]-'0')*10 + (t->value[11]-'0'));
        return true;
    } else if (t->tag == ASN1_TAG_GENERALIZEDTIME) {
        if (t->len != 15 || t->value[14] != 'Z')
            return false;
        for (int i = 0; i < 14; i++)
            if (t->value[i] < '0' || t->value[i] > '9')
                return false;
        out->year = (u16)((t->value[0]-'0')*1000+(t->value[1]-'0')*100+(t->value[2]-'0')*10+(t->value[3]-'0'));
        out->month  = (u8)((t->value[4]-'0')*10 + (t->value[5]-'0'));
        out->day    = (u8)((t->value[6]-'0')*10 + (t->value[7]-'0'));
        out->hour   = (u8)((t->value[8]-'0')*10 + (t->value[9]-'0'));
        out->minute = (u8)((t->value[10]-'0')*10 + (t->value[11]-'0'));
        out->second = (u8)((t->value[12]-'0')*10 + (t->value[13]-'0'));
        return true;
    }
    return false;
}

/* SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier,
   subjectPublicKey BIT STRING } -- for an RSA key, the BIT STRING
   contains a DER-encoded RSAPublicKey ::= SEQUENCE { modulus INTEGER,
   publicExponent INTEGER } */
static bool x509_parse_spki(const asn1_tlv_t *spki_tlv, x509_cert_t *out)
{
    asn1_cursor_t cur = { spki_tlv->value, spki_tlv->len };
    asn1_tlv_t alg_tlv;
    if (!asn1_cursor_next(&cur, &alg_tlv) || alg_tlv.tag != ASN1_TAG_SEQUENCE)
        return false;
    asn1_cursor_t alg_cur = { alg_tlv.value, alg_tlv.len };
    asn1_tlv_t oid_tlv;
    if (!asn1_cursor_next(&alg_cur, &oid_tlv) || oid_tlv.tag != ASN1_TAG_OID)
        return false;
    static const u8 rsa_encryption_oid[9] = {0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01};
    if (oid_tlv.len != 9 || !x509_bytes_eq(oid_tlv.value, rsa_encryption_oid, 9))
        return false; /* only RSA subject keys are supported -- sufficient
                          for TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 */

    asn1_tlv_t bitstr_tlv;
    if (!asn1_cursor_next(&cur, &bitstr_tlv) || bitstr_tlv.tag != ASN1_TAG_BIT_STRING)
        return false;
    if (bitstr_tlv.len < 1 || bitstr_tlv.value[0] != 0x00)
        return false;
    const u8 *rsakey_buf = bitstr_tlv.value + 1;
    u32 rsakey_len = bitstr_tlv.len - 1;

    asn1_tlv_t rsakey_seq;
    u32 consumed;
    if (!asn1_parse_tlv(rsakey_buf, rsakey_len, &rsakey_seq, &consumed) || rsakey_seq.tag != ASN1_TAG_SEQUENCE)
        return false;
    asn1_cursor_t rsa_cur = { rsakey_seq.value, rsakey_seq.len };
    asn1_tlv_t mod_tlv, exp_tlv;
    if (!asn1_cursor_next(&rsa_cur, &mod_tlv) || mod_tlv.tag != ASN1_TAG_INTEGER)
        return false;
    if (!asn1_cursor_next(&rsa_cur, &exp_tlv) || exp_tlv.tag != ASN1_TAG_INTEGER)
        return false;

    const u8 *mod_p = mod_tlv.value; u32 mod_l = mod_tlv.len;
    if (mod_l > 1 && mod_p[0] == 0x00) { mod_p++; mod_l--; } /* DER's
        non-negative-INTEGER padding byte, not part of the value */
    if (mod_l == 0 || mod_l > 512)
        return false;
    bn_from_bytes_be(&out->rsa_n, mod_p, mod_l);

    const u8 *exp_p = exp_tlv.value; u32 exp_l = exp_tlv.len;
    if (exp_l > 1 && exp_p[0] == 0x00) { exp_p++; exp_l--; }
    if (exp_l == 0 || exp_l > 512)
        return false;
    bn_from_bytes_be(&out->rsa_e, exp_p, exp_l);

    out->has_rsa_key = true;
    return true;
}

static void x509_parse_san(const u8 *buf, u32 len, x509_cert_t *out)
{
    asn1_tlv_t seq;
    u32 consumed;
    if (!asn1_parse_tlv(buf, len, &seq, &consumed) || seq.tag != ASN1_TAG_SEQUENCE)
        return;
    asn1_cursor_t cur = { seq.value, seq.len };
    asn1_tlv_t name;
    while (out->san_dns_count < X509_MAX_SAN && asn1_cursor_next(&cur, &name)) {
        if (name.tag == ASN1_TAG_CTX_DNSNAME) {
            out->san_dns[out->san_dns_count].ptr = name.value;
            out->san_dns[out->san_dns_count].len = name.len;
            out->san_dns_count++;
        }
    }
}

static void x509_parse_basic_constraints(const u8 *buf, u32 len, x509_cert_t *out)
{
    asn1_tlv_t seq;
    u32 consumed;
    if (!asn1_parse_tlv(buf, len, &seq, &consumed) || seq.tag != ASN1_TAG_SEQUENCE)
        return;
    if (seq.len == 0) {
        out->is_ca = false; /* empty SEQUENCE -- cA defaults to FALSE */
        return;
    }
    asn1_cursor_t cur = { seq.value, seq.len };
    asn1_tlv_t b;
    if (asn1_cursor_next(&cur, &b) && b.tag == ASN1_TAG_BOOLEAN && b.len == 1)
        out->is_ca = (b.value[0] != 0x00);
}

/* ext_outer is the [3] EXPLICIT wrapper around the Extensions
   SEQUENCE OF Extension. Unrecognized extensions (the overwhelming
   majority in any real certificate) are silently skipped rather than
   failing the whole parse -- only SubjectAltName and BasicConstraints
   are extracted, since those are the only two this codebase currently
   acts on. */
static void x509_parse_extensions(const asn1_tlv_t *ext_outer, x509_cert_t *out)
{
    asn1_tlv_t exts_seq;
    u32 consumed;
    if (!asn1_parse_tlv(ext_outer->value, ext_outer->len, &exts_seq, &consumed) || exts_seq.tag != ASN1_TAG_SEQUENCE)
        return;
    asn1_cursor_t cur = { exts_seq.value, exts_seq.len };
    asn1_tlv_t ext;
    while (asn1_cursor_next(&cur, &ext)) {
        if (ext.tag != ASN1_TAG_SEQUENCE)
            continue;
        asn1_cursor_t ecur = { ext.value, ext.len };
        asn1_tlv_t oid_tlv;
        if (!asn1_cursor_next(&ecur, &oid_tlv) || oid_tlv.tag != ASN1_TAG_OID)
            continue;
        asn1_tlv_t next_tlv;
        if (!asn1_cursor_next(&ecur, &next_tlv))
            continue;
        asn1_tlv_t octet_tlv;
        if (next_tlv.tag == ASN1_TAG_BOOLEAN) {
            if (!asn1_cursor_next(&ecur, &octet_tlv))
                continue;
        } else {
            octet_tlv = next_tlv;
        }
        if (octet_tlv.tag != ASN1_TAG_OCTET_STRING)
            continue;

        static const u8 oid_san[3] = {0x55,0x1d,0x11};
        static const u8 oid_basic_constraints[3] = {0x55,0x1d,0x13};
        if (oid_tlv.len == 3 && x509_bytes_eq(oid_tlv.value, oid_san, 3))
            x509_parse_san(octet_tlv.value, octet_tlv.len, out);
        else if (oid_tlv.len == 3 && x509_bytes_eq(oid_tlv.value, oid_basic_constraints, 3))
            x509_parse_basic_constraints(octet_tlv.value, octet_tlv.len, out);
    }
}

bool x509_parse_certificate(const u8 *der, u32 der_len, x509_cert_t *out)
{
    memset(out, 0, sizeof(*out));

    asn1_tlv_t cert_tlv;
    u32 consumed;
    if (!asn1_parse_tlv(der, der_len, &cert_tlv, &consumed) || cert_tlv.tag != ASN1_TAG_SEQUENCE)
        return false;
    if (consumed != der_len)
        return false; /* no trailing garbage after the one top-level SEQUENCE */

    asn1_cursor_t cert_cur = { cert_tlv.value, cert_tlv.len };

    asn1_tlv_t tbs_tlv;
    if (!asn1_cursor_next(&cert_cur, &tbs_tlv) || tbs_tlv.tag != ASN1_TAG_SEQUENCE)
        return false;
    out->tbs_start = tbs_tlv.header_start;
    out->tbs_len = tbs_tlv.header_len + tbs_tlv.len;

    asn1_tlv_t sigalg_tlv;
    if (!asn1_cursor_next(&cert_cur, &sigalg_tlv) || sigalg_tlv.tag != ASN1_TAG_SEQUENCE)
        return false;
    {
        asn1_cursor_t sigalg_cur = { sigalg_tlv.value, sigalg_tlv.len };
        asn1_tlv_t oid_tlv;
        if (!asn1_cursor_next(&sigalg_cur, &oid_tlv) || oid_tlv.tag != ASN1_TAG_OID)
            return false;
        static const u8 sha256_rsa_oid[9] = {0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x0b};
        out->sig_alg_is_sha256_rsa = (oid_tlv.len == 9 && x509_bytes_eq(oid_tlv.value, sha256_rsa_oid, 9));
    }

    asn1_tlv_t sigval_tlv;
    if (!asn1_cursor_next(&cert_cur, &sigval_tlv) || sigval_tlv.tag != ASN1_TAG_BIT_STRING)
        return false;
    if (sigval_tlv.len < 1 || sigval_tlv.value[0] != 0x00)
        return false; /* unused-bits byte must be 0 for a byte-aligned RSA sig */
    out->sig_start = sigval_tlv.value + 1;
    out->sig_len = sigval_tlv.len - 1;

    asn1_cursor_t tbs_cur = { tbs_tlv.value, tbs_tlv.len };
    asn1_tlv_t elem;
    if (!asn1_cursor_next(&tbs_cur, &elem))
        return false;
    if (elem.tag == ASN1_TAG_CTX0) {
        if (!asn1_cursor_next(&tbs_cur, &elem)) /* advance past version to serialNumber */
            return false;
    }
    if (elem.tag != ASN1_TAG_INTEGER) /* serialNumber */
        return false;

    if (!asn1_cursor_next(&tbs_cur, &elem) || elem.tag != ASN1_TAG_SEQUENCE) /* signature AlgorithmIdentifier */
        return false;

    if (!asn1_cursor_next(&tbs_cur, &elem) || elem.tag != ASN1_TAG_SEQUENCE) /* issuer */
        return false;
    out->issuer_start = elem.header_start;
    out->issuer_len = elem.header_len + elem.len;

    if (!asn1_cursor_next(&tbs_cur, &elem) || elem.tag != ASN1_TAG_SEQUENCE) /* validity */
        return false;
    {
        asn1_cursor_t val_cur = { elem.value, elem.len };
        asn1_tlv_t nb, na;
        if (!asn1_cursor_next(&val_cur, &nb) || !x509_parse_time(&nb, &out->not_before))
            return false;
        if (!asn1_cursor_next(&val_cur, &na) || !x509_parse_time(&na, &out->not_after))
            return false;
    }

    if (!asn1_cursor_next(&tbs_cur, &elem) || elem.tag != ASN1_TAG_SEQUENCE) /* subject */
        return false;
    out->subject_start = elem.header_start;
    out->subject_len = elem.header_len + elem.len;

    if (!asn1_cursor_next(&tbs_cur, &elem) || elem.tag != ASN1_TAG_SEQUENCE) /* subjectPublicKeyInfo */
        return false;
    if (!x509_parse_spki(&elem, out))
        return false;

    while (asn1_cursor_next(&tbs_cur, &elem)) {
        if (elem.tag == ASN1_TAG_CTX3)
            x509_parse_extensions(&elem, out);
        /* [1]/[2] unique IDs, if present, are simply skipped */
    }

    return true;
}

/* Case-insensitive hostname match against every SAN dNSName, with
   RFC 6125 section 6.4.3's baseline wildcard support: a leading "*."
   label matches exactly one leftmost hostname label (never spans a
   dot, and never matches when the hostname has no further labels
   after it). No support for partial-label wildcards (e.g. "f*.example.com")
   -- real CAs essentially never issue those, and being conservative
   here only makes matching stricter, never looser. */
static u8 x509_lower(u8 c) { return (c >= 'A' && c <= 'Z') ? (u8)(c + 32) : c; }

static bool x509_label_eq_ci(const u8 *a, u32 alen, const char *b, u32 blen)
{
    if (alen != blen)
        return false;
    for (u32 i = 0; i < alen; i++)
        if (x509_lower(a[i]) != x509_lower((u8)b[i]))
            return false;
    return true;
}

bool x509_hostname_matches(const x509_cert_t *cert, const char *hostname)
{
    u32 host_len = (u32)strlen(hostname);
    for (u32 i = 0; i < cert->san_dns_count; i++) {
        const u8 *san = cert->san_dns[i].ptr;
        u32 san_len = cert->san_dns[i].len;

        if (x509_label_eq_ci(san, san_len, hostname, host_len))
            return true;

        if (san_len > 2 && san[0] == '*' && san[1] == '.') {
            u32 host_first_dot = 0;
            bool found_dot = false;
            for (u32 j = 0; j < host_len; j++) {
                if (hostname[j] == '.') { host_first_dot = j; found_dot = true; break; }
            }
            if (!found_dot)
                continue;
            u32 san_suffix_len = san_len - 2;
            u32 host_suffix_len = host_len - host_first_dot - 1;
            if (san_suffix_len == host_suffix_len &&
                x509_label_eq_ci(san + 2, san_suffix_len,
                                 hostname + host_first_dot + 1, host_suffix_len))
                return true;
        }
    }
    return false;
}

/* ---- self-test: a real certificate, checked at boot --------------------
 *
 * The embedded DER below is a real, self-signed 2048-bit RSA/SHA-256
 * certificate generated by OpenSSL (not synthesized by this codebase),
 * with a SubjectAltName extension carrying two dNSName entries and a
 * critical BasicConstraints CA:TRUE. Every field extracted from it is
 * checked against the ground truth `openssl x509 -text` printed for
 * the same certificate during development. Its self-signed nature
 * doubles as an end-to-end test of the whole chain: parse -> extract
 * RSA key -> hash the extracted TBSCertificate bytes -> verify the
 * extracted signature against the extracted key, exercising this
 * file together with sha256() and rsa_verify_pkcs1v15_sha256() from
 * crypto.c, not just x509_parse_certificate() in isolation.
 */
static const u8 x509_test_cert_der[936] = {
    0x30,0x82,0x03,0xa4,0x30,0x82,0x02,0x8c,0xa0,0x03,0x02,0x01,0x02,0x02,0x14,0x67,
    0x91,0xbe,0xe2,0xe5,0xf6,0x1a,0xbe,0xfc,0xda,0x9f,0x1d,0xc5,0xaa,0xb4,0x11,0xc7,
    0xce,0x75,0xd4,0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x0b,
    0x05,0x00,0x30,0x43,0x31,0x0b,0x30,0x09,0x06,0x03,0x55,0x04,0x06,0x13,0x02,0x55,
    0x53,0x31,0x15,0x30,0x13,0x06,0x03,0x55,0x04,0x0a,0x0c,0x0c,0x41,0x6c,0x70,0x68,
    0x61,0x4f,0x53,0x20,0x54,0x65,0x73,0x74,0x31,0x1d,0x30,0x1b,0x06,0x03,0x55,0x04,
    0x03,0x0c,0x14,0x74,0x65,0x73,0x74,0x2e,0x61,0x6c,0x70,0x68,0x61,0x6f,0x73,0x2e,
    0x65,0x78,0x61,0x6d,0x70,0x6c,0x65,0x30,0x1e,0x17,0x0d,0x32,0x36,0x30,0x37,0x31,
    0x32,0x30,0x34,0x33,0x36,0x33,0x37,0x5a,0x17,0x0d,0x32,0x37,0x30,0x37,0x31,0x32,
    0x30,0x34,0x33,0x36,0x33,0x37,0x5a,0x30,0x43,0x31,0x0b,0x30,0x09,0x06,0x03,0x55,
    0x04,0x06,0x13,0x02,0x55,0x53,0x31,0x15,0x30,0x13,0x06,0x03,0x55,0x04,0x0a,0x0c,
    0x0c,0x41,0x6c,0x70,0x68,0x61,0x4f,0x53,0x20,0x54,0x65,0x73,0x74,0x31,0x1d,0x30,
    0x1b,0x06,0x03,0x55,0x04,0x03,0x0c,0x14,0x74,0x65,0x73,0x74,0x2e,0x61,0x6c,0x70,
    0x68,0x61,0x6f,0x73,0x2e,0x65,0x78,0x61,0x6d,0x70,0x6c,0x65,0x30,0x82,0x01,0x22,
    0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01,0x05,0x00,0x03,
    0x82,0x01,0x0f,0x00,0x30,0x82,0x01,0x0a,0x02,0x82,0x01,0x01,0x00,0xa0,0xa3,0x1c,
    0x65,0xca,0x41,0x26,0xfe,0x01,0x28,0x95,0x8a,0x8c,0xca,0xe7,0x84,0x5f,0x80,0xdb,
    0x6e,0xc3,0xc7,0x67,0x32,0xac,0x81,0xd3,0x82,0x01,0x98,0x35,0x81,0x01,0x8d,0x6a,
    0xd6,0x1d,0x09,0xd0,0xb8,0x10,0x32,0x23,0x4a,0x91,0xb0,0x15,0x5a,0x1e,0x00,0x45,
    0x70,0x5a,0xd8,0xdc,0x24,0xe6,0x04,0x10,0xa6,0x2d,0xb8,0xd5,0x42,0x96,0x3d,0x17,
    0x31,0x1a,0x12,0xbf,0xd6,0x17,0x53,0x02,0xfb,0xe3,0xd8,0xbd,0xab,0xee,0x94,0x9a,
    0x7a,0xe5,0xb5,0x19,0x58,0xea,0x55,0x71,0xd7,0xab,0x45,0x0b,0x89,0xbf,0x50,0x2e,
    0x56,0x1c,0xda,0xbf,0x76,0x25,0x18,0x0c,0x7d,0xea,0x8d,0xc4,0x3f,0x22,0x91,0x04,
    0x92,0xd5,0xfa,0xff,0x04,0x18,0x35,0x02,0xb0,0x60,0x7f,0xb6,0xb4,0xb0,0x1c,0x6e,
    0xb6,0x5b,0xb2,0xc2,0x93,0xbb,0x76,0x2f,0x5c,0xdf,0x5e,0x34,0xc1,0x12,0x88,0x17,
    0xff,0x92,0x49,0x9d,0x61,0xd4,0x03,0xc4,0x8b,0x24,0x20,0x2d,0x15,0x11,0x1d,0xb7,
    0x03,0x25,0x81,0x20,0xe4,0x7e,0x57,0xa5,0x60,0x9f,0xfb,0x30,0xf0,0xdd,0xbc,0x4a,
    0xd8,0x68,0x91,0x12,0x76,0x5d,0xc1,0x66,0x79,0x90,0xdb,0x78,0x91,0x1f,0x2d,0x1b,
    0x97,0x8c,0xaa,0x8f,0x1c,0x97,0xd4,0x6f,0x21,0x14,0x86,0x6b,0xa6,0x04,0x16,0x66,
    0x9c,0xcd,0x9d,0x5c,0xd7,0xee,0x31,0xaf,0x05,0xbc,0x7a,0x5e,0xa9,0x91,0x08,0x93,
    0x67,0xb0,0x89,0xc1,0x33,0x3c,0x6c,0xdb,0x60,0xf2,0x03,0x45,0xbf,0x53,0xf7,0x16,
    0x8d,0x17,0xa5,0x3c,0x8c,0x0c,0x85,0xf5,0xd0,0xb3,0x9b,0x79,0x2d,0x02,0x03,0x01,
    0x00,0x01,0xa3,0x81,0x8f,0x30,0x81,0x8c,0x30,0x1d,0x06,0x03,0x55,0x1d,0x0e,0x04,
    0x16,0x04,0x14,0xc7,0x02,0x9b,0xdc,0xb9,0x85,0xce,0xe3,0x89,0x94,0x79,0xe7,0x82,
    0xdb,0xb9,0x38,0x81,0xdb,0xd0,0x10,0x30,0x1f,0x06,0x03,0x55,0x1d,0x23,0x04,0x18,
    0x30,0x16,0x80,0x14,0xc7,0x02,0x9b,0xdc,0xb9,0x85,0xce,0xe3,0x89,0x94,0x79,0xe7,
    0x82,0xdb,0xb9,0x38,0x81,0xdb,0xd0,0x10,0x30,0x0f,0x06,0x03,0x55,0x1d,0x13,0x01,
    0x01,0xff,0x04,0x05,0x30,0x03,0x01,0x01,0xff,0x30,0x39,0x06,0x03,0x55,0x1d,0x11,
    0x04,0x32,0x30,0x30,0x82,0x14,0x74,0x65,0x73,0x74,0x2e,0x61,0x6c,0x70,0x68,0x61,
    0x6f,0x73,0x2e,0x65,0x78,0x61,0x6d,0x70,0x6c,0x65,0x82,0x18,0x77,0x77,0x77,0x2e,
    0x74,0x65,0x73,0x74,0x2e,0x61,0x6c,0x70,0x68,0x61,0x6f,0x73,0x2e,0x65,0x78,0x61,
    0x6d,0x70,0x6c,0x65,0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,
    0x0b,0x05,0x00,0x03,0x82,0x01,0x01,0x00,0x60,0xa7,0x4e,0xc8,0x6b,0x0f,0xf2,0x2f,
    0x1f,0xc9,0x3a,0x99,0x34,0x1a,0xd5,0x44,0xe9,0x49,0xf0,0x99,0x5e,0x8f,0x90,0x1e,
    0xe4,0x41,0x9c,0x9b,0x65,0xdb,0xf9,0xe9,0xd1,0xac,0xd5,0x16,0x3e,0x5d,0x51,0xa6,
    0x59,0x1a,0x67,0x67,0x57,0xd3,0x51,0x82,0xce,0x49,0xf9,0x0b,0x75,0xd7,0x85,0x59,
    0x43,0xb1,0x03,0x86,0xa2,0x80,0x1e,0x1e,0x3b,0x40,0xf7,0xe8,0x3d,0x35,0xb2,0xb1,
    0xa7,0x33,0x72,0x3b,0xc6,0x69,0xe8,0x77,0xa8,0x85,0x2b,0xe6,0xcc,0xab,0x41,0x60,
    0xb0,0xd4,0x6e,0x1e,0x95,0x55,0xc0,0x24,0xf8,0x0b,0x24,0x30,0x70,0x1e,0x31,0xba,
    0xbe,0xfb,0x03,0x66,0x5d,0x52,0xed,0xc9,0x3f,0x2e,0xbb,0xb7,0xca,0x6e,0x38,0xf6,
    0x5f,0x41,0x5b,0xf5,0x39,0x41,0xd7,0x97,0x88,0x75,0x0c,0x3b,0x16,0xe8,0x89,0x5a,
    0xc8,0xa6,0x0a,0xde,0x6d,0x72,0xfc,0x4b,0xcd,0x22,0xff,0x7c,0xe3,0xfe,0xc2,0x7a,
    0xff,0xd7,0xdb,0x29,0x1f,0xe5,0x66,0xed,0x9a,0xab,0xbf,0xee,0x2c,0x1c,0x8a,0x6f,
    0xa2,0xda,0x73,0x0a,0x21,0x40,0x9b,0x41,0xc6,0xfd,0xe8,0x71,0x0c,0x8a,0xf1,0x08,
    0xc3,0xf5,0x1e,0x4c,0xdd,0x63,0x5a,0x29,0x9c,0x66,0x6b,0xc5,0xb2,0x1b,0x96,0x86,
    0x5b,0x49,0xfc,0xfa,0x41,0x8c,0xe8,0x60,0x06,0xbf,0xee,0xec,0x80,0x4b,0x60,0x10,
    0xca,0x7d,0x36,0x1e,0x20,0xdf,0x16,0xf0,0x09,0x52,0x61,0x1d,0x64,0x26,0x08,0xfc,
    0x96,0xa4,0xf3,0x36,0x55,0xf7,0x0a,0x68,0x9c,0xb4,0xbb,0x5a,0x42,0x7f,0x5c,0x82,
    0xb6,0x98,0xcf,0x1f,0xcd,0xc2,0x77,0x3c,
};

bool x509_selftest(void)
{
    x509_cert_t cert;
    if (!x509_parse_certificate(x509_test_cert_der, sizeof(x509_test_cert_der), &cert))
        return false;

    if (!cert.sig_alg_is_sha256_rsa || !cert.has_rsa_key)
        return false;
    if (!cert.is_ca)
        return false;

    if (cert.not_before.year != 2026 || cert.not_before.month != 7 ||
        cert.not_before.day != 12 || cert.not_before.hour != 4 ||
        cert.not_before.minute != 36 || cert.not_before.second != 37)
        return false;
    if (cert.not_after.year != 2027 || cert.not_after.month != 7 ||
        cert.not_after.day != 12)
        return false;

    if (cert.san_dns_count != 2)
        return false;
    static const char san0[] = "test.alphaos.example";
    static const char san1[] = "www.test.alphaos.example";
    if (cert.san_dns[0].len != sizeof(san0) - 1 ||
        !x509_bytes_eq(cert.san_dns[0].ptr, (const u8 *)san0, sizeof(san0) - 1))
        return false;
    if (cert.san_dns[1].len != sizeof(san1) - 1 ||
        !x509_bytes_eq(cert.san_dns[1].ptr, (const u8 *)san1, sizeof(san1) - 1))
        return false;

    bignum_t expect_e;
    bn_zero(&expect_e);
    expect_e.limb[0] = 65537;
    if (bn_cmp(&cert.rsa_e, &expect_e) != 0)
        return false;

    /* end-to-end: this certificate is self-signed, so its signature
       must verify against its own extracted public key */
    u8 tbs_hash[32];
    sha256(cert.tbs_start, cert.tbs_len, tbs_hash);
    bignum_t sig_bn;
    bn_from_bytes_be(&sig_bn, cert.sig_start, cert.sig_len);
    if (!rsa_verify_pkcs1v15_sha256(&cert.rsa_n, &cert.rsa_e, &sig_bn, cert.sig_len, tbs_hash))
        return false;

    if (!x509_hostname_matches(&cert, "test.alphaos.example"))
        return false;
    if (!x509_hostname_matches(&cert, "www.test.alphaos.example"))
        return false;
    if (x509_hostname_matches(&cert, "evil.example"))
        return false;
    if (!x509_hostname_matches(&cert, "TEST.ALPHAOS.EXAMPLE")) /* case-insensitive */
        return false;

    /* wildcard matching, exercised against a synthetic cert (no need
       to embed a second real certificate just for this) */
    x509_cert_t wc;
    memset(&wc, 0, sizeof(wc));
    static const u8 wc_san[] = "*.example.com";
    wc.san_dns_count = 1;
    wc.san_dns[0].ptr = wc_san;
    wc.san_dns[0].len = sizeof(wc_san) - 1;
    if (!x509_hostname_matches(&wc, "foo.example.com"))
        return false;
    if (x509_hostname_matches(&wc, "example.com")) /* wildcard needs a label */
        return false;
    if (x509_hostname_matches(&wc, "a.b.example.com")) /* single-label only */
        return false;
    if (x509_hostname_matches(&wc, "fooexample.com")) /* no dot -- must not match */
        return false;

    /* malformed-DER negative tests -- must all be rejected, not just
       "not crash" (the truncation-fuzz coverage for the "not crash"
       property lived in this file's host-side dev harness, since
       there's no way to assert non-crashing from inside the crashing
       process itself) */
    x509_cert_t junk;
    static const u8 bad_indefinite[] = {0x30, 0x80, 0x02, 0x01, 0x01};
    if (x509_parse_certificate(bad_indefinite, sizeof(bad_indefinite), &junk))
        return false;
    static const u8 bad_nonminimal[] = {0x30, 0x81, 0x02, 0x02, 0x01, 0x00};
    if (x509_parse_certificate(bad_nonminimal, sizeof(bad_nonminimal), &junk))
        return false;
    static const u8 bad_truncated[] = {0x30, 0x7f, 0x02, 0x01};
    if (x509_parse_certificate(bad_truncated, sizeof(bad_truncated), &junk))
        return false;
    static const u8 bad_trailing[] = {0x30, 0x03, 0x02, 0x01, 0x01, 0xff};
    if (x509_parse_certificate(bad_trailing, sizeof(bad_trailing), &junk))
        return false;

    return true;
}
