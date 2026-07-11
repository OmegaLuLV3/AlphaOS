/*
 * kernel/net.c — the first slice of a network stack: an RTL8139 PCI
 * NIC driver plus just enough of Ethernet/ARP/IPv4/ICMP to send a real
 * ping and get a real reply back. This is deliberately not more than
 * that yet — no UDP/TCP, no DNS, no TLS — see README.md for the roadmap
 * this is step one of.
 *
 * Register offsets, bit values, and the RX/TX algorithms below are
 * cross-checked against Linux's own 8139too.c driver (the enum
 * RTL8139_registers / ChipCmdBits / IntrStatusBits / RxStatusBits
 * blocks), not reconstructed from memory alone.
 *
 * Threat model note: every byte parsed below (Ethernet/ARP/IPv4/ICMP
 * headers) comes straight off the wire — from QEMU's SLIRP backend in
 * normal use, but structurally this is untrusted network input the
 * same way a loaded .exe is untrusted file input. Every length/offset
 * used here is bounds-checked against the actual frame length before
 * use; see SECURITY.md for the threat model this joins.
 *
 * Static IP configuration matches QEMU's `-netdev user` (SLIRP)
 * defaults exactly (guest 10.0.2.15/24, gateway/DNS proxy 10.0.2.2) —
 * this driver targets that backend specifically, documented in the
 * Makefile's QEMU invocation.
 */
#include "kernel.h"

/* ---- RTL8139 registers (offsets from the I/O base BAR) -------------- */
#define REG_MAC0        0x00
#define REG_TSD0        0x10 /* Transmit Status Descriptor 0-3 (4 x u32) */
#define REG_TSAD0       0x20 /* Transmit Start Address Descriptor 0-3 */
#define REG_RBSTART     0x30
#define REG_CHIPCMD     0x37
#define REG_CAPR        0x38 /* Current Address of Packet Read */
#define REG_IMR         0x3C
#define REG_ISR         0x3E
#define REG_TCR         0x40
#define REG_RCR         0x44
#define REG_CFG9346     0x50
#define REG_CONFIG1     0x52

#define CMD_RESET       0x10
#define CMD_RX_ENABLE   0x08
#define CMD_TX_ENABLE   0x04
#define CMD_RX_EMPTY    0x01

#define ISR_ROK         0x01
#define ISR_TOK         0x04

#define RX_STATUS_OK    0x01

#define RCR_APM         0x02 /* accept physical (our own) MAC match */
#define RCR_AB          0x08 /* accept broadcast */
#define RCR_WRAP        0x80 /* let RX DMA spill into the pad past 8K */

/* nominal ring size the software read pointer wraps at; the extra
   +16+1500 bytes of the actual buffer let a packet that straddles the
   wrap point be written contiguously (that's what RCR_WRAP is for) */
#define RX_BUF_LEN      8192
static u8 rx_buffer[RX_BUF_LEN + 16 + 1500] __attribute__((aligned(4)));

#define TX_SLOTS   4
#define TX_BUF_LEN 1600
static u8 tx_buffer[TX_SLOTS][TX_BUF_LEN] __attribute__((aligned(4)));

static u16 io_base;
static u8  our_mac[6];
static u32 cur_rx;
static u32 tx_slot;
static bool nic_present;
static u8   irq_line;

static const u8 our_ip[4]      = { 10, 0, 2, 15 };
static const u8 gateway_ip[4]  = { 10, 0, 2, 2 };
static const u8 dns_server_ip[4] = { 10, 0, 2, 3 }; /* SLIRP's DNS proxy */
static const u8 bcast_mac[6]   = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

/* ---- byte-order helpers: only 16-bit protocol fields need swapping
   (IP addresses are handled as raw 4-byte arrays throughout, already
   in wire order, so they never need htonl/ntohl) ------------------- */
static u16 htons(u16 v) { return (u16)((v >> 8) | (v << 8)); }
#define ntohs htons /* swap is its own inverse */

/* ---- tiny ARP cache (IP -> MAC), and one outstanding-ping slot ------ */
#define ARP_CACHE_SIZE 4
typedef struct { bool used; u8 ip[4]; u8 mac[6]; } arp_entry_t;
static arp_entry_t arp_cache[ARP_CACHE_SIZE];

static volatile bool ping_reply_seen;
static volatile u16  ping_reply_id, ping_reply_seq;
static volatile u32  ping_reply_ms;
static u16 ping_expect_id, ping_expect_seq;

/* ---- low-level NIC I/O ------------------------------------------------ */

static void nic_send_raw(const u8 *frame, u32 len)
{
    if (!nic_present)
        return;
    u32 slot = tx_slot;
    tx_slot = (tx_slot + 1) % TX_SLOTS;

    u32 n = len < TX_BUF_LEN ? len : TX_BUF_LEN;
    memcpy(tx_buffer[slot], frame, n);
    if (n < 60) { /* Ethernet minimum frame size */
        memset(tx_buffer[slot] + n, 0, 60 - n);
        n = 60;
    }
    outl(io_base + REG_TSAD0 + slot * 4, (u32)(uptr)tx_buffer[slot]);
    outl(io_base + REG_TSD0 + slot * 4, n); /* triggers transmission */
}

/* ---- checksums --------------------------------------------------------- */

static u16 checksum16(const void *data, u32 len)
{
    const u8 *p = data;
    u32 sum = 0;
    while (len > 1) {
        sum += ((u32)p[0] << 8) | p[1];
        p += 2;
        len -= 2;
    }
    if (len)
        sum += (u32)p[0] << 8;
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (u16)~sum;
}

/* ---- Ethernet ----------------------------------------------------------- */

#define ETH_HDR_LEN     14
#define ETHERTYPE_ARP   0x0806
#define ETHERTYPE_IPV4  0x0800

static void eth_send(const u8 dst_mac[6], u16 ethertype, const u8 *payload,
                      u32 payload_len)
{
    u8 frame[ETH_HDR_LEN + 1500];
    if (payload_len > sizeof(frame) - ETH_HDR_LEN)
        return;
    memcpy(frame, dst_mac, 6);
    memcpy(frame + 6, our_mac, 6);
    *(u16 *)(frame + 12) = htons(ethertype);
    memcpy(frame + ETH_HDR_LEN, payload, payload_len);
    nic_send_raw(frame, ETH_HDR_LEN + payload_len);
}

/* ---- ARP ------------------------------------------------------------- */

#define ARP_LEN 28
#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY   2

static void arp_cache_put(const u8 ip[4], const u8 mac[6])
{
    for (u32 i = 0; i < ARP_CACHE_SIZE; i++) {
        if (arp_cache[i].used && memcmp(arp_cache[i].ip, ip, 4) == 0) {
            memcpy(arp_cache[i].mac, mac, 6);
            return;
        }
    }
    for (u32 i = 0; i < ARP_CACHE_SIZE; i++) {
        if (!arp_cache[i].used) {
            arp_cache[i].used = true;
            memcpy(arp_cache[i].ip, ip, 4);
            memcpy(arp_cache[i].mac, mac, 6);
            return;
        }
    }
    /* cache full: drop the newest rather than evict -- this is a
       best-effort cache for a handful of hosts, not a real ARP table */
}

static bool arp_cache_get(const u8 ip[4], u8 mac_out[6])
{
    for (u32 i = 0; i < ARP_CACHE_SIZE; i++) {
        if (arp_cache[i].used && memcmp(arp_cache[i].ip, ip, 4) == 0) {
            memcpy(mac_out, arp_cache[i].mac, 6);
            return true;
        }
    }
    return false;
}

static void arp_send(u16 op, const u8 dst_mac[6], const u8 dst_ip[4])
{
    u8 pkt[ARP_LEN];
    *(u16 *)(pkt + 0) = htons(1);      /* htype: Ethernet */
    *(u16 *)(pkt + 2) = htons(0x0800); /* ptype: IPv4 */
    pkt[4] = 6;                        /* hlen */
    pkt[5] = 4;                        /* plen */
    *(u16 *)(pkt + 6) = htons(op);
    memcpy(pkt + 8, our_mac, 6);
    memcpy(pkt + 14, our_ip, 4);
    memcpy(pkt + 18, dst_mac, 6);
    memcpy(pkt + 24, dst_ip, 4);
    eth_send(dst_mac, ETHERTYPE_ARP, pkt, ARP_LEN);
}

static void arp_handle(const u8 *pkt, u32 len)
{
    if (len < ARP_LEN)
        return;
    u16 op = ntohs(*(const u16 *)(pkt + 6));
    const u8 *sender_mac = pkt + 8;
    const u8 *sender_ip  = pkt + 14;
    const u8 *target_ip  = pkt + 24;

    if (op == ARP_OP_REPLY) {
        arp_cache_put(sender_ip, sender_mac);
    } else if (op == ARP_OP_REQUEST && memcmp(target_ip, our_ip, 4) == 0) {
        arp_cache_put(sender_ip, sender_mac); /* learn the requester too */
        arp_send(ARP_OP_REPLY, sender_mac, sender_ip);
    }
}

bool net_arp_resolve(const u8 ip[4], u8 mac_out[6])
{
    if (arp_cache_get(ip, mac_out))
        return true;
    if (!nic_present)
        return false;

    arp_send(ARP_OP_REQUEST, bcast_mac, ip);

    u32 start = uptime_ms();
    while (uptime_ms() - start < 2000) {
        if (arp_cache_get(ip, mac_out))
            return true;
    }
    return false;
}

/* ---- IPv4 + ICMP -------------------------------------------------------- */

#define IP_HDR_LEN   20
#define IP_PROTO_ICMP 1
#define IP_PROTO_UDP  17
#define ICMP_ECHO_REQUEST 8
#define ICMP_ECHO_REPLY   0
#define IP_PAYLOAD_MAX 512 /* plenty for ICMP echo and DNS queries/replies */

/* Builds and sends an IPv4 header + the given already-built payload
   (ICMP or UDP, whichever proto says) to dst_ip, resolving the
   next-hop MAC via ARP first. Shared by icmp_send() and udp_send() so
   the IP header construction/checksum logic exists in exactly one
   place. */
static void ip_send(const u8 dst_ip[4], u8 proto, const u8 *payload,
                    u32 payload_len)
{
    u8 mac[6];
    if (!net_arp_resolve(dst_ip, mac))
        return;
    if (payload_len > IP_PAYLOAD_MAX)
        return;

    u8 buf[IP_HDR_LEN + IP_PAYLOAD_MAX];
    u8 *ip = buf;
    ip[0] = 0x45; /* version 4, IHL 5 (20 bytes, no options) */
    ip[1] = 0;
    *(u16 *)(ip + 2) = htons(IP_HDR_LEN + payload_len);
    *(u16 *)(ip + 4) = htons(1); /* identification */
    *(u16 *)(ip + 6) = 0;        /* flags/fragment offset */
    ip[8] = 64;                  /* TTL */
    ip[9] = proto;
    *(u16 *)(ip + 10) = 0;       /* checksum, filled below */
    memcpy(ip + 12, our_ip, 4);
    memcpy(ip + 16, dst_ip, 4);
    *(u16 *)(ip + 10) = htons(checksum16(ip, IP_HDR_LEN));

    memcpy(buf + IP_HDR_LEN, payload, payload_len);
    eth_send(mac, ETHERTYPE_IPV4, buf, IP_HDR_LEN + payload_len);
}

static void icmp_send(const u8 dst_ip[4], u8 type, u16 id, u16 seq,
                      const u8 *data, u32 data_len)
{
    u8 icmp[8 + 32];
    u32 icmp_len = 8 + data_len;
    if (icmp_len > sizeof(icmp))
        icmp_len = sizeof(icmp);
    if (data_len > icmp_len - 8)
        data_len = icmp_len - 8;

    icmp[0] = type;
    icmp[1] = 0;
    *(u16 *)(icmp + 2) = 0; /* checksum, filled below */
    *(u16 *)(icmp + 4) = htons(id);
    *(u16 *)(icmp + 6) = htons(seq);
    memcpy(icmp + 8, data, data_len);
    *(u16 *)(icmp + 2) = htons(checksum16(icmp, icmp_len));

    ip_send(dst_ip, IP_PROTO_ICMP, icmp, icmp_len);
}

static void icmp_handle(const u8 src_ip[4], const u8 *pkt, u32 len)
{
    if (len < 8)
        return;
    u8 type = pkt[0];
    u16 id  = ntohs(*(const u16 *)(pkt + 4));
    u16 seq = ntohs(*(const u16 *)(pkt + 6));

    if (type == ICMP_ECHO_REQUEST) {
        icmp_send(src_ip, ICMP_ECHO_REPLY, id, seq, pkt + 8,
                  len - 8 > 32 ? 32 : len - 8);
    } else if (type == ICMP_ECHO_REPLY) {
        if (id == ping_expect_id && seq == ping_expect_seq) {
            ping_reply_id = id;
            ping_reply_seq = seq;
            ping_reply_ms = uptime_ms();
            ping_reply_seen = true;
        }
    }
}

/* ---- UDP ---------------------------------------------------------------- */

#define UDP_HDR_LEN 8

/* single-outstanding-request model, same as the ping_expect_/
   ping_reply_ fields above -- AlphaOS only ever runs one blocking
   network call at a time, so one slot is all that's needed rather
   than a real socket table */
static volatile bool udp_reply_seen;
static u16           udp_expect_local_port;
static u8            udp_reply_buf[512];
static volatile u32  udp_reply_len;

static void udp_send(const u8 dst_ip[4], u16 dst_port, u16 src_port,
                     const u8 *data, u32 data_len)
{
    u8 buf[IP_PAYLOAD_MAX];
    u32 udp_len = UDP_HDR_LEN + data_len;
    if (udp_len > sizeof(buf))
        return;

    *(u16 *)(buf + 0) = htons(src_port);
    *(u16 *)(buf + 2) = htons(dst_port);
    *(u16 *)(buf + 4) = htons(udp_len);
    *(u16 *)(buf + 6) = 0; /* checksum: 0 = not computed, valid per RFC 768 */
    memcpy(buf + UDP_HDR_LEN, data, data_len);

    ip_send(dst_ip, IP_PROTO_UDP, buf, udp_len);
}

static void udp_handle(const u8 *pkt, u32 len)
{
    if (len < UDP_HDR_LEN)
        return;
    u16 dst_port = ntohs(*(const u16 *)(pkt + 2));
    u16 udp_len  = ntohs(*(const u16 *)(pkt + 4));
    if (udp_len < UDP_HDR_LEN || udp_len > len)
        return; /* self-inconsistent or truncated-on-the-wire */

    if (dst_port != udp_expect_local_port)
        return; /* not the reply we're waiting for */

    u32 data_len = udp_len - UDP_HDR_LEN;
    if (data_len > sizeof(udp_reply_buf))
        data_len = sizeof(udp_reply_buf);
    memcpy(udp_reply_buf, pkt + UDP_HDR_LEN, data_len);
    udp_reply_len = data_len;
    udp_reply_seen = true;
}

/* Sends `data` to dst_ip:dst_port from src_port and blocks (bounded)
   for a UDP reply addressed back to src_port. Same one-shot,
   single-outstanding-request polling pattern as net_ping(). */
static bool udp_request(const u8 dst_ip[4], u16 dst_port, u16 src_port,
                        const u8 *data, u32 data_len, u8 *reply_buf,
                        u32 reply_buf_size, u32 *reply_len_out)
{
    if (!nic_present)
        return false;

    udp_expect_local_port = src_port;
    udp_reply_seen = false;
    udp_send(dst_ip, dst_port, src_port, data, data_len);

    u32 start = uptime_ms();
    while (uptime_ms() - start < 2000) {
        if (udp_reply_seen) {
            u32 n = udp_reply_len < reply_buf_size ? udp_reply_len
                                                    : reply_buf_size;
            memcpy(reply_buf, udp_reply_buf, n);
            if (reply_len_out)
                *reply_len_out = n;
            return true;
        }
    }
    return false;
}

static void ip_handle(const u8 *pkt, u32 len)
{
    if (len < IP_HDR_LEN)
        return;
    u8 ihl = (pkt[0] & 0x0F) * 4;
    if (ihl < IP_HDR_LEN || len < ihl)
        return;
    u16 total_len = ntohs(*(const u16 *)(pkt + 2));
    /* total_len must be truncated-on-the-wire-safe (<= the real bytes
       we have) AND self-consistent with the header it claims to carry
       (>= ihl) -- without the second half of this check, a crafted
       packet with total_len < ihl makes total_len - ihl underflow
       below (u16 -> u32 arithmetic), handing icmp_handle() a huge
       bogus length that would read past this packet's real data into
       whatever stale bytes a previous packet left in the RX ring,
       and potentially echo them back to the attacker in a reply. */
    if (total_len > len || total_len < ihl)
        return;
    u8 proto = pkt[9];
    const u8 *src_ip = pkt + 12;
    const u8 *dst_ip = pkt + 16;
    if (memcmp(dst_ip, our_ip, 4) != 0)
        return; /* not addressed to us */

    if (proto == IP_PROTO_ICMP)
        icmp_handle(src_ip, pkt + ihl, total_len - ihl);
    else if (proto == IP_PROTO_UDP)
        udp_handle(pkt + ihl, total_len - ihl);
}

/* ---- Ethernet dispatch + RX/IRQ ---------------------------------------- */

static void eth_handle_frame(const u8 *frame, u32 len)
{
    if (len < ETH_HDR_LEN)
        return;
    u16 ethertype = ntohs(*(const u16 *)(frame + 12));
    const u8 *payload = frame + ETH_HDR_LEN;
    u32 payload_len = len - ETH_HDR_LEN;

    if (ethertype == ETHERTYPE_ARP)
        arp_handle(payload, payload_len);
    else if (ethertype == ETHERTYPE_IPV4)
        ip_handle(payload, payload_len);
}

static void nic_irq(regs_t *r)
{
    (void)r;
    u16 status = inw(io_base + REG_ISR);
    outw(io_base + REG_ISR, status); /* write-1-to-clear the bits we saw */

    if (!(status & ISR_ROK))
        return;

    while (!(inb(io_base + REG_CHIPCMD) & CMD_RX_EMPTY)) {
        u32 offset = cur_rx % RX_BUF_LEN;
        u32 header = *(u32 *)(rx_buffer + offset);
        u16 rx_status = header & 0xFFFF;
        u16 rx_len    = header >> 16; /* includes 4-byte trailing CRC */

        /* a corrupt length (from a wedged NIC/ring desync) must not
           be trusted to compute the next offset -- bound it against
           the actual buffer before touching anything */
        if (rx_len < 4 || rx_len > RX_BUF_LEN) {
            cur_rx = 0;
            outw(io_base + REG_CAPR, (u16)(cur_rx - 16));
            break;
        }

        if ((rx_status & RX_STATUS_OK) && offset + rx_len <= sizeof(rx_buffer))
            eth_handle_frame(rx_buffer + offset + 4, rx_len - 4);

        cur_rx = (cur_rx + rx_len + 4 + 3) & ~3u;
        if (cur_rx > RX_BUF_LEN)
            cur_rx -= RX_BUF_LEN;
        outw(io_base + REG_CAPR, (u16)(cur_rx - 16));
    }
}

/* ---- DNS (minimal A-record resolver) ------------------------------------
 *
 * Talks to whatever DNS server QEMU SLIRP's "user" backend provides
 * (10.0.2.3 by default -- SLIRP's own built-in proxy, which forwards
 * to the host's real resolver) over UDP/53. Only handles a straight
 * A-record lookup: one question, take the first A answer found. No
 * caching, no retries beyond udp_request()'s single 2s timeout, no
 * CNAME following, no AAAA.
 */
#define DNS_PORT       53
#define DNS_LOCAL_PORT 53000
#define DNS_HDR_LEN    12

static u32 dns_encode_name(const char *host, u8 *out, u32 out_max)
{
    u32 pos = 0;
    const char *label = host;
    while (1) {
        const char *p = label;
        while (*p && *p != '.')
            p++;
        u32 label_len = (u32)(p - label);
        if (label_len == 0 || label_len > 63 ||
            pos + 1 + label_len + 1 > out_max)
            return 0; /* empty label, over the 63-byte label cap, or
                          the encoded name doesn't fit -- reject rather
                          than write past `out` */
        out[pos++] = (u8)label_len;
        memcpy(out + pos, label, label_len);
        pos += label_len;
        if (!*p)
            break;
        label = p + 1;
    }
    /* root label (terminating zero byte): every iteration's bound
       check above reserved room for this, including after the last
       real label written, so this write is always in bounds */
    out[pos++] = 0;
    return pos;
}

/* Returns the offset just past a (possibly compressed) DNS name at
   pkt[offset], or 0 on malformed/out-of-bounds input. Doesn't need to
   follow a compression pointer's target -- a pointer is always
   exactly 2 bytes at the location being skipped, regardless of what
   it points to -- which sidesteps the classic "pointer loop" DNS
   parser bug entirely rather than needing a jump-count guard against
   it. */
static u32 dns_skip_name(const u8 *pkt, u32 len, u32 offset)
{
    while (offset < len) {
        u8 b = pkt[offset];
        if (b == 0)
            return offset + 1;
        if ((b & 0xC0) == 0xC0)
            return offset + 2 <= len ? offset + 2 : 0;
        if (b & 0xC0)
            return 0; /* reserved length-byte bits set: malformed */
        offset += 1 + b;
    }
    return 0;
}

bool net_dns_resolve(const char *hostname, u8 ip_out[4])
{
    if (!nic_present)
        return false;

    u8 query[256];
    static u16 query_counter;
    u16 id = (u16)(uptime_ms() ^ (++query_counter * 0x9E37u));
    *(u16 *)(query + 0) = htons(id);
    *(u16 *)(query + 2) = htons(0x0100); /* standard query, recursion desired */
    *(u16 *)(query + 4) = htons(1);      /* QDCOUNT */
    *(u16 *)(query + 6) = 0;             /* ANCOUNT */
    *(u16 *)(query + 8) = 0;             /* NSCOUNT */
    *(u16 *)(query + 10) = 0;            /* ARCOUNT */

    u32 name_len = dns_encode_name(hostname, query + DNS_HDR_LEN,
                                   sizeof(query) - DNS_HDR_LEN - 4);
    if (!name_len)
        return false;
    u32 qpos = DNS_HDR_LEN + name_len;
    *(u16 *)(query + qpos) = htons(1);     /* QTYPE = A */
    *(u16 *)(query + qpos + 2) = htons(1); /* QCLASS = IN */
    u32 query_len = qpos + 4;

    u8 reply[512];
    u32 reply_len = 0;
    if (!udp_request(dns_server_ip, DNS_PORT, DNS_LOCAL_PORT, query,
                     query_len, reply, sizeof(reply), &reply_len))
        return false;

    if (reply_len < DNS_HDR_LEN)
        return false;
    if (ntohs(*(u16 *)(reply + 0)) != id)
        return false; /* not a reply to our query */
    u16 flags = ntohs(*(u16 *)(reply + 2));
    if (!(flags & 0x8000))
        return false; /* QR bit clear: not a response */
    u16 qdcount = ntohs(*(u16 *)(reply + 4));
    u16 ancount = ntohs(*(u16 *)(reply + 6));

    u32 offset = DNS_HDR_LEN;
    for (u16 i = 0; i < qdcount; i++) {
        offset = dns_skip_name(reply, reply_len, offset);
        if (!offset || offset + 4 > reply_len)
            return false;
        offset += 4; /* QTYPE + QCLASS */
    }

    for (u16 i = 0; i < ancount; i++) {
        offset = dns_skip_name(reply, reply_len, offset);
        if (!offset || offset + 10 > reply_len)
            return false; /* TYPE(2)+CLASS(2)+TTL(4)+RDLENGTH(2) */
        u16 rtype = ntohs(*(u16 *)(reply + offset));
        u16 rdlength = ntohs(*(u16 *)(reply + offset + 8));
        offset += 10;
        if (offset + rdlength > reply_len)
            return false;
        if (rtype == 1 && rdlength == 4) { /* A record */
            memcpy(ip_out, reply + offset, 4);
            return true;
        }
        offset += rdlength;
    }
    return false; /* no A record in the answer section */
}

/* ---- public API --------------------------------------------------------- */

bool net_ping(const u8 ip[4], u32 *rtt_ms_out)
{
    if (!nic_present)
        return false;

    u8 mac[6];
    if (!net_arp_resolve(ip, mac))
        return false;

    static u16 seq_counter;
    ping_expect_id = 0xA10E;
    ping_expect_seq = ++seq_counter;
    ping_reply_seen = false;

    static const u8 payload[16] = "AlphaOS ping!";
    u32 sent_ms = uptime_ms();
    icmp_send(ip, ICMP_ECHO_REQUEST, ping_expect_id, ping_expect_seq,
              payload, sizeof(payload));

    u32 start = uptime_ms();
    while (uptime_ms() - start < 2000) {
        if (ping_reply_seen) {
            if (rtt_ms_out)
                *rtt_ms_out = ping_reply_ms - sent_ms;
            return true;
        }
    }
    return false;
}

const u8 *net_gateway_ip(void) { return gateway_ip; }
const u8 *net_our_ip(void) { return our_ip; }
bool net_ready(void) { return nic_present; }

void net_init(void)
{
    pci_dev_t *d = pci_find(0x10EC, 0x8139);
    if (!d) {
        kprint("net: no RTL8139 NIC found (pass -netdev user,id=net0 "
               "-device rtl8139,netdev=net0 to QEMU)\n");
        return;
    }

    pci_enable_device(d);
    /* RTL8139 BAR0 is I/O-space (bit0=1); base address is bits [31:2] */
    io_base = (u16)(d->bar0 & ~0x3u);
    irq_line = d->irq_line;

    outb(io_base + REG_CONFIG1, 0x00); /* power on */

    outb(io_base + REG_CHIPCMD, CMD_RESET);
    for (u32 i = 0; i < 1000000 && (inb(io_base + REG_CHIPCMD) & CMD_RESET);
         i++)
        ;

    outl(io_base + REG_RBSTART, (u32)(uptr)rx_buffer);

    outw(io_base + REG_IMR, ISR_ROK | ISR_TOK);
    outl(io_base + REG_RCR, RCR_APM | RCR_AB | RCR_WRAP);

    outb(io_base + REG_CHIPCMD, CMD_RX_ENABLE | CMD_TX_ENABLE);

    for (u32 i = 0; i < 6; i++)
        our_mac[i] = inb(io_base + REG_MAC0 + i);

    irq_register(irq_line, nic_irq);
    pic_unmask(irq_line);

    nic_present = true;
    kprintf("net: RTL8139 at io=%x irq=%u mac=%x:%x:%x:%x:%x:%x ip=%u.%u.%u.%u\n",
            io_base, irq_line, our_mac[0], our_mac[1], our_mac[2],
            our_mac[3], our_mac[4], our_mac[5], our_ip[0], our_ip[1],
            our_ip[2], our_ip[3]);
}
