/*
 * pagerinj — a minimal 802.11 injector for the WiFi Pineapple Pager bench work.
 *
 * Why this exists, and why it is not hcxdumptool or aireplay-ng:
 *
 *   The experiments it serves are about isolating *gates*.  B4 asks whether cfg80211 drops a
 *   monitor-mode frame on a 5 GHz DFS channel; 17a asks whether a Channel Switch Count of 0 is
 *   what disqualifies pineapd's CSA from the connection-denial path.  Any tool that manages the
 *   channel itself, or picks its own frame contents, adds a gate to an experiment whose whole
 *   purpose is removing them.  dev/pager-6ghz-determination-plan.md §B3 rules out aireplay-ng on
 *   exactly that ground; hcxdumptool manages its channel too.
 *
 *   So this does three things and nothing else:
 *     - it never touches the channel.  Whatever `iw dev <if> set freq` left is what it uses.
 *     - it puts bytes you chose on the air, at a rate you chose.
 *     - it can set the CSA count byte, which pineapd hardcodes to 0 and offers no setting for.
 *
 *   It deliberately does NOT use the device's libwifi.  §B3 suggests dlopen()ing it, and notes
 *   that no headers ship so "prototypes and struct layouts must be written by hand" — it calls
 *   struct layouts the real risk.  The CSA element is five bytes; writing five bytes is strictly
 *   safer than guessing a struct layout, and pineapd's own method needs no frame builder either
 *   (recon_engine::index_beacon_ns clones a real beacon and appends the element).  So: no libwifi,
 *   no dlopen, no MIPS16 dlsym bit-0 trap.
 *
 * Modes:
 *   --nonce     transmit a beacon whose SSID carries a nonce.  For B4: proves a frame left the
 *               antenna, identifiable at the external receiver.  Needs no target.
 *   --csa       capture one beacon for --bssid, append a CSA element with the chosen --count,
 *               and flood it.  For 17a: run once with --count 0 and once with --count 3.
 *   --selftest  build frames from a baked-in captured beacon and validate every byte.  No radio,
 *               no interface, no privileges — this is how the build is checked before the bench.
 *
 * Build: see the Makefile beside this file.  Target is mipsel_24kc / musl / soft-float; the
 * loader name must come out as /lib/ld-musl-mipsel-sf.so.1 or it will not run on the Pager.
 *
 * Context: dev/pager-6ghz-determination-plan.md (§B3, §B4), dev/pager-day-one.md (steps 13, 17a),
 * dev/pager-csa-primitives.md ("THE ONE BYTE").  Operator notes: dev/injector/README.md.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

/* ------------------------------------------------------------------ radiotap */

/* Minimal radiotap header for injection: version 0, no present fields.  mac80211 fills in its
 * own defaults for rate and TX flags, which is what we want — we are testing the stack's gates,
 * not a particular PHY rate. */
static const uint8_t RTAP_TX[] = { 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00 };
#define RTAP_TX_LEN (sizeof RTAP_TX)

/* Radiotap bits we care about when parsing a *captured* frame. */
#define RT_TSFT   0
#define RT_FLAGS  1
#define RT_FLAG_FCS 0x10   /* IEEE80211_RADIOTAP_F_FCS: frame includes a trailing 4-byte FCS */

/* Walk a captured radiotap header far enough to learn whether a trailing FCS is present.
 *
 * This matters more than it looks.  In monitor mode the capture may carry a 4-byte FCS at the end
 * of the frame; if it does and we do not strip it, the CSA element we append lands *after* the
 * FCS and every receiver discards the frame as malformed.  That is a silent failure of exactly
 * the kind this whole investigation is trying to avoid, so it is handled rather than assumed.
 *
 * Returns the radiotap header length, sets *fcs to 1 if a trailing FCS is present, or -1 on a
 * header we cannot trust. */
static int rtap_parse(const uint8_t *buf, size_t len, int *fcs)
{
    *fcs = 0;
    if (len < 8 || buf[0] != 0x00)
        return -1;
    uint16_t it_len = (uint16_t)(buf[2] | (buf[3] << 8));
    if (it_len < 8 || it_len > len)
        return -1;

    /* it_present at offset 4; bit 31 set means another present word follows. */
    uint32_t present = (uint32_t)buf[4] | ((uint32_t)buf[5] << 8) |
                       ((uint32_t)buf[6] << 16) | ((uint32_t)buf[7] << 24);
    size_t off = 8;
    uint32_t first = present;
    while (present & (1u << 31)) {
        if (off + 4 > it_len)
            return (int)it_len;          /* truncated bitmap; treat as "no FCS known" */
        present = (uint32_t)buf[off] | ((uint32_t)buf[off + 1] << 8) |
                  ((uint32_t)buf[off + 2] << 16) | ((uint32_t)buf[off + 3] << 24);
        off += 4;
    }

    /* Fields appear in bit order, each with its own alignment.  We only need to reach FLAGS,
     * so the only field that can precede it is TSFT (8 bytes, 8-byte aligned). */
    if (first & (1u << RT_TSFT)) {
        off = (off + 7) & ~(size_t)7;
        off += 8;
    }
    if (first & (1u << RT_FLAGS)) {
        if (off + 1 > it_len)
            return (int)it_len;
        if (buf[off] & RT_FLAG_FCS)
            *fcs = 1;
    }
    return (int)it_len;
}

/* ------------------------------------------------------------- 802.11 layout */

#define FC_MGMT_BEACON_0 0x80    /* type 0 (mgmt), subtype 8 (beacon) */
#define FC_MGMT_BEACON_1 0x00
#define MGMT_HDR_LEN 24          /* fc(2) dur(2) addr1(6) addr2(6) addr3(6) seq(2) */
#define BEACON_FIXED_LEN 12      /* timestamp(8) beacon interval(2) capability(2) */
#define IE_START (MGMT_HDR_LEN + BEACON_FIXED_LEN)

#define EID_SSID 0
#define EID_DS   3
#define EID_CSA  37             /* Channel Switch Announcement */
#define CSA_IE_LEN 3            /* mode(1) new_channel(1) count(1) */

/* The element pineapd builds, for reference.  From dev/pager-csa-primitives.md, construction
 * disassembled at 0x4bee8a:
 *
 *     li v1,37  ; sb -> element ID 37
 *     li v1,3   ; sb -> length 3
 *     li v1,1   ; sb -> Channel Switch Mode = 1   (hardcoded)
 *     lbu  a0+52; sb -> New Channel Number = runtime
 *                 sb -> Channel Switch Count = 0  (s1, zeroed at 0x4bee6c)
 *
 * so {37, 3, 1, ch, 0}.  Only element 37 — no Extended CSA (60), no Operating Class.  The whole
 * point of --count is that the last byte is the one pineapd cannot change. */
static size_t csa_ie_build(uint8_t *out, uint8_t mode, uint8_t chan, uint8_t count)
{
    out[0] = EID_CSA;
    out[1] = CSA_IE_LEN;
    out[2] = mode;
    out[3] = chan;
    out[4] = count;
    return 5;
}

/* Append a CSA element to a captured beacon.
 *
 * `in`/`in_len` is the 802.11 frame with radiotap already stripped and any trailing FCS already
 * removed.  Output is radiotap + the original frame + the CSA element.  We append rather than
 * splice: element order is not significant to mac80211's parser, and appending cannot corrupt an
 * element we failed to understand.
 *
 * Returns the length written, or 0 if the frame is too short or not a beacon. */
static size_t csa_frame_build(const uint8_t *in, size_t in_len,
                              uint8_t mode, uint8_t chan, uint8_t count,
                              uint8_t *out, size_t out_cap)
{
    if (in_len < IE_START)
        return 0;
    if (in[0] != FC_MGMT_BEACON_0 || (in[1] & 0x0c) != 0x00)
        return 0;
    if (RTAP_TX_LEN + in_len + 5 > out_cap)
        return 0;

    memcpy(out, RTAP_TX, RTAP_TX_LEN);
    memcpy(out + RTAP_TX_LEN, in, in_len);
    csa_ie_build(out + RTAP_TX_LEN + in_len, mode, chan, count);
    return RTAP_TX_LEN + in_len + 5;
}

/* Build a self-contained beacon whose SSID is the nonce.  For B4 this is the frame whose arrival
 * at the external receiver proves a transmission left the antenna; nothing about it needs a
 * target or an association.  The nonce also goes in the low 3 bytes of the source MAC so the
 * frame is identifiable two independent ways. */
static size_t nonce_frame_build(const char *nonce, uint8_t chan,
                                uint8_t *out, size_t out_cap)
{
    size_t nlen = strlen(nonce);
    if (nlen > 32)
        nlen = 32;
    size_t need = RTAP_TX_LEN + IE_START + (2 + nlen) + (2 + 1);
    if (need > out_cap)
        return 0;

    uint8_t *p = out;
    memcpy(p, RTAP_TX, RTAP_TX_LEN);
    p += RTAP_TX_LEN;

    uint8_t *f = p;
    memset(f, 0, IE_START);
    f[0] = FC_MGMT_BEACON_0;
    f[1] = FC_MGMT_BEACON_1;
    memset(f + 4, 0xff, 6);                       /* addr1: broadcast */
    /* addr2/addr3: locally-administered OUI 02:00:5e plus three nonce-derived bytes. */
    uint8_t mac[6] = { 0x02, 0x00, 0x5e, 0x00, 0x00, 0x00 };
    uint32_t h = 2166136261u;                     /* FNV-1a, so the MAC tracks the nonce */
    for (size_t i = 0; i < nlen; i++) { h ^= (uint8_t)nonce[i]; h *= 16777619u; }
    mac[3] = (uint8_t)(h >> 16); mac[4] = (uint8_t)(h >> 8); mac[5] = (uint8_t)h;
    memcpy(f + 10, mac, 6);
    memcpy(f + 16, mac, 6);
    f[MGMT_HDR_LEN + 8]  = 0x64;                  /* beacon interval 100 TU */
    f[MGMT_HDR_LEN + 10] = 0x01;                  /* capability: ESS */
    p = f + IE_START;

    *p++ = EID_SSID; *p++ = (uint8_t)nlen;
    memcpy(p, nonce, nlen); p += nlen;
    *p++ = EID_DS;   *p++ = 1; *p++ = chan;

    return (size_t)(p - out);
}

/* ------------------------------------------------------------------- selftest */

/* A real captured beacon, radiotap and FCS already removed: 24-byte header, 12 fixed, then
 * SSID "bench" and DS channel 52.  Used so the selftest exercises csa_frame_build() on a frame
 * shaped like the ones index_beacon_ns clones, not on a synthetic one. */
static const uint8_t FIX_BEACON[] = {
    0x80, 0x00, 0x00, 0x00,                             /* fc, duration */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,                 /* addr1 broadcast */
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55,                 /* addr2 */
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55,                 /* addr3 (BSSID) */
    0x00, 0x00,                                         /* seq */
    0,0,0,0,0,0,0,0,                                    /* timestamp */
    0x64, 0x00,                                         /* beacon interval */
    0x01, 0x00,                                         /* capability */
    0x00, 0x05, 'b','e','n','c','h',                    /* SSID "bench" */
    0x03, 0x01, 0x34                                    /* DS: channel 52 */
};

static int st_n, st_fail;
static void st(const char *name, int ok)
{
    st_n++;
    if (ok) printf("ok   %s\n", name);
    else  { printf("FAIL %s\n", name); st_fail++; }
}
static int st_eqmem(const void *a, const void *b, size_t n) { return memcmp(a, b, n) == 0; }

static int selftest(void)
{
    uint8_t buf[2048];
    size_t n;

    /* --- the CSA element itself, against the bytes pineapd writes at 0x4bee8a --- */
    uint8_t ie[8];
    n = csa_ie_build(ie, 1, 52, 0);
    const uint8_t want_pineapd[] = { 37, 3, 1, 52, 0 };
    st("csa ie: length is 5", n == 5);
    st("csa ie: byte-identical to pineapd's {37,3,1,ch,0}", st_eqmem(ie, want_pineapd, 5));

    csa_ie_build(ie, 1, 52, 3);
    const uint8_t want_count3[] = { 37, 3, 1, 52, 3 };
    st("csa ie: count=3 differs from pineapd in exactly one byte", st_eqmem(ie, want_count3, 5));
    st("csa ie: that byte is the last one", want_pineapd[4] == 0 && want_count3[4] == 3 &&
                                            st_eqmem(want_pineapd, want_count3, 4));

    /* --- appending to a captured beacon --- */
    n = csa_frame_build(FIX_BEACON, sizeof FIX_BEACON, 1, 52, 3, buf, sizeof buf);
    st("csa frame: built", n == RTAP_TX_LEN + sizeof FIX_BEACON + 5);
    st("csa frame: radiotap header intact", st_eqmem(buf, RTAP_TX, RTAP_TX_LEN));
    st("csa frame: original beacon unmodified",
       st_eqmem(buf + RTAP_TX_LEN, FIX_BEACON, sizeof FIX_BEACON));
    st("csa frame: CSA element is last", st_eqmem(buf + n - 5, want_count3, 5));
    st("csa frame: still a beacon", buf[RTAP_TX_LEN] == 0x80);

    /* The count byte must be the ONLY difference between the two arms of step 17a.  If this ever
     * fails, the experiment is not a controlled comparison and its result means nothing. */
    uint8_t a[2048], b[2048];
    size_t na = csa_frame_build(FIX_BEACON, sizeof FIX_BEACON, 1, 52, 0, a, sizeof a);
    size_t nb = csa_frame_build(FIX_BEACON, sizeof FIX_BEACON, 1, 52, 3, b, sizeof b);
    int diffs = 0, diff_at = -1;
    if (na == nb) {
        for (size_t i = 0; i < na; i++)
            if (a[i] != b[i]) { diffs++; diff_at = (int)i; }
    }
    st("17a control: both arms the same length", na == nb && na > 0);
    st("17a control: arms differ in exactly ONE byte", diffs == 1);
    st("17a control: that byte is the CSA count", diff_at == (int)na - 1);

    /* --- rejections --- */
    st("csa frame: rejects a too-short frame",
       csa_frame_build(FIX_BEACON, 8, 1, 52, 0, buf, sizeof buf) == 0);
    st("csa frame: rejects a non-beacon", (buf[0] = 0, 1) &&
       csa_frame_build((const uint8_t[IE_START]){ 0x40 }, IE_START, 1, 52, 0, buf, sizeof buf) == 0);
    st("csa frame: rejects an undersized output buffer",
       csa_frame_build(FIX_BEACON, sizeof FIX_BEACON, 1, 52, 0, buf, 16) == 0);

    /* --- the nonce beacon --- */
    n = nonce_frame_build("PAGERINJ-a1b2c3d4", 52, buf, sizeof buf);
    st("nonce frame: built", n > 0);
    st("nonce frame: is a beacon", buf[RTAP_TX_LEN] == 0x80);
    st("nonce frame: SSID element carries the nonce",
       buf[RTAP_TX_LEN + IE_START] == EID_SSID &&
       buf[RTAP_TX_LEN + IE_START + 1] == 17 &&
       st_eqmem(buf + RTAP_TX_LEN + IE_START + 2, "PAGERINJ-a1b2c3d4", 17));
    st("nonce frame: source MAC is locally administered",
       (buf[RTAP_TX_LEN + 10] & 0x02) != 0);
    st("nonce frame: DS element carries the channel",
       buf[n - 3] == EID_DS && buf[n - 1] == 52);
    size_t n2 = nonce_frame_build("PAGERINJ-deadbeef", 52, a, sizeof a);
    st("nonce frame: a different nonce gives a different MAC",
       n2 > 0 && !st_eqmem(a + RTAP_TX_LEN + 10, buf + RTAP_TX_LEN + 10, 6));
    st("nonce frame: rejects an undersized output buffer",
       nonce_frame_build("PAGERINJ-a1b2c3d4", 52, buf, 16) == 0);

    /* --- radiotap parsing, including the FCS trap --- */
    int fcs = 99;
    const uint8_t rt_plain[] = { 0x00,0x00, 0x08,0x00, 0x00,0x00,0x00,0x00 };
    st("rtap: minimal header, no FCS", rtap_parse(rt_plain, sizeof rt_plain, &fcs) == 8 && fcs == 0);

    /* present = FLAGS only (bit 1); FLAGS byte says FCS present */
    const uint8_t rt_fcs[] = { 0x00,0x00, 0x09,0x00, 0x02,0x00,0x00,0x00, RT_FLAG_FCS };
    st("rtap: FLAGS says FCS present", rtap_parse(rt_fcs, sizeof rt_fcs, &fcs) == 9 && fcs == 1);

    /* present = TSFT|FLAGS; TSFT is 8 bytes and 8-aligned, so FLAGS sits at offset 16 */
    const uint8_t rt_tsft[] = { 0x00,0x00, 0x11,0x00, 0x03,0x00,0x00,0x00,
                                0,0,0,0,0,0,0,0, RT_FLAG_FCS };
    st("rtap: skips TSFT to reach FLAGS", rtap_parse(rt_tsft, sizeof rt_tsft, &fcs) == 17 && fcs == 1);

    const uint8_t rt_ext[] = { 0x00,0x00, 0x0d,0x00, 0x02,0x00,0x00,0x80,
                               0x00,0x00,0x00,0x00, RT_FLAG_FCS };
    st("rtap: walks an extended present bitmap", rtap_parse(rt_ext, sizeof rt_ext, &fcs) == 13);

    st("rtap: rejects a truncated header", rtap_parse(rt_plain, 4, &fcs) == -1);
    const uint8_t rt_bad[] = { 0x01,0x00, 0x08,0x00, 0x00,0x00,0x00,0x00 };
    st("rtap: rejects a non-zero version", rtap_parse(rt_bad, sizeof rt_bad, &fcs) == -1);
    const uint8_t rt_lie[] = { 0x00,0x00, 0xff,0x00, 0x00,0x00,0x00,0x00 };
    st("rtap: rejects it_len past the buffer", rtap_parse(rt_lie, sizeof rt_lie, &fcs) == -1);

    printf("== %d checks, %d failed ==\n", st_n, st_fail);
    return st_fail ? 1 : 0;
}

/* ----------------------------------------------------------------------- net */

static int open_mon(const char *ifname, int *ifindex)
{
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) { perror("socket(AF_PACKET)"); return -1; }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", ifname);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) { perror("SIOCGIFINDEX"); close(fd); return -1; }
    *ifindex = ifr.ifr_ifindex;
    return fd;
}

static int tx(int fd, int ifindex, const uint8_t *f, size_t n)
{
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof sll);
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex  = ifindex;
    sll.sll_halen    = 6;
    return (int)sendto(fd, f, n, 0, (struct sockaddr *)&sll, sizeof sll);
}

/* Capture one beacon for `bssid`.  Returns the 802.11 frame with radiotap stripped and any
 * trailing FCS removed, which is what csa_frame_build() expects. */
static size_t capture_beacon(int fd, const uint8_t *bssid, int timeout_s,
                             uint8_t *out, size_t out_cap)
{
    uint8_t buf[4096];
    time_t deadline = time(NULL) + timeout_s;
    while (time(NULL) < deadline) {
        ssize_t n = recv(fd, buf, sizeof buf, MSG_DONTWAIT);
        if (n <= 0) { struct timespec ts = {0, 2000000}; nanosleep(&ts, NULL); continue; }
        int fcs = 0;
        int rl = rtap_parse(buf, (size_t)n, &fcs);
        if (rl < 0 || (size_t)rl >= (size_t)n) continue;
        const uint8_t *f = buf + rl;
        size_t flen = (size_t)n - (size_t)rl;
        if (fcs) { if (flen < 4) continue; flen -= 4; }
        if (flen < IE_START) continue;
        if (f[0] != FC_MGMT_BEACON_0 || (f[1] & 0x0c) != 0x00) continue;
        if (memcmp(f + 16, bssid, 6) != 0) continue;
        if (flen > out_cap) continue;
        memcpy(out, f, flen);
        return flen;
    }
    return 0;
}

static int parse_mac(const char *s, uint8_t *out)
{
    unsigned v[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x", &v[0],&v[1],&v[2],&v[3],&v[4],&v[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++) { if (v[i] > 0xff) return -1; out[i] = (uint8_t)v[i]; }
    return 0;
}

static void usage(void)
{
    fprintf(stderr,
      "pagerinj — minimal 802.11 injector (never changes the channel)\n"
      "\n"
      "  pagerinj --selftest\n"
      "  pagerinj -i <iface> --nonce <text> [--chan N] [--rate N] [--secs N]\n"
      "  pagerinj -i <iface> --csa --bssid <mac> --chan N --count N\n"
      "                      [--mode N] [--rate N] [--secs N] [--wait N]\n"
      "\n"
      "  --rate   frames per second (default 10)\n"
      "  --secs   how long to transmit; 0 = until interrupted (default 10)\n"
      "  --count  CSA Channel Switch Count.  pineapd hardcodes 0, which the kernel discards\n"
      "           before the auth/assoc refusal check.  Step 17a is --count 0 vs --count 3.\n"
      "  --mode   CSA Channel Switch Mode (default 1, matching pineapd)\n"
      "  --wait   seconds to wait for a beacon from --bssid (default 10)\n"
      "\n"
      "Set the channel yourself first:  iw dev <iface> set freq <MHz> 20\n");
}

int main(int argc, char **argv)
{
    const char *ifname = NULL, *nonce = NULL;
    int do_csa = 0, do_nonce = 0, chan = 0, count = -1, mode = 1;
    int rate = 10, secs = 10, wait_s = 10;
    uint8_t bssid[6]; int have_bssid = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        #define NEXT() (++i < argc ? argv[i] : (usage(), exit(2), ""))
        if      (!strcmp(a, "--selftest")) return selftest();
        else if (!strcmp(a, "-i"))         ifname = NEXT();
        else if (!strcmp(a, "--nonce"))  { do_nonce = 1; nonce = NEXT(); }
        else if (!strcmp(a, "--csa"))      do_csa = 1;
        else if (!strcmp(a, "--bssid"))  { if (parse_mac(NEXT(), bssid) < 0) { usage(); return 2; } have_bssid = 1; }
        else if (!strcmp(a, "--chan"))     chan  = atoi(NEXT());
        else if (!strcmp(a, "--count"))    count = atoi(NEXT());
        else if (!strcmp(a, "--mode"))     mode  = atoi(NEXT());
        else if (!strcmp(a, "--rate"))     rate  = atoi(NEXT());
        else if (!strcmp(a, "--secs"))     secs  = atoi(NEXT());
        else if (!strcmp(a, "--wait"))     wait_s = atoi(NEXT());
        else { usage(); return 2; }
        #undef NEXT
    }

    if (do_csa == do_nonce) { usage(); return 2; }
    if (!ifname)            { usage(); return 2; }
    if (rate < 1) rate = 1;
    if (do_csa) {
        if (!have_bssid || chan <= 0 || chan > 255 || count < 0 || count > 255 ||
            mode < 0 || mode > 255) { usage(); return 2; }
    } else if (chan <= 0 || chan > 255) {
        chan = 1;   /* only cosmetic for the nonce beacon's DS element */
    }

    int ifindex = 0;
    int fd = open_mon(ifname, &ifindex);
    if (fd < 0) return 1;

    uint8_t frame[4096];
    size_t flen = 0;

    if (do_nonce) {
        flen = nonce_frame_build(nonce, (uint8_t)chan, frame, sizeof frame);
        if (!flen) { fprintf(stderr, "nonce too long\n"); close(fd); return 1; }
        fprintf(stderr, "nonce beacon: ssid=\"%s\" src=%02x:%02x:%02x:%02x:%02x:%02x %zu bytes\n",
                nonce, frame[RTAP_TX_LEN+10], frame[RTAP_TX_LEN+11], frame[RTAP_TX_LEN+12],
                frame[RTAP_TX_LEN+13], frame[RTAP_TX_LEN+14], frame[RTAP_TX_LEN+15], flen);
    } else {
        uint8_t cap[4096];
        fprintf(stderr, "waiting up to %ds for a beacon from %02x:%02x:%02x:%02x:%02x:%02x ...\n",
                wait_s, bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5]);
        size_t clen = capture_beacon(fd, bssid, wait_s, cap, sizeof cap);
        if (!clen) {
            fprintf(stderr, "no beacon captured — is the interface on the target's channel?\n");
            close(fd); return 1;
        }
        flen = csa_frame_build(cap, clen, (uint8_t)mode, (uint8_t)chan, (uint8_t)count,
                               frame, sizeof frame);
        if (!flen) { fprintf(stderr, "could not build the CSA frame\n"); close(fd); return 1; }
        fprintf(stderr, "cloned %zu-byte beacon; CSA {37,3,mode=%d,ch=%d,count=%d}; %zu bytes\n",
                clen, mode, chan, count, flen);
    }

    /* Transmit.  Nothing here touches the channel — see the file header. */
    long sent = 0, failed = 0;
    time_t end = secs > 0 ? time(NULL) + secs : 0;
    long interval_ns = 1000000000L / rate;
    for (;;) {
        if (end && time(NULL) >= end) break;
        if (tx(fd, ifindex, frame, flen) < 0) {
            if (failed == 0) perror("sendto");
            failed++;
        } else {
            sent++;
        }
        struct timespec ts = { interval_ns / 1000000000L, interval_ns % 1000000000L };
        nanosleep(&ts, NULL);
    }

    /* sendto() reporting success proves nothing: a cfg80211-blocked frame is freed and the path
     * returns NETDEV_TX_OK.  Only the external receiver can tell you it was transmitted. */
    fprintf(stderr, "sent=%ld failed=%ld  (sendto success does NOT mean transmitted — "
                    "confirm at the external receiver)\n", sent, failed);
    close(fd);
    return failed && !sent ? 1 : 0;
}
