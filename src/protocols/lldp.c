/**
 * LLDP (Link Layer Discovery Protocol) - IEEE 802.1AB
 * 
 * Implementation file for parsing and displaying LLDP frames
 */

 #ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "src/format/format.h"
#include <string.h>

/* Two bytes on wire: [ TTTTTTT LLLLLLLLL ] (big-endian overall) */
struct lldp_tlv_hdr_bits {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    uint16_t type   : 7;
    uint16_t length : 9;
#else
    /* Portable parsing should avoid bitfields; see note below. */
    uint16_t length : 9;
    uint16_t type   : 7;
#endif
} __attribute__((packed));


/* Helper: safe printable check */
static int is_printable_ascii(const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; ++i) {
        if (p[i] < 32 || p[i] > 126) return 0;
    }
    return 1;
}


/* Try to append "..." without exceeding dstsz or LIMIT budget. 
 * - *pos is the number of display chars already written to dst.
 * - LIMIT is the max budget (20).
 * Ensures dst stays NUL-terminated. 
 */
static void append_ellipsis(char *dst, size_t dstsz, size_t *pos, size_t LIMIT)
{
    static const char ELLIPSIS[] = "...";
    size_t need = 3;  /* strlen("...") */
    size_t room_buf = (dstsz > *pos) ? (dstsz - 1 - *pos) : 0;
    size_t room_lim = (LIMIT > *pos) ? (LIMIT - *pos) : 0;
    size_t to_copy = need;

    if (room_buf < to_copy) to_copy = room_buf;
    if (room_lim < to_copy) to_copy = room_lim;

    if (to_copy > 0) {
        memcpy(dst + *pos, ELLIPSIS, to_copy);
        *pos += to_copy;
        dst[*pos] = '\0';
    }
}





/* Limit formatted output to at most 32 display chars; append "..." if truncated. */
static void copy_text_or_hex(char *dst, size_t dstsz, const uint8_t *p, size_t n)
{
    const size_t LIMIT = 32;  /* display budget, not source bytes */
    size_t pos = 0;

    if (!dst || dstsz == 0) return;
    dst[0] = '\0';
    if (!p) return;

    /* Printable path: take up to LIMIT chars, then "..." if more exist. */
    if (is_printable_ascii(p, n)) {
        size_t want = (n < LIMIT) ? n : LIMIT;
        if (want > 0) {
            size_t room = (dstsz > 1) ? (dstsz - 1) : 0;
            size_t take = (want < room) ? want : room;
            if (take > 0) {
                memcpy(dst, p, take);
                pos = take;
                dst[pos] = '\0';
            }
        }
        if (n > LIMIT) {
            append_ellipsis(dst, dstsz, &pos, LIMIT);
        }
        return;
    }

    /* Hex with ':' path: each first byte -> "XX" (2 chars), following -> ":XX" (3 chars) */
    {
        size_t i = 0;
        int truncated = 0;

        while (i < n) {
            size_t chunk_len = (i == 0) ? 2 : 3;     /* "XX" or ":XX" */
            size_t room_lim  = (LIMIT > pos) ? (LIMIT - pos) : 0;
            size_t room_buf  = (dstsz > pos) ? (dstsz - 1 - pos) : 0;

            /* Would this chunk exceed the 20-char LIMIT? */
            if (chunk_len > room_lim) { truncated = 1; break; }
            /* Do we have space in dst buffer? */
            if (chunk_len > room_buf) { truncated = 1; break; }

            /* Emit chunk */
            if (i == 0) {
                /* First byte: "XX" */
                int w = snprintf(dst + pos, room_buf + 1, "%02x", p[i]);
                if (w < 0) break;
                pos += (size_t)w;
            } else {
                /* Subsequent bytes: ":XX" */
                int w = snprintf(dst + pos, room_buf + 1, ":%02x", p[i]);
                if (w < 0) break;
                pos += (size_t)w;
            }

            ++i;
        }

        if (truncated || i < n) {
            append_ellipsis(dst, dstsz, &pos, LIMIT);
        }

        /* Defensive NUL-termination */
        if (dstsz) dst[dstsz - 1] = '\0';
    }
}

/* Helper: chassis/port ID pretty (subtype-aware) */
static void copy_id_subtyped(char *dst, size_t dstsz, uint8_t subtype,
                             const uint8_t *id, size_t idlen)
{
    if (dstsz == 0) return;
    dst[0] = '\0';

    if (subtype == 4 /* MAC */ && idlen == 6) {
        /* MAC canonical */
        snprintf(dst, dstsz, "%02x:%02x:%02x:%02x:%02x:%02x",
                 id[0], id[1], id[2], id[3], id[4], id[5]);
        return;
    }
    /* Otherwise use text-or-hex */
    copy_text_or_hex(dst, dstsz, id, idlen);
}

/* Build short "Mgmt=..." output.
 * dst/dstsz: output buffer
 * val/len: TLV value pointer/length (NOT including the 2-byte TLV header)
 * Returns 1 if something meaningful was written, 0 otherwise.
 */
static int lldp_format_mgmt_addr_short(char *dst, size_t dstsz,
                                       const uint8_t *val, uint16_t len)
{
    size_t pos = 0;
    if (!dst || dstsz == 0) return 0;
    dst[0] = '\0';

    if (!val || len < 1) return 0;

    uint8_t mlen = val[0];
    if (len < (uint16_t)(1 + mlen + 1 + 4 + 1)) {
        /* Not enough bytes for ifSub(1)+ifNum(4)+oidLen(1) — print only addr if possible */
        if (len < 1 + mlen) return 0;
    }

    const uint8_t *mgmt = val + 1;
    if (mlen < 1) return 0; /* must contain AFI */
    uint8_t afi = mgmt[0];
    const uint8_t *addr = mgmt + 1;
    uint8_t addr_len = (uint8_t)(mlen - 1);

    /* Optional: interface fields if present */
    uint8_t ifsub = 0;
    uint32_t ifnum = 0;
    int have_if = 0;
    if ((uint16_t)(1 + mlen + 1 + 4) <= len) {
        const uint8_t *p_if = val + 1 + mlen;
        ifsub = p_if[0];
        ifnum = ((uint32_t)p_if[1] << 24) |
                ((uint32_t)p_if[2] << 16) |
                ((uint32_t)p_if[3] << 8)  |
                ((uint32_t)p_if[4]);
        have_if = 1;
    }

    /* Start: "Mgmt=" */
    {
        size_t room = (dstsz > 1) ? (dstsz - 1) : 0;
        int w = snprintf(dst, room + 1, "Mgmt=");
        if (w < 0) return 0;
        pos = (size_t)w;
    }

    /* Render address per AFI */
    if (afi == 1 && addr_len == 4) {
        /* IPv4 dotted-decimal */
        size_t room = (dstsz > pos) ? (dstsz - 1 - pos) : 0;
        int w = snprintf(dst + pos, room + 1, "%u.%u.%u.%u",
                         addr[0], addr[1], addr[2], addr[3]);
        if (w < 0) w = 0;
        pos += (size_t)w;
    } else if (afi == 2 && addr_len == 16) {
        /* IPv6: compact hex-pairs joined with ':' (no zero-compression for brevity) */
        size_t room = (dstsz > pos) ? (dstsz - 1 - pos) : 0;
        int w = 0;
        /* Write first 2 bytes as one group, then prepend ':' */
        if (room > 0) {
            w = snprintf(dst + pos, room + 1, "%02x%02x", addr[0], addr[1]);
            if (w < 0) w = 0;
            pos += (size_t)w;
            size_t i;
            for (i = 2; i + 1 < 16; i += 2) {
                room = (dstsz > pos) ? (dstsz - 1 - pos) : 0;
                if (room == 0) break;
                w = snprintf(dst + pos, room + 1, ":%02x%02x", addr[i], addr[i+1]);
                if (w < 0) { w = 0; break; }
                pos += (size_t)w;
            }
        }
    } else {
        /* Unknown/other AFI: render as hex */
        size_t i;
        for (i = 0; i < addr_len; ++i) {
            size_t room = (dstsz > pos) ? (dstsz - 1 - pos) : 0;
            if (room < (i ? 3 : 2)) break;
            if (i == 0) pos += (size_t)snprintf(dst + pos, room + 1, "%02x", addr[i]);
            else        pos += (size_t)snprintf(dst + pos, room + 1, ":%02x", addr[i]);
        }
    }

    /* Optional short suffix with interface number; keep it compact */
    if (have_if) {
        size_t room = (dstsz > pos) ? (dstsz - 1 - pos) : 0;
        if (room > 0) {
            /* You can change "ifX" to "ifIndex" or omit if you want even shorter */
            int w = snprintf(dst + pos, room + 1, "(ifX=%" PRIu32 ")", ifnum);
            if (w > 0) pos += (size_t)w;
        }
    }

    /* Ensure NUL-termination */
    if (dstsz) dst[dstsz - 1] = '\0';
    return 1;
}


static inline void lldp_get_tlv_hdr(const uint8_t *p, uint8_t *type, uint16_t *length)
{
    /* TLV header is 2 bytes, big-endian: [ TTTTTTT LLLLLLLLL ] */
    uint16_t w = (uint16_t)p[0] << 8 | p[1];
    *type   = (uint8_t)((w >> 9) & 0x7F);
    *length = (uint16_t)(w & 0x1FF);
}

struct lldp_tlv {
    uint8_t type;          /* 0..127 */
    uint16_t length;       /* 0..511 */
    const uint8_t *value;  /* points into the original frame buffer */
};

static void lldp_dump_tlv_chassis_id(FILE *fp, const char *prefix, const uint8_t *val, uint16_t len)
{
    /* Value = 1 byte subtype + ID (len-1) */
    if (len < 1) {
        fprintf(fp, "%sChassis ID: <malformed>\n", prefix);
        return;
    }
    uint8_t subtype = val[0];
    const uint8_t *id = val + 1;
    uint16_t idlen = (uint16_t)(len - 1);

    fprintf(fp, "%sChassis ID: subtype %u, value ", prefix, subtype);
    /* quick printable-or-hex dump */
    int printable = 1;
    for (uint16_t i = 0; i < idlen; ++i) {
        if ((unsigned)id[i] < 32 || (unsigned)id[i] > 126) { printable = 0; break; }
    }
    if (printable) {
        fwrite(id, 1, idlen, fp);
    } else {
        for (uint16_t i = 0; i < idlen; ++i)
            fprintf(fp, "%s%02x", (i ? ":" : ""), id[i]);
    }
    fputc('\n', fp);
}

static void lldp_dump_tlv_port_id(FILE *fp, const char *prefix, const uint8_t *val, uint16_t len)
{
    if (len < 1) {
        fprintf(fp, "%sPort ID: <malformed>\n", prefix);
        return;
    }
    uint8_t subtype = val[0];
    const uint8_t *id = val + 1;
    uint16_t idlen = (uint16_t)(len - 1);

    fprintf(fp, "%sPort ID: subtype %u, value ", prefix, subtype);
    int printable = 1;
    for (uint16_t i = 0; i < idlen; ++i) {
        if ((unsigned)id[i] < 32 || (unsigned)id[i] > 126) { printable = 0; break; }
    }
    if (printable) fwrite(id, 1, idlen, fp);
    else {
        for (uint16_t i = 0; i < idlen; ++i)
            fprintf(fp, "%s%02x", (i ? ":" : ""), id[i]);
    }
    fputc('\n', fp);
}

static void lldp_dump_tlv_ttl(FILE *fp, const char *prefix, const uint8_t *val, uint16_t len)
{
    if (len != 2) {
        fprintf(fp, "%sTTL: <malformed>\n", prefix);
        return;
    }
    uint16_t ttl = (uint16_t)val[0] << 8 | val[1];
    fprintf(fp, "%sTTL: %u s\n", prefix, ttl);
}

static void lldp_dump_tlv_text(FILE *fp, const char *prefix, const char *label, const uint8_t *val, uint16_t len)
{
    fprintf(fp, "%s%s: ", prefix, label);
    /* Just print as-is if printable; else hex */
    int printable = 1;
    for (uint16_t i = 0; i < len; ++i) {
        if ((unsigned)val[i] < 32 || (unsigned)val[i] > 126) { printable = 0; break; }
    }
    if (printable) fwrite(val, 1, len, fp);
    else {
        for (uint16_t i = 0; i < len; ++i)
            fprintf(fp, "%s%02x", (i ? ":" : ""), val[i]);
    }
    fputc('\n', fp);
}

static void lldp_dump_tlv_sys_caps(FILE *fp, const char *prefix, const uint8_t *val, uint16_t len)
{
    if (len != 4) {
        fprintf(fp, "%sSystem Capabilities: <malformed>\n", prefix);
        return;
    }
    uint16_t caps = (uint16_t)val[0] << 8 | val[1];
    uint16_t enab = (uint16_t)val[2] << 8 | val[3];

    fprintf(fp, "%sSystem Capabilities: 0x%04x  Enabled: 0x%04x\n", prefix, caps, enab);
}

static void lldp_dump_tlv_org(FILE *fp, const char *prefix, const uint8_t *val, uint16_t len)
{
    if (len < 4) {
        fprintf(fp, "%sOrg-Specific: <malformed>\n", prefix);
        return;
    }
    fprintf(fp, "%sOrg-Specific: OUI %02x:%02x:%02x subtype %u, len %u\n",
            prefix, val[0], val[1], val[2], val[3], (unsigned)len);
}

static enum caputils_protocol_type lldp_next(struct header_chunk* header, const char* ptr, const char** out){
    return PROTOCOL_DONE; /* Do not look for data after LLDP message */
}


static void lldp_format(FILE* fp, const struct header_chunk* header, const char* ptr, unsigned int flags){

	if ( limited_caplen(header->cp, ptr, sizeof(struct lldp_tlv)) ){
		fputs(" [Packet size limited during capture]", fp);
		return;
	}

    const size_t payload_size = header->last_net.plen;
   
    /* ---- First pass: collect fields we care about ---- */
    char sys_name[256] = {0};
    char sys_desc[256] = {0};
    char chassis_id[256] = {0};
    char port_id[256] = {0};
    char mgmt_short[128] = {0};

    int have_sys_name = 0, have_sys_desc = 0;
    int have_chassis = 0, have_port = 0;
    int have_mgmt = 0;

    const char *p = ptr; /* cursor into payload */

    for (;;) {
        /* 1) Check we can read the 2-byte TLV header */
        if (limited_caplen(header->cp, p, 2)) {
            fprintf(fp, "[Truncated: missing TLV header] ");
            return;
        }

        uint8_t  tlv_type = 0;
        uint16_t tlv_len  = 0;
        lldp_get_tlv_hdr((const uint8_t*)p, &tlv_type, &tlv_len);

        /* Move past the TLV header */
        p += 2;

        /* 2) Verify that Value fits in capture bounds */
        if (limited_caplen(header->cp, p, tlv_len)) {
            fprintf(fp, "[Truncated: TLV value exceeds captured length]\n");
            return;
        }

        const uint8_t *val = (const uint8_t*)p;

        /* 3) Dispatch per TLV type */
        switch (tlv_type) {
        case 0: /* End of LLDPDU */
            goto done_collect;

        case 1: /* Chassis ID */
            if (tlv_len >= 1 && !have_chassis) {
                uint8_t subtype = val[0];
                const uint8_t *id = val + 1;
                size_t idlen = (size_t)(tlv_len - 1);
                copy_id_subtyped(chassis_id, sizeof(chassis_id), subtype, id, idlen);
                have_chassis = 1;
            }
 //       lldp_format_tlv_chassis_id(fp, (const uint8_t*)p, tlv_len);
            break;

        case 2: /* Port ID */
            if (tlv_len >= 1 && !have_port) {
                uint8_t subtype = val[0];
                const uint8_t *id = val + 1;
                size_t idlen = (size_t)(tlv_len - 1);
                copy_id_subtyped(port_id, sizeof(port_id), subtype, id, idlen);
                have_port = 1;
            }
//            lldp_format_tlv_port_id(fp, (const uint8_t*)p, tlv_len);
            break;
/*
        case 3: // TTL 
            lldp_format_tlv_ttl(fp, (const uint8_t*)p, tlv_len);
            break;

        case 4: // Port Description 
            lldp_format_tlv_text(fp, "P.Desc", (const uint8_t*)p, tlv_len);
            break;
*/

        case 5: /* System Name */
            if (!have_sys_name) {
                copy_text_or_hex(sys_name, sizeof(sys_name), val, tlv_len);
                have_sys_name = 1;
            }
//            lldp_format_tlv_text(fp, "Sys.Name", (const uint8_t*)p, tlv_len);
            break;

        case 6: /* System Description */
            if (!have_sys_desc) {
                copy_text_or_hex(sys_desc, sizeof(sys_desc), val, tlv_len);
                have_sys_desc = 1;
            }
//            lldp_format_tlv_text(fp, "Sys.Desc", (const uint8_t*)p, tlv_len);
            break;


        case 8: /* Management Address */
            if (!have_mgmt) {
                /* Build a short string right away */
                if (lldp_format_mgmt_addr_short(mgmt_short, sizeof(mgmt_short), val, tlv_len)) {
                    have_mgmt = 1;
                }
            }
            break;

/*
         case 7: // System Capabilities 
//            lldp_format_tlv_sys_caps(fp, (const uint8_t*)p, tlv_len);
            break;
        
        case 8: // Management Address 
            // You can add a dedicated parser; for now, show raw length. 
//            fprintf(fp, "Mgnt.Add.TLV.len %u ",(unsigned)tlv_len);
            break;

        
        case 127:  // Organizationally Specific. 
 //           lldp_format_tlv_org(fp, (const uint8_t*)p, tlv_len);
            break;
 */       

        default:
            /* Generic fallback */
//            fprintf(fp, "TLV type %u, len %u", (unsigned)tlv_type, (unsigned)tlv_len);
            break;
        }

        /* 4) Advance to next TLV value start + length */
        p += tlv_len;

        /* 5) Loop continues; next iteration will check header bounds again */
        /* Optional guard: if tlv_len == 0 (should only happen for End TLV),
           we would have returned already; this prevents infinite loops. */
    }
done_collect:


    /* ---- Second pass: emit in desired order ---- */
    fprintf(fp, "LLDP: ");
    if (flags & FORMAT_HEADER) {
        fprintf(fp, "(HDR[<needs_calc>]DATA[%zu]) ", payload_size);
    }

    /* Desired order: Sys.Name (ChassisID) / PortID Sys.Desc */
    if (have_sys_name) {
        fprintf(fp, "%s", sys_name);
    }
/*
    if (have_chassis) {
        fprintf(fp, "(%s)", chassis_id);
    }
*/
    if (have_port) {
        fprintf(fp, "/%s ", port_id);
    }

    
    /* Show Mgmt after interface details */
    if (have_mgmt) {
        char mgmt_capped[32];
        copy_text_or_hex(mgmt_capped, sizeof(mgmt_capped),
                        (const uint8_t*)mgmt_short, strlen(mgmt_short));
        fprintf(fp, "%s ", mgmt_capped);
    }


    if (have_sys_desc) {
        fprintf(fp, "%s", sys_desc);
    }

//    fprintf(fp,"\n");

}

static void lldp_dump(FILE* fp, const struct header_chunk* header, const char* ptr, const char* prefix, int flags){
	if ( limited_caplen(header->cp, ptr, sizeof(struct lldp_tlv)) ){
		fprintf(fp, "%s[Packet size limited during capture]", prefix);
		return;
	}
    fprintf(fp, "LLDP\n");
    const char *p = ptr; /* cursor into payload */

    
    for (;;) {
        /* 1) Check we can read the 2-byte TLV header */
        if (limited_caplen(header->cp, p, 2)) {
            fprintf(fp, "%s[Truncated: missing TLV header]\n", prefix);
            return;
        }

        uint8_t  tlv_type = 0;
        uint16_t tlv_len  = 0;
        lldp_get_tlv_hdr((const uint8_t*)p, &tlv_type, &tlv_len);

        /* Move past the TLV header */
        p += 2;

        /* 2) Verify that Value fits in capture bounds */
        if (limited_caplen(header->cp, p, tlv_len)) {
            fprintf(fp, "%s[Truncated: TLV value exceeds captured length]\n", prefix);
            return;
        }

        /* 3) Dispatch per TLV type */
        switch (tlv_type) {
        case 0: /* End of LLDPDU */
//            fprintf(fp, "%sEnd of LLDPDU\n", prefix);
            return;

        case 1: /* Chassis ID */
            lldp_dump_tlv_chassis_id(fp, prefix, (const uint8_t*)p, tlv_len);
            break;

        case 2: /* Port ID */
            lldp_dump_tlv_port_id(fp, prefix, (const uint8_t*)p, tlv_len);
            break;

        case 3: /* TTL */
            lldp_dump_tlv_ttl(fp, prefix, (const uint8_t*)p, tlv_len);
            break;

        case 4: /* Port Description */
            lldp_dump_tlv_text(fp, prefix, "Port Description", (const uint8_t*)p, tlv_len);
            break;

        case 5: /* System Name */
            lldp_dump_tlv_text(fp, prefix, "System Name", (const uint8_t*)p, tlv_len);
            break;

        case 6: /* System Description */
            lldp_dump_tlv_text(fp, prefix, "System Description", (const uint8_t*)p, tlv_len);
            break;

        case 7: /* System Capabilities */
            lldp_dump_tlv_sys_caps(fp, prefix, (const uint8_t*)p, tlv_len);
            break;

        case 8: /* Management Address */
            /* You can add a dedicated parser; for now, show raw length. */
            fprintf(fp, "%sManagement Address TLV (len %u)\n", prefix, (unsigned)tlv_len);
            break;

        case 127: /* Organizationally Specific */
            lldp_dump_tlv_org(fp, prefix, (const uint8_t*)p, tlv_len);
            break;

        default:
            /* Generic fallback */
            fprintf(fp, "%sTLV type %u, len %u\n", prefix, (unsigned)tlv_type, (unsigned)tlv_len);
            break;
        }

        /* 4) Advance to next TLV value start + length */
        p += tlv_len;

        /* 5) Loop continues; next iteration will check header bounds again */
        /* Optional guard: if tlv_len == 0 (should only happen for End TLV),
           we would have returned already; this prevents infinite loops. */
    }



}

struct caputils_protocol protocol_lldp = {
	.name = "LLDP",
	.size = sizeof(struct lldp_tlv),
	.next_payload = lldp_next,
	.format = lldp_format,
	.dump = lldp_dump,
};
