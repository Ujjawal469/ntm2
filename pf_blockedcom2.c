#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/pfil.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <net/if.h>
#include <net/ethernet.h> // Not strictly needed for IP filtering
#include <sys/lock.h>
#include <sys/rwlock.h>

static unsigned long dropped_packets = 0;
static unsigned long dropped_bytes = 0;

static struct pfil_hook *pfh_inet_hook = NULL;

static pfil_return_t
pf_http_filter(struct mbuf **mp, struct ifnet *ifp, int dir, void *ruleset, struct inpcb *inp_arg) // Renamed one 'inp' to avoid conflict
{
    struct mbuf *m = *mp; // m now refers to the current mbuf chain
    struct ip *ip_hdr;
    struct tcphdr *tcp_hdr;
    char buf[256]; // buffer size, adjust if HTTP headers are typically larger
    unsigned int ip_hlen, tcp_hlen;
    int payload_offset; // Offset to the start of the TCP payload
    int tocopy;

    // --- Basic checks for valid packet ---
    if (m == NULL) {
        return PFIL_PASS;
    }

    // We are only interested in incoming packets to block access to our service.
    // If you want to block outgoing requests *from* this machine, you'd add logic here
    // for PFIL_OUT and check tcp_hdr->th_sport, ip_hdr->ip_dst etc.
    if (dir != PFIL_IN) {
        return PFIL_PASS;
    }

    // Ensure IP header is present and contiguous in the first mbuf
    if (m->m_len < sizeof(struct ip)) {
        m = m_pullup(m, sizeof(struct ip));
        if (m == NULL) {
            *mp = NULL; // Packet is lost
            return PFIL_DROPPED; // Or PFIL_PASS if you prefer to silently drop
        }
        *mp = m; // Update the mbuf pointer if m_pullup reallocated
    }
    ip_hdr = mtod(m, struct ip *);

    // Only process TCP packets
    if (ip_hdr->ip_p != IPPROTO_TCP) {
        return PFIL_PASS;
    }

    ip_hlen = ip_hdr->ip_hl << 2;

    // Ensure entire IP header + TCP header is present and contiguous
    if (m->m_len < ip_hlen + sizeof(struct tcphdr)) {
        m = m_pullup(m, ip_hlen + sizeof(struct tcphdr));
        if (m == NULL) {
            *mp = NULL; // Packet is lost
            return PFIL_DROPPED;
        }
        *mp = m; // Update the mbuf pointer
        ip_hdr = mtod(m, struct ip *); // Re-get ip_hdr after potential m_pullup
    }
    tcp_hdr = (struct tcphdr *)((caddr_t)ip_hdr + ip_hlen);

    // Only process HTTP traffic on destination port 80
    if (ntohs(tcp_hdr->th_dport) != 80) {
        return PFIL_PASS;
    }

    tcp_hlen = tcp_hdr->th_off << 2;
    payload_offset = ip_hlen + tcp_hlen;

    // Calculate actual payload length remaining in the packet
    // Note: m->m_pkthdr.len is the total packet length
    int total_packet_len = m->m_pkthdr.len;
    int actual_payload_len = total_packet_len - payload_offset;

    if (actual_payload_len <= 0) {
        return PFIL_PASS;
    }

    // Copy relevant part of the payload into our buffer for string comparison
    // Use min to prevent buffer overflow and to not copy more than available payload
    tocopy = min(sizeof(buf) - 1, actual_payload_len);
    m_copydata(m, payload_offset, tocopy, buf);
    buf[tocopy] = '\0'; // Null-terminate the buffer

    // Check for both common casings of "Host:" header
    if (strstr(buf, "Host: blocked.com") != NULL ||
        strstr(buf, "host: blocked.com") != NULL) { // Added lowercase check
        printf("[pf_blockedcom] DEBUG: Found blocked.com in Host header\n");
        dropped_packets++;
        dropped_bytes += total_packet_len; // Use total packet length
        printf("[pf_blockedcom] Dropped HTTP packet to blocked.com (count=%lu, bytes=%lu)\n",
               dropped_packets, dropped_bytes);
        m_freem(m); // Free the mbuf chain for the dropped packet
        *mp = NULL; // Set the mbuf pointer to NULL to indicate it's been consumed
        return PFIL_DROPPED;
    } else {
        printf("[pf_blockedcom] DEBUG: blocked.com not found in Host header, passing\n");
    }
    
    return PFIL_PASS; // Packet not blocked, let it pass
}

static int
load(module_t mod, int cmd, void *arg)
{
    int error = 0;
    struct pfil_link_args pla; // Declare pfil_link_args here

    switch (cmd) {
    case MOD_LOAD:
        {
            struct pfil_hook_args pha;
            
            /* Initialize the hook arguments structure */
            bzero(&pha, sizeof(pha));
            
            pha.pa_version = PFIL_VERSION;
            pha.pa_flags = PFIL_IN; // Only PFIL_IN as per hook logic
            pha.pa_type = PFIL_TYPE_IP4;
            pha.pa_modname = "http_block_mod";
            pha.pa_rulname = "http_block_rule";
            pha.pa_func = pf_http_filter;
            
            pfh_inet_hook = pfil_add_hook(&pha);
            if (pfh_inet_hook == NULL) {
                printf("[pf_blockedcom] Failed to add pfil hook!\n");
                return (ENOMEM);
            }

            // --- Add pfil_link to activate the hook ---
            bzero(&pla, sizeof(pla));
            pla.pa_version = PFIL_VERSION;
            pla.pa_flags = PFIL_IN | PFIL_HOOKPTR; // Link for incoming, use hook pointer
            pla.pa_headname = "inet"; // Link to the IPv4 filter chain
            pla.pa_hook = pfh_inet_hook;

            if (pfil_link(&pla) != 0) {
                printf("[pf_blockedcom] Failed to link pfil hook!\n");
                pfil_remove_hook(pfh_inet_hook); // Clean up if linking fails
                pfh_inet_hook = NULL;
                return (EFAULT);
            }
        }
        printf("[pf_blockedcom] Module loaded. HTTP traffic to 'blocked.com' will be filtered.\n");
        break;

    case MOD_UNLOAD:
        if (pfh_inet_hook != NULL) {
            // --- Unlink the hook before removing it ---
            bzero(&pla, sizeof(pla));
            pla.pa_version = PFIL_VERSION;
            pla.pa_flags = PFIL_IN | PFIL_HOOKPTR;
            pla.pa_headname = "inet";
            pla.pa_hook = pfh_inet_hook;
            pfil_unlink(&pla); // Unlink first
            
            pfil_remove_hook(pfh_inet_hook); // Then remove the hook
            pfh_inet_hook = NULL;
        }
        
        printf("[pf_blockedcom] Module unloaded. Total dropped: %lu packets, %lu bytes\n",
               dropped_packets, dropped_bytes);
        break;

    default:
        error = EOPNOTSUPP;
        break;
    }
    return error;
}

static moduledata_t pf_blockedcom_mod = {
    "pf_blockedcom",
    load,
    NULL
};

DECLARE_MODULE(pf_blockedcom, pf_blockedcom_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
