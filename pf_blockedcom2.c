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
#include <net/ethernet.h>
#include <sys/lock.h>
#include <sys/rwlock.h>

static unsigned long dropped_packets = 0;
static unsigned long dropped_bytes = 0;

static struct pfil_hook *pfh_inet_hook = NULL;

/* Hook function with extensive debugging */
static int
pf_http_filter(void *arg, struct mbuf **mp, struct ifnet *ifp, int dir, void *inp)
{
    struct mbuf *m = *mp;
    struct ip *ip_hdr;
    struct tcphdr *tcp_hdr;
    char buf[256];  // Increased buffer size
    int ip_hlen, tcp_hlen, payload_len;
    int tocopy;

    printf("[pf_blockedcom] DEBUG: Packet received, direction: %d\n", dir);

    if (m == NULL) {
        printf("[pf_blockedcom] DEBUG: Null mbuf, passing\n");
        return (0);
    }

    printf("[pf_blockedcom] DEBUG: Packet length: %d\n", m->m_pkthdr.len);

    /* Check if it's an IP packet */
    if (m->m_pkthdr.len < sizeof(struct ip)) {
        printf("[pf_blockedcom] DEBUG: Packet too short for IP, passing\n");
        return (0);
    }

    /* Get IP header */
    if (m->m_len < sizeof(struct ip) && (m = m_pullup(m, sizeof(struct ip))) == NULL) {
        printf("[pf_blockedcom] DEBUG: Failed to pull up IP header, passing\n");
        return (0);
    }
    
    ip_hdr = mtod(m, struct ip *);
    printf("[pf_blockedcom] DEBUG: IP protocol: %d\n", ip_hdr->ip_p);
    
    /* Check if it's TCP */
    if (ip_hdr->ip_p != IPPROTO_TCP) {
        printf("[pf_blockedcom] DEBUG: Not TCP, passing\n");
        return (0);
    }

    ip_hlen = ip_hdr->ip_hl << 2;
    printf("[pf_blockedcom] DEBUG: IP header length: %d\n", ip_hlen);
    
    /* Ensure we have enough data for TCP header */
    if (m->m_len < ip_hlen + sizeof(struct tcphdr)) {
        m = m_pullup(m, ip_hlen + sizeof(struct tcphdr));
        if (m == NULL) {
            printf("[pf_blockedcom] DEBUG: Failed to pull up TCP header, passing\n");
            return (0);
        }
        *mp = m;
        ip_hdr = mtod(m, struct ip *);
    }

    tcp_hdr = (struct tcphdr *)((caddr_t)ip_hdr + ip_hlen);
    printf("[pf_blockedcom] DEBUG: TCP dest port: %d\n", ntohs(tcp_hdr->th_dport));
    
    /* Check if it's HTTP (port 80) */
    if (ntohs(tcp_hdr->th_dport) != 80) {
        printf("[pf_blockedcom] DEBUG: Not HTTP (port 80), passing\n");
        return (0);
    }

    tcp_hlen = tcp_hdr->th_off << 2;
    printf("[pf_blockedcom] DEBUG: TCP header length: %d\n", tcp_hlen);
    
    payload_len = ntohs(ip_hdr->ip_len) - (ip_hlen + tcp_hlen);
    printf("[pf_blockedcom] DEBUG: Payload length: %d\n", payload_len);
    
    if (payload_len <= 0) {
        printf("[pf_blockedcom] DEBUG: No payload, passing\n");
        return (0);
    }

    /* Copy payload for inspection */
    tocopy = min(sizeof(buf) - 1, payload_len);
    m_copydata(m, ip_hlen + tcp_hlen, tocopy, buf);
    buf[tocopy] = '\0';
    
    printf("[pf_blockedcom] DEBUG: Payload (first %d bytes): %s\n", tocopy, buf);

    /* Check for blocked.com in Host header */
    if (strstr(buf, "Host: blocked.com") != NULL ||
        strstr(buf, "host: blocked.com") != NULL) {
        printf("[pf_blockedcom] DEBUG: Found blocked.com in Host header\n");
        dropped_packets++;
        dropped_bytes += m->m_pkthdr.len;
        printf("[pf_blockedcom] Dropped HTTP packet to blocked.com (count=%lu, bytes=%lu)\n",
               dropped_packets, dropped_bytes);
        m_freem(m);
        *mp = NULL;
        return (-1);
    } else {
        printf("[pf_blockedcom] DEBUG: blocked.com not found in Host header, passing\n");
    }

    printf("[pf_blockedcom] DEBUG: Allowing packet\n");
    return (0);
}

static int
load(module_t mod, int cmd, void *arg)
{
    int error = 0;

    switch (cmd) {
    case MOD_LOAD:
        {
            struct pfil_hook_args pha;
            
            /* Initialize the hook arguments structure */
            bzero(&pha, sizeof(pha));
            pha.pa_version = PFIL_VERSION;
            pha.pa_flags = PFIL_IN | PFIL_OUT;
            pha.pa_type = PFIL_TYPE_IP4;
            pha.pa_func = (pfil_func_t)pf_http_filter;
            
            pfh_inet_hook = pfil_add_hook(&pha);
            if (pfh_inet_hook == NULL) {
                printf("[pf_blockedcom] ERROR: Failed to add hook\n");
                return (ENOMEM);
            }

            printf("[pf_blockedcom] Module loaded successfully\n");
        }
        break;

    case MOD_UNLOAD:
        if (pfh_inet_hook != NULL)
            pfil_remove_hook(pfh_inet_hook);
        
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
