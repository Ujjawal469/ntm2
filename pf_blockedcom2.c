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

/* Hook function with correct signature and return values */
static int
pf_http_filter(void *arg, struct mbuf **mp, struct ifnet *ifp, int dir, void *inp)
{
    struct mbuf *m = *mp;
    struct ip *ip_hdr;
    struct tcphdr *tcp_hdr;
    char buf[128];
    int ip_hlen, tcp_hlen, payload_len;
    int tocopy;

    if (m == NULL) 
        return (0);  /* 0 means pass the packet */

    /* Check if it's an IP packet */
    if (m->m_pkthdr.len < sizeof(struct ip))
        return (0);  /* Pass */

    /* Get IP header */
    if (m->m_len < sizeof(struct ip) && (m = m_pullup(m, sizeof(struct ip))) == NULL)
        return (0);  /* Pass */
    
    ip_hdr = mtod(m, struct ip *);
    
    /* Check if it's TCP */
    if (ip_hdr->ip_p != IPPROTO_TCP) 
        return (0);  /* Pass */

    ip_hlen = ip_hdr->ip_hl << 2;
    
    /* Ensure we have enough data for TCP header */
    if (m->m_len < ip_hlen + sizeof(struct tcphdr)) {
        m = m_pullup(m, ip_hlen + sizeof(struct tcphdr));
        if (m == NULL)
            return (0);  /* Pass */
        *mp = m;
        ip_hdr = mtod(m, struct ip *);
    }

    tcp_hdr = (struct tcphdr *)((caddr_t)ip_hdr + ip_hlen);
    
    /* Check if it's HTTP (port 80) */
    if (ntohs(tcp_hdr->th_dport) != 80)
        return (0);  /* Pass */

    tcp_hlen = tcp_hdr->th_off << 2;
    payload_len = ntohs(ip_hdr->ip_len) - (ip_hlen + tcp_hlen);
    
    if (payload_len <= 0)
        return (0);  /* Pass */

    /* Copy payload for inspection */
    tocopy = min(sizeof(buf) - 1, payload_len);
    m_copydata(m, ip_hlen + tcp_hlen, tocopy, buf);
    buf[tocopy] = '\0';

    /* Check for blocked.com in Host header */
    if (strstr(buf, "Host: blocked.com") != NULL ||
        strstr(buf, "host: blocked.com") != NULL) {
        dropped_packets++;
        dropped_bytes += m->m_pkthdr.len;
        printf("[pf_blockedcom] Dropped HTTP packet to blocked.com (count=%lu, bytes=%lu)\n",
               dropped_packets, dropped_bytes);
        m_freem(m);
        *mp = NULL;
        return (-1);  /* -1 means drop the packet */
    }

    return (0);  /* Pass */
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
                printf("[pf_blockedcom] Failed to add hook\n");
                return (ENOMEM);
            }

            printf("[pf_blockedcom] Module loaded\n");
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

