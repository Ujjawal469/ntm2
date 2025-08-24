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

static unsigned long dropped_packets = 0;
static unsigned long dropped_bytes = 0;

static struct pfil_head *pfh_inet;
static pfil_hook_t *pfh_inet_hook;

/* Hook function */
static int
pf_http_filter(void *arg, struct mbuf **mp, struct ifnet *ifp, int dir, struct inpcb *inp)
{
    struct mbuf *m = *mp;
    struct ip *ip_hdr;
    struct tcphdr *tcp_hdr;
    char *payload;
    int ip_hlen, tcp_hlen, payload_len;

    if (m == NULL) return 0;

    ip_hdr = mtod(m, struct ip *);
    if (ip_hdr->ip_p != IPPROTO_TCP) return 0;

    ip_hlen = ip_hdr->ip_hl << 2;
    tcp_hdr = (struct tcphdr *)((caddr_t)ip_hdr + ip_hlen);
    tcp_hlen = tcp_hdr->th_off << 2;

    if (ntohs(tcp_hdr->th_dport) != 80) return 0;

    payload_len = ntohs(ip_hdr->ip_len) - (ip_hlen + tcp_hlen);
    if (payload_len <= 0) return 0;

    payload = (char *)tcp_hdr + tcp_hlen;

    if (payload && (payload_len > 0) &&
        (strnstr(payload, "Host: blocked.com", payload_len) != NULL)) {
        dropped_packets++;
        dropped_bytes += payload_len;
        printf("[pf_blockedcom] Dropped HTTP packet (count=%lu, bytes=%lu)\n",
               dropped_packets, dropped_bytes);
        m_freem(m);
        *mp = NULL;
        return EPERM;
    }

    return 0;
}

static int
load(module_t mod, int cmd, void *arg)
{
    int error = 0;

    switch (cmd) {
    case MOD_LOAD:
        pfh_inet = pfil_head_get(PFIL_TYPE_AF, AF_INET);
        if (pfh_inet == NULL)
            return ENOENT;

        struct pfil_hook_args pha = {
            .pha_type = PFIL_TYPE_AF,
            .pha_func = pf_http_filter,
            .pha_arg  = NULL,
            .pha_flags = PFIL_IN,
            .pha_head = pfh_inet,
            .pha_name = "pf_blockedcom"
        };

        pfh_inet_hook = pfil_add_hook(&pha);
        if (pfh_inet_hook == NULL)
            return ENOMEM;

        printf("[pf_blockedcom] Module loaded\n");
        break;

    case MOD_UNLOAD:
        if (pfh_inet_hook)
            pfil_remove_hook(pfh_inet_hook);
        printf("[pf_blockedcom] Module unloaded\n");
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
