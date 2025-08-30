#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <net/if.h>
#include <net/pfil.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>




// --- Global Variables ---

static const char *blocked_domain ="Host: blocked.com";
static unsigned int total_http_packets_dropped = 0;
static unsigned long total_bytes_dropped = 0;

static pfil_return_t
http_blocker_hook( struct mbuf **m , struct ifnet *ifp , int dir , void *ruleset ,struct inpcb *inp)
{
	 // struct mbuf*m;
	struct ip* ip_header;
	struct tcphdr *tcp_header;
	unsigned int ip_header_len ,tcp_header_len, dest_port ;	
	char *payload ;	

	if (dir != PFIL_IN ){
		return PFIL_PASS;

	}	
	// m = *(pkt.m);

	if(m == NULL || *m == NULL ){
		return PFIL_PASS;
	}
	
	ip_header = mtod(m,struct ip);

	if ( ip_header->ip_p != IPPROTO_TCP ){
		return PFIL_PASS;
	}
	
	ip_header_len = ip_header->ip_hl << 2 ;
	tcp_header = (struct tcphdr*)((char*)ip_header+ ip_header_len);
	
	dest_port = ntohs(tcp_header->th_dport) ;
	
	if( dest_port != 80 ) {
		return PFIL_PASS ;
	}

	tcp_header_len = tcp_header->th_off << 2 ;
	payload = (char*)tcp_header + tcp_header_len ;

	if ( strstr(payload , blocked_domain ) != NULL ){
		total_http_packets_dropped++;
		total_bytes_dropped += ntohs(ip_header->ip_len);
		
		printf("HTTP Blocker : Dropped packet %u for %s ."
			 "Total size dropped: %lu bytes. \n " ,
		total_http_packets_dropped,blocked_domain,total_bytes_dropped);	
		
		return PFIL_DROPPED;
	}
	

	return PFIL_PASS ;
}

static struct pfil_hook *http_hook = NULL;

static int
loader(struct module *m ,int event , void *arg)
{
	struct pfil_hook_args pha ;
	struct pfil_link_args pla ;

	bzero(&pha,sizeof(pha));
	
	pha.pa_version = PFIL_VERSION;
	pha.pa_flags = PFIL_IN;
	pha.pa_type = PFIL_TYPE_IP4;
	pha.pa_ruleset = NULL;
	pha.pa_modname = "http_block_mod";
	pha.pa_rulname = "http_block_rule";
	pha.pa_mbuf_chk = http_blocker_hook ;
	
	switch (event){
		case MOD_LOAD:
			http_hook = pfil_add_hook(&pha);
			
			if( http_hook == NULL){
				printf("Failed to create HTTP block hook \n");
				return EFAULT ;
			}
			bzero(&pla, sizeof(pla));
			
			pla.pa_version = PFIL_VERSION;
			pla.pa_flags = PFIL_IN | PFIL_HOOKPTR;
			pla.pa_headname = "inet";
			pla.pa_hook = http_hook;
					
			if( pfil_link(&pla) != 0){
			   printf("HTTP blocker kernel module loaded. \n");
			   pfil_remove_hook(http_hook);
			   return EFAULT;
			}
			
			printf("HTTP blocker kernel module loaded. \n");
			break;
		case MOD_UNLOAD:
			if (http_hook != NULL){
				pfil_remove_hook(http_hook);
				printf("HTTP blocker kernel module unloaded.\n");
			}
			break;
		default:
			return EOPNOTSUPP;
	}
	
	return 0;
}

static moduledata_t http_block_mod = {
	"http_blocker",
	loader,
	NULL
};	

DECLARE_MODULE(http_blocker , http_block_mod , SI_SUB_DRIVERS , SI_ORDER_MIDDLE );
