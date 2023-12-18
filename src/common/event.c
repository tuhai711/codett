#include <zl-comm.h>
#include <zl-netlink.h>
#include <zl-ttdp.h>
#if 0
static void
zl_ttdp_ev_time_cb(evutil_socket_t fd, short what, void *arg) {
	zl_log_info(" -> Process <- zl_ttdp_ev_time_cb...\n");
	zl_ttdpd_t *ctx = (zl_ttdpd_t *)(arg);
#if 0
	int size = 0;
	char *zframe = zl_ttdpd_hello_encode(ctx, &size);
	event_add(event->write_event, NULL);
#endif
	// TODO: More
	
//	size_t size = 0;
//	uint8_t *buff = zl_ttdpd_hello_tlv_encode(ctx, NULL, &size);
//	uint8_t zl_dst_mac[] = TTDP_HELLO_DEST_MAC_ADDR;
//	zl_port_send_all(ctx->pList, zl_dst_mac, ETH_P_HELLO, buff, size);

  struct list_head *pos, *q;
  list_for_each_safe(pos, q, &ctx->pList->list) {
    zl_port_t *v = list_entry(pos, zl_port_t, list);
	if(v->state == ZL_PORT_UP)
    	if(v->l2_data) {
			///
		size_t size = 0;
		 uint8_t *buff = zl_ttdpd_hello_tlv_encode(ctx, v, NULL, &size);
  		uint8_t zl_dst_mac[] = TTDP_HELLO_DEST_MAC_ADDR;
			//
	      zl_port_send_by_port(v, zl_dst_mac, ETH_P_HELLO, buff, size);
    }
  }	
	struct timeval tv = {1, 0};	// timeout to send
	event_add(ctx->time_event, &tv);
}
#endif
#if 0
static void
zl_ttdp_topology_ev_time_cb(evutil_socket_t fd, short what, void *arg) {
  zl_log_info(" -> Process <-...\n");
  zl_ttdpd_t *ctx = (zl_ttdpd_t *)(arg);
	
#if 0
  int size = 0;
  char *zframe = zl_ttdpd_hello_encode(ctx, &size);
  event_add(event->write_event, NULL);
#endif
  // TODO: More
	if(ctx->InaugInhi != 2)
		return;
  size_t size = 0;
  uint8_t *buff = zl_ttdpd_topology_tlv_encode(ctx, NULL, &size);
  uint8_t zl_dst_mac[] = TTDP_TOPOLOGY_MAC_ADDR;
  zl_port_send_all(ctx->pList, zl_dst_mac, ETH_P_TOPOLOGY, buff, size);
  struct timeval tv = {5, 0}; // timeout to send
  event_add(ctx->time_topo_event, &tv);
}
#endif
static void 
zl_ttdp_ev_link_cb(evutil_socket_t fd, short what, void *arg) {
	zl_log_info(" -> Process <-...\n");
	char t_buf[4096] = {0, };
	struct iovec iov = { t_buf, sizeof t_buf };
	struct sockaddr_nl snl;
	struct msghdr msg = { (void *) &snl, sizeof snl, &iov, 1, NULL, 0, 0 };
	ssize_t status = recvmsg (fd, &msg, 0);
	if(status < 0) {
		if (errno == EWOULDBLOCK || errno == EAGAIN) {
			zl_log_dbg(" Netlink ->[AGAIN] <-\n");
			return;
		}
	} else if(status == 0) {
		zl_log_dbg(" Netlink EOF..\n");
	} else {
		struct nlmsghdr *h = NULL;
		for(h = (struct nlmsghdr *) t_buf; 
				NLMSG_OK (h, (unsigned int) status); 
				h = NLMSG_NEXT (h, status)) {
			if ((h->nlmsg_type == NLMSG_DONE) || (h->nlmsg_type == NLMSG_ERROR)) {
				break;
			}
			zl_netlink_process(arg, &snl, h);
		}
	}
}
static void
zl_ttdp_dump(evutil_socket_t fd, short what, void *arg) {
	struct event_base *base = arg;
	zl_log_info("[event] dumping all events");
	event_base_dump_events(base, stderr);
}
static void
zl_ttdp_stop(evutil_socket_t fd, short what, void *arg) {
	struct event_base *base = arg;
	zl_log_info("[event] Press CTRL + C\n");
	event_base_loopbreak(base);
}
void
zl_ttdpd_event_init(zl_ttdpd_t *ctx) {
	assert(ctx != NULL);
	// Create Event Base
	ctx->g_base = event_base_new();
	assert(ctx->g_base != NULL);
        // netlink socket event
        ctx->nl_sock = zl_netlink_bind();
        ctx->nl_sequence = 0;     //
        ctx->link_event = event_new(ctx->g_base, ctx->nl_sock,  EV_READ|EV_PERSIST, zl_ttdp_ev_link_cb, ctx);
        event_add(ctx->link_event, NULL); // Active Netlink Event

#if 0
	//topology
	ctx->time_topo_event = event_new(ctx->g_base, -1, 0, zl_ttdp_topology_ev_time_cb, ctx);
  	event_active(ctx->time_topo_event, EV_TIMEOUT, 2);
#endif
	// Signals
	zl_log_info("[event] register signals..\n");
	evsignal_add(evsignal_new(ctx->g_base, SIGUSR1, 
				zl_ttdp_dump, ctx->g_base), NULL);
	evsignal_add(evsignal_new(ctx->g_base, SIGINT,
				zl_ttdp_stop, ctx->g_base), NULL);
	evsignal_add(evsignal_new(ctx->g_base, SIGTERM,
				zl_ttdp_stop, ctx->g_base), NULL);
}
void 
zl_ttdpd_event_free(zl_ttdpd_t *ctx) {
	// netlink
	if(ctx->link_event) {
		event_free(ctx->link_event);
		zl_netlink_free(ctx->nl_sock);	// close socket
	}
	if(ctx->time_topo_event) {
	    event_free(ctx->time_topo_event);
  }
}
void
zl_ttdpd_event_loop(zl_ttdpd_t *ctx) {
	do {
		if(event_base_got_break(ctx->g_base) || 
				event_base_got_exit(ctx->g_base)) {
			break;
		}
	} while(event_base_loop(ctx->g_base, EVLOOP_ONCE) == 0);
}
