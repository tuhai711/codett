#include <zl-sock.h>
#include <zl-log.h>
#include <zl-ttdp.h>

int 
zl_sock_bind(char *zl_iface) {
	int sock = -1;
	sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(sock < 0) {
		zl_log_warn(" socket [%s] is failed..\n", zl_iface);
		return -1;
	}
	evutil_make_socket_nonblocking(sock);

	struct ifreq ifr;
	strncpy( ifr.ifr_name, zl_iface, sizeof( ifr.ifr_name ) - 1 );
	if( ioctl( sock, SIOCGIFFLAGS, &ifr ) < 0 ) {
		close(sock);
		return -1;
	}
	ifr.ifr_flags |= ( IFF_PROMISC | IFF_UP );
	if( ioctl( sock, SIOCSIFFLAGS, &ifr ) < 0 ) {
		close(sock);
		return -1;
	}
        if( ioctl( sock, SIOCGIFINDEX, &ifr ) < 0 ) {
                close(sock);
                return -1;
        }
	fprintf(stderr, "ifr.ifr_ifindex = [%d]\n", ifr.ifr_ifindex);
	struct sockaddr_ll sa = {
		.sll_family = PF_PACKET,
		.sll_ifindex = ifr.ifr_ifindex,
		.sll_protocol = htons( ETH_P_ALL)
	};
	int one = 1;
	if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) {
		zl_log_warn(" setsockopt is failed..\n");
		close(sock);
		return -1;
	}
	one = 1;
	if(setsockopt(sock, SOL_PACKET, PACKET_AUXDATA, &one, sizeof(one)) < 0) {
		zl_log_warn(" setsockopt is failed..\n");
		close(sock);
		return -1;
	}
	static struct sock_filter ttdp_filter_f[] = { TTDP_FILTER_F };
	struct sock_fprog prog = {
		.filter = ttdp_filter_f,
		.len = sizeof(ttdp_filter_f) / sizeof(struct sock_filter)
	};
	if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER,
			&prog, sizeof(prog)) < 0) {
		zl_log_warn(" setsockopt is failed..\n");
		close(sock);
		return -1;
	}
	zl_log_info(" sock = [%d]\n", sock);
        struct packet_mreq mreq = {
                .mr_ifindex = ifr.ifr_ifindex,
                .mr_type = PACKET_MR_PROMISC,
                .mr_alen = ETH_ALEN,
                .mr_address = { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x00 }
        };
	if (setsockopt(sock, SOL_SOCKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
		zl_log_warn(" setsockopt is failed..\n");
		close(sock);
		return -1;
	}
	mreq.mr_address[ETH_ALEN - 1] = 0x10;
	if (setsockopt(sock, SOL_SOCKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
		zl_log_warn(" setsockopt is failed..\n");
		close(sock);
		return -1;
	}
	mreq.mr_address[ETH_ALEN - 1] = 0x0E;
	if (setsockopt(sock, SOL_SOCKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
		zl_log_warn(" setsockopt is failed..\n");
		close(sock);
		return -1;
	}	
	if(bind(sock, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
                zl_log_warn(" bind [%s] is failed..\n", zl_iface);
                close(sock);
                return -1;
        }
	return sock;
}
int 
zl_sock_free(int sock) {
	if(sock > 0) {
		close(sock);
	}
	return TRUE;
}
