#include <zl-comm.h>
#include <zl-ttdp.h>
#include <zl-mem.h>
#include <zl-netlink.h>
int 
zl_netlink_bind(void) {
	int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if(fd < 0) {	// can't create socket netlink
		zl_log_dbg(" can't create netlink.\n");
		return -1;
	}
	struct sockaddr_nl addr;
	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_pid = getpid ();
	addr.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE | RTMGRP_NOTIFY | RTMGRP_NEIGH;
	if(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) <0) {
		zl_log_dbg(" can't bind netlink.\n");
		zl_netlink_free(fd);
		return -1;
	}
	zl_log_info(" netlink sock = [%d]\n", fd);
	return fd;
}
int
zl_netlink_free(int sock) {
	if(sock) {
		close(sock);
	}
	return 0;
}
int
zl_netlink_neighbor_callback(void *udata, struct sockaddr_nl *nl, struct nlmsghdr *msg) {
	zl_ttdpd_t *ctx = (zl_ttdpd_t *)(udata);
	struct ndmsg *nd_msg = (struct ndmsg *) NLMSG_DATA(msg);
	struct rtattr * attr = (struct rtattr *) NDA_RTA(nd_msg);
	int rtattr_len = NDA_PAYLOAD(msg);
	zl_port_t *v;
	for(; RTA_OK(attr, rtattr_len); attr = RTA_NEXT(attr, rtattr_len)) {
		if(attr->rta_type == NDA_LLADDR) {
			uint8_t mac[ETH_ALEN] = {0, };
			zl_memcpy(mac, RTA_DATA(attr), ETH_ALEN);
			if(msg->nlmsg_type == RTM_NEWNEIGH) {	// add FDB entry
				if((zl_port_find_by_hwaddr(ctx->pList, mac) == NULL) && ((v = zl_port_find_by_index(ctx->pList, nd_msg->ndm_ifindex)) != NULL)) {	// local
					zl_log_info(" ->[ADD]<- [" ZL_MACSTR "] ifindex = [%d]\n", ZL_MACVAL(mac), nd_msg->ndm_ifindex);
					zl_fdb_list_add(ctx->fList, mac, nd_msg->ndm_ifindex);
					//set link_up
					v->linkStatus = ZL_PORT_UP;
				}
			} else if (msg->nlmsg_type == RTM_DELNEIGH) {	// del FDB entry
				if((zl_port_find_by_hwaddr(ctx->pList, mac) == NULL) && (zl_port_find_by_index(ctx->pList, nd_msg->ndm_ifindex) != NULL)) {	// local
					zl_log_info(" ->[DEL]<- [" ZL_MACSTR "] ifindex = [%d]\n", ZL_MACVAL(mac), nd_msg->ndm_ifindex);
					zl_fdb_list_del(ctx->fList, mac, nd_msg->ndm_ifindex);
				}
			}
		//	} else if (attr->rta_type == NDA_XXX) {	// TODO: More
		}
	}
	return 0;
}
typedef struct zl_v4_route_s {
    uint32_t src_if_index;
    uint32_t src_ip;
    uint8_t  src_mask_len;   /* 16 not 255.255.0.0 */
    uint32_t dst_if_index;
    uint32_t dst_ip;
    uint8_t  dst_mask_len;   /* 16 not 255.255.0.0 */
    uint32_t gateway;    /* gateway == 0 if no gateway/we are last hop */
} zl_v4_route_t;
int
zl_netlink_route_callback(void *udata, struct sockaddr_nl *nl, struct nlmsghdr *msg) {
	struct rtmsg *ifr = (struct rtmsg *) NLMSG_DATA(msg);
	int rtattr_len = RTM_PAYLOAD(msg);
	struct rtattr * attr = (struct rtattr *) RTM_RTA(ifr);
	if (ifr->rtm_family == AF_INET6) {
		return 0;
	}
	zl_v4_route_t entry = {0, };
	entry.dst_mask_len = ifr->rtm_dst_len;
	entry.src_mask_len = ifr->rtm_src_len;

	for(; RTA_OK(attr, rtattr_len); attr = RTA_NEXT(attr, rtattr_len)) {
		switch (attr->rta_type)
		{
			case RTA_DST:
				memcpy(&entry.dst_ip, RTA_DATA(attr), sizeof(uint32_t));
			break;
			case RTA_SRC:
				memcpy(&entry.src_ip, RTA_DATA(attr), sizeof(uint32_t));
			break;
			case RTA_IIF:
				memcpy(&entry.src_if_index, RTA_DATA(attr), sizeof(uint32_t));
			break;
			case RTA_OIF:
				memcpy(&entry.dst_if_index, RTA_DATA(attr), sizeof(uint32_t));
			break;
			case RTA_GATEWAY:
				memcpy(&entry.gateway, RTA_DATA(attr), sizeof(uint32_t));
			break;
			default:
				break;
		}
	}
	return 0;
}
int
zl_netlink_link_callback(void *udata, struct sockaddr_nl *nl, struct nlmsghdr *msg) {
	struct ifinfomsg *ifi = NLMSG_DATA(msg); /* for RTM_{NEW,DEL}ADDR */
	struct rtattr * attr = (struct rtattr *) IFLA_RTA(ifi);
        int rtattr_len = IFLA_PAYLOAD(msg);
	for(; RTA_OK(attr, rtattr_len); attr = RTA_NEXT(attr, rtattr_len)) {
		if(attr->rta_type == IFLA_IFNAME) {
			zl_log_info(" New Link [%d] -> [%s]..\n", ifi->ifi_index, (char *)RTA_DATA(attr));
		// } else if(attr->rta_type == IFLA_XXX) { 	// TODO: More
		}
	}
	return 0;
}
int
zl_netlink_addr_callback(void *udata, struct sockaddr_nl *nl, struct nlmsghdr *msg) {
	struct ifaddrmsg *ifa = NLMSG_DATA(msg); /* for RTM_{NEW,DEL}LINK */
	struct rtattr *attr = (struct rtattr *) IFA_RTA(ifa);
	int rtattr_len = IFA_PAYLOAD(msg);
	for(; RTA_OK(attr, rtattr_len); attr = RTA_NEXT(attr, rtattr_len)) {
		if(attr->rta_type == IFA_ADDRESS) {
			// TODO: 
			uint32_t addr = 0;
			memcpy(&addr,  RTA_DATA(attr), sizeof(addr));
			if(msg->nlmsg_type == RTM_NEWADDR) {
				zl_log_info(" New Address [0x%x] in [%d]\n", addr, ifa->ifa_index);
			} else if(msg->nlmsg_type == RTM_DELADDR) {
				zl_log_info(" Del Address [0x%x] in [%d]\n", addr, ifa->ifa_index);
			}
		} else if(attr->rta_type == IFA_LABEL) {
			// TODO: 
		} else if(attr->rta_type == IFA_LOCAL) {
			// TODO: 
		} else if(attr->rta_type == IFA_BROADCAST) {
			// TODO: 
		}
	}
	return 0;
}
int
zl_netlink_process(void *udata, struct sockaddr_nl *nl, struct nlmsghdr *msg) {
	//zl_ttdpd_t *ctx = (zl_ttdpd_t *)(udata);
	switch (msg->nlmsg_type) {
		case RTM_NEWADDR:
		case RTM_DELADDR:
			zl_netlink_addr_callback(udata, nl, msg);
			break;
		case RTM_NEWLINK:
		case RTM_DELLINK:
			zl_log_info(" [%d]\n", msg->nlmsg_type);
			zl_netlink_link_callback(udata, nl, msg);
			break;
		case RTM_NEWNEIGH:
		case RTM_DELNEIGH:
			zl_netlink_neighbor_callback(udata, nl, msg);
			break;
		case RTM_NEWROUTE:
		case RTM_DELROUTE:
			zl_netlink_route_callback(udata, nl, msg);
			break;
		default:
			zl_log_info(" netlink [0x%x] is not supported now...\n", msg->nlmsg_type);
			break;
	}
	return 0;
}
// Function netlink
static int
addattr_l (struct nlmsghdr *n, size_t maxlen, int type, void *data, size_t alen)
{
	size_t len;
	struct rtattr *rta;

	len = RTA_LENGTH (alen);

	if (NLMSG_ALIGN (n->nlmsg_len) + len > maxlen)
		return -1;

	rta = (struct rtattr *) (((char *) n) + NLMSG_ALIGN (n->nlmsg_len));
	rta->rta_type = type;
	rta->rta_len = len;
	memcpy (RTA_DATA (rta), data, alen);
	n->nlmsg_len = NLMSG_ALIGN (n->nlmsg_len) + len;

	return 0;
}
static int
netlink_talk (struct nlmsghdr *n, void *udata)
{
	zl_ttdpd_t *ctx = (zl_ttdpd_t *)(udata);        // ctx
	int status;
	struct sockaddr_nl snl;
	struct iovec iov = { (void *) n, n->nlmsg_len };
	struct msghdr msg = { (void *) &snl, sizeof snl, &iov, 1, NULL, 0, 0 };

	memset (&snl, 0, sizeof snl);
	snl.nl_family = AF_NETLINK;

	n->nlmsg_seq = ++ctx->nl_sequence;
	/* Request an acknowledgement by setting NLM_F_ACK */
	n->nlmsg_flags |= NLM_F_ACK;

	/* Send message to netlink interface. */
	status = sendmsg (ctx->nl_sock, &msg, 0);

	if (status < 0)
	{
		return -1;
	}
	return 0;
}
// 
static int
netlink_request (int family, int type, void *udata)	{
	zl_ttdpd_t *ctx = (zl_ttdpd_t *)(udata);	// ctx
	int ret;
	struct sockaddr_nl snl;
	struct
	{
		struct nlmsghdr nlh;
		struct rtgenmsg g;
	} req;


	/* Check netlink socket. */
	if (ctx->nl_sock < 0)
	{
		return -1;
	}

	memset (&snl, 0, sizeof snl);
	snl.nl_family = AF_NETLINK;

	memset (&req, 0, sizeof req);
	req.nlh.nlmsg_len = sizeof req;
	req.nlh.nlmsg_type = type;
	req.nlh.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
	req.nlh.nlmsg_pid = getpid();
	req.nlh.nlmsg_seq = ++ctx->nl_sequence;
	req.g.rtgen_family = family;

	ret = sendto (ctx->nl_sock, (void *) &req, sizeof req, 0,
			(struct sockaddr *) &snl, sizeof snl);
	if (ret < 0)
	{
		return -1;
	}

	return 0;
}
int
zl_netlink_get_link(void *udata) {
	return netlink_request(AF_PACKET, RTM_GETLINK, udata);
}
int 
zl_netlink_get_route(void *udata) {
	return netlink_request(AF_INET, RTM_GETROUTE, udata);
}
int
zl_netlink_get_addr(void *udata) {
	return netlink_request(AF_INET, RTM_GETADDR, udata);
}
int
zl_netlink_get_neigh(void *udata) {
	zl_ttdpd_t *ctx = (zl_ttdpd_t *)(udata);        // ctx
	struct sockaddr_nl snl;
	int ret;
	struct {
		struct nlmsghdr nlh;
		struct ndmsg rtm;
	} req;
	/* Check netlink socket. */
        if (ctx->nl_sock < 0)
        {
                return -1;
        }
	memset (&snl, 0, sizeof snl);
        snl.nl_family = AF_NETLINK;

	memset (&req, 0, sizeof req);
	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT | NLM_F_DUMP;
	req.rtm.ndm_state = NUD_REACHABLE;
	req.nlh.nlmsg_type = RTM_GETNEIGH;
	req.rtm.ndm_family = AF_INET; 	
	ret = sendto (ctx->nl_sock, (void *) &req, sizeof req, 0,
                        (struct sockaddr *) &snl, sizeof snl);
        if (ret < 0)
        {
                return -1;
        }
	return 0;
}
//---------------------------------
/*
 *	cmd: RTM_NEWADDR | RTM_DELADDR
 *
 *
 *
 */
int
netlink_address(int cmd, int ifindex, void *z_address, int length, void *z_broadcast, void *udata) 
{
	struct
	{
		struct nlmsghdr n;
		struct ifaddrmsg ifa;
		char buf[1024];
	} req;
	int ret;
	memset (&req, 0, sizeof req);
	req.n.nlmsg_len = NLMSG_LENGTH (sizeof (struct ifaddrmsg));
	req.n.nlmsg_flags = NLM_F_CREATE | NLM_F_EXCL | NLM_F_REQUEST;
	req.n.nlmsg_type = cmd;
	req.ifa.ifa_family    = AF_INET;
	req.ifa.ifa_prefixlen = length;	// 32
	req.ifa.ifa_scope     = RT_SCOPE_UNIVERSE;
	req.ifa.ifa_index = ifindex;
	addattr_l (&req.n, sizeof req, IFA_LOCAL, z_address, 4);
	if(z_broadcast) {
		addattr_l (&req.n, sizeof req, IFA_BROADCAST, z_broadcast, 4);
	}
        /* Talk to netlink socket. */
        ret = netlink_talk (&req.n, udata);
        if (ret < 0)
                return -1;

        return 0;
}
/******
 * cmd:
 *              RTM_DELROUTE | RTM_NEWROUTE
 *
 * nl_flags:
 *              0 | (NLM_F_CREATE | NLM_F_EXCL)
 * def_gw:
 *              TRUE: default gw
 * if_idx:
 *              ifindex of interface
 */
int
netlink_route (int cmd, void *dest, int length, void *gate,
               int index, int table, void *udata)
{
	int ret;
	struct sockaddr_nl snl;
	struct
	{
		struct nlmsghdr n;
		struct rtmsg r;
		char buf[1024];
	} req;

	memset (&req, 0, sizeof req);

	req.n.nlmsg_len = NLMSG_LENGTH (sizeof (struct rtmsg));
	req.n.nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST;
	req.n.nlmsg_type = cmd;
	req.r.rtm_family = AF_INET;
	req.r.rtm_table = table;
	req.r.rtm_dst_len = length;
	req.r.rtm_protocol = RTPROT_STATIC;
	req.r.rtm_scope = RT_SCOPE_UNIVERSE;

	if (cmd == RTM_NEWROUTE)
	{
		req.r.rtm_type = RTN_UNICAST;
	}

	if (dest)
		addattr_l (&req.n, sizeof req, RTA_DST, dest, 4);

	if (gate)
		addattr_l (&req.n, sizeof req, RTA_GATEWAY, gate, 4);
	if (index > 0)
		addattr_l (&req.n, sizeof req, RTA_OIF, &index, sizeof(index));

	/* Destination netlink address. */
	memset (&snl, 0, sizeof snl);
	snl.nl_family = AF_NETLINK;

	/* Talk to netlink socket. */
	ret = netlink_talk (&req.n, udata);
	if (ret < 0)
		return -1;

	return 0;
}
