#ifndef __ZL_NETLINK_H__
#define	__ZL_NETLINK_H__
typedef struct zl_sock_addr_s {
        int8_t family;
        int8_t bitlen;
        uint8_t data[sizeof(struct in6_addr)];  // MAX 16 bytes
}zl_sock_addr_t;
int zl_netlink_set_route(int sock, int cmd, int nl_flags, zl_sock_addr_t *dst, zl_sock_addr_t *gw, int def_gw, int if_idx);
//
int zl_netlink_bind(void);      // Netlink
int zl_netlink_free(int sock);
int zl_netlink_process(void *udata, struct sockaddr_nl *nl, struct nlmsghdr *msg);
///
int zl_netlink_get_addr(void *udata);
int zl_netlink_get_link(void *udata);
int zl_netlink_get_route(void *udata);
int netlink_address(int cmd, int ifindex, void *z_address,
        int length, void *z_broadcast, void *udata);
int netlink_route (int cmd, void *dest, int length,
        void *gate, int index, int table, void *udata);
//
int zl_netlink_get_neigh(void *udata);
#endif	//	__ZL_NETLINK_H__
