#ifndef __ZL_IOCTL_H__
#define	__ZL_IOCTL_H__
#include <zl-ports.h>
//-----------------------------------
int zl_prefix_to_mask(struct in_addr *mask, int masklen);
int zl_mask_to_prefix(struct in_addr *mask);
//
int zl_ioctl_get_index(const char *ifname, uint32_t *ifindex);
int zl_ioctl_get_hwaddr(const char *ifname, uint8_t *ifmac);
int zl_ioctl_get_addr(const char *ifname, struct sockaddr_in *addr);
int zl_ioctl_set_addr(const char *ifname, struct sockaddr_in *addr);
int zl_ioctl_get_mask(const char *ifname, struct sockaddr_in *mask);
int zl_ioctl_set_mask(const char *ifname, struct sockaddr_in *mask);
int zl_ioctl_get_state(const char *ifname,  int *state);
int zl_ioctl_set_state(const char *ifname, int enable);
//-----------------------------------
int zl_route_update_by_mask(int cmd, uint32_t addr, uint32_t mask, uint32_t gw);
int zl_route_update_by_prefix(int cmd, uint32_t addr, int prefix_len, uint32_t gw);
//-----------------------------------
int zl_ioctl_br_add(const char *name);
int zl_ioctl_br_del(const char *name);
int zl_ioctl_br_clean(const char *name);
int zl_ioctl_br_addif(const char *name, int ifindex);
int zl_ioctl_br_delif(const char *name, int ifindex);
#endif	//	__ZL_IOCTL_H__
