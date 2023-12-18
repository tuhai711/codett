#include <zl-comm.h>
#include <zl-mem.h>
#include <zl-ioctl.h>
static int
zl_ioctl(u_long req, caddr_t data) {
	int sock;
	int ret;
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if(sock < 0) {
		return -1;
	}
	if((ret = ioctl(sock, req, data)) < 0) {
		close(sock);
		return -1;
	}
	close(sock);
	return 0;
}
int
zl_ioctl_get_index(const char *ifname, uint32_t *ifindex) {
	struct ifreq ifreq;
        int ret;
        strncpy (ifreq.ifr_name, ifname, IFNAMSIZ);
        ifreq.ifr_addr.sa_family = AF_INET;
        ret = zl_ioctl(SIOCGIFINDEX, (caddr_t) &ifreq);
        if(ret < 0) {
                return -1;
        }
        *ifindex = ifreq.ifr_ifindex;
        return 0;
}

int
zl_ioctl_get_hwaddr(const char *ifname, uint8_t *ifmac) {
	struct ifreq ifreq;
	int ret;
	strncpy (ifreq.ifr_name, ifname, IFNAMSIZ);
	ifreq.ifr_addr.sa_family = AF_INET;
	ret = zl_ioctl(SIOCGIFHWADDR, (caddr_t) &ifreq);
	if(ret < 0) {
		return -1;
	}
	memcpy(ifmac, ifreq.ifr_hwaddr.sa_data, ETH_ALEN);
	return 0;
}

int 
zl_prefix_to_mask(struct in_addr *mask, int masklen) {
        if(masklen >= 0 && masklen <= 32) {
                if (sizeof(unsigned long long) > 4)
                        mask->s_addr = htonl(0xffffffffULL << (32 - masklen));
                else
                        mask->s_addr = htonl(masklen ? 0xffffffffU << (32 - masklen) : 0);
        }
        return 0;
}
int
zl_mask_to_prefix(struct in_addr *mask) {
	int tmp = ~ntohl(mask->s_addr);
	if(tmp)
		return __builtin_clz(tmp);
	return 32;
}
int
zl_ioctl_get_addr(const char *ifname, struct sockaddr_in *addr) {
	struct ifreq ifreq;
	int ret;
	strncpy (ifreq.ifr_name, ifname, IFNAMSIZ);
	ifreq.ifr_addr.sa_family = AF_INET;
	ret = zl_ioctl(SIOCGIFADDR, (caddr_t) &ifreq);
	if(ret < 0) {
		return -1;
	}
	memcpy (addr, &ifreq.ifr_addr, sizeof (struct sockaddr_in));
	return 0;
}

int
zl_ioctl_set_addr(const char *ifname, struct sockaddr_in *addr) {
        struct ifreq ifreq;
        int ret;
        strncpy (ifreq.ifr_name, ifname, IFNAMSIZ);
        ifreq.ifr_addr.sa_family = AF_INET;
	memcpy(&ifreq.ifr_addr, addr, sizeof(struct sockaddr));
	ret = zl_ioctl(SIOCSIFADDR, (caddr_t) &ifreq);
	if(ret < 0) {
		return -1;
	}
	return 0;
}
int
zl_ioctl_get_mask(const char *ifname, struct sockaddr_in *mask) {
        struct ifreq ifreq;
        int ret;
        strncpy (ifreq.ifr_name, ifname, IFNAMSIZ);
        ifreq.ifr_addr.sa_family = AF_INET;
        ret = zl_ioctl (SIOCGIFNETMASK, (caddr_t) &ifreq);
        if(ret < 0) {
                return -1;
        }
        memcpy (mask, &ifreq.ifr_addr, sizeof (struct sockaddr_in));
        return 0;
}
int
zl_ioctl_set_mask(const char *ifname, struct sockaddr_in *mask) {
	struct ifreq ifreq;
	int ret;
	strncpy (ifreq.ifr_name, ifname, IFNAMSIZ);
	ifreq.ifr_addr.sa_family = AF_INET;
	memcpy(&ifreq.ifr_addr, mask, sizeof(struct sockaddr));
	ret = zl_ioctl(SIOCGIFNETMASK, (caddr_t) &ifreq);
	if(ret < 0) {
		return -1;
	}
	return 0;
}

// up/down
int
zl_ioctl_get_state(const char *ifname,  int *state) {
        struct ifreq ifreq;
        int ret;
        strncpy (ifreq.ifr_name, ifname, IFNAMSIZ);
        ifreq.ifr_addr.sa_family = AF_INET;
	ret = zl_ioctl(SIOCGIFFLAGS, (caddr_t) &ifreq);
	if(ret < 0) {
		return -1;
	}
	if(ifreq.ifr_flags & IFF_UP ) {
		*state = TRUE;
	} else {
		*state = FALSE;
	}
	return 0;
}

int
zl_ioctl_set_state(const char *ifname, int enable) {
	struct ifreq ifreq;
	int ret;
	strncpy (ifreq.ifr_name, ifname, IFNAMSIZ);
	ifreq.ifr_addr.sa_family = AF_INET;
	ret = zl_ioctl(SIOCGIFFLAGS, (caddr_t) &ifreq);
	if(ret < 0) {
		return -1;
	}
	if(enable) {
        	ifreq.ifr_flags |= ( IFF_UP | IFF_PROMISC | IFF_RUNNING );
	} else {
		ifreq.ifr_flags &= ~(IFF_PROMISC | IFF_RUNNING | IFF_UP);
	}
	ret = zl_ioctl(SIOCSIFFLAGS, (caddr_t) &ifreq);
	if(ret < 0) {
                return -1;
        }
	return 0;
}
// add/delete route
int
zl_route_update_by_mask(int cmd, uint32_t addr, uint32_t mask, uint32_t gw) {
	struct rtentry rt;
	struct sockaddr_in *s = NULL;
	int ret;
	memset( &rt, 0, sizeof( rt ) );
	// gw
	s = (struct sockaddr_in *)&rt.rt_gateway;
	s->sin_family = AF_INET;
	s->sin_addr.s_addr = htonl(gw);
	// addr
	s = (struct sockaddr_in*) &rt.rt_dst;
	s->sin_family = AF_INET;
	s->sin_addr.s_addr = htonl(addr);
	// mask
	s = (struct sockaddr_in*) &rt.rt_genmask;
	s->sin_family = AF_INET;
	s->sin_addr.s_addr = htonl(mask);
	// flags
	rt.rt_flags = RTF_UP | RTF_HOST | RTF_REJECT;
	rt.rt_metric = 0;
	if(cmd) {	// TRUE is add
		ret = zl_ioctl(SIOCADDRT, (caddr_t) &rt);
		if(ret < 0) {
			return -1;
		}
	} else {
		ret = zl_ioctl(SIOCDELRT, (caddr_t) &rt);
		if(ret < 0) {
			return -1;
		}
	}
	return 0;
}
int
zl_route_update_by_prefix(int cmd, uint32_t addr, int prefix_len, uint32_t gw) {
        struct rtentry rt;
        struct sockaddr_in *s = NULL;
        int ret;
        memset( &rt, 0, sizeof( rt ) );
        // gw
        s = (struct sockaddr_in *)&rt.rt_gateway;
        s->sin_family = AF_INET;
        s->sin_addr.s_addr = htonl(gw);
        // addr
        s = (struct sockaddr_in*) &rt.rt_dst;
        s->sin_family = AF_INET;
        s->sin_addr.s_addr = htonl(addr);
        // mask
        s = (struct sockaddr_in*) &rt.rt_genmask;
        s->sin_family = AF_INET;
	zl_prefix_to_mask(&s->sin_addr, prefix_len);
	// flags
        rt.rt_flags = RTF_UP | RTF_HOST | RTF_REJECT;
        rt.rt_metric = 0;
        if(cmd) {       // TRUE is add
                ret = zl_ioctl(SIOCADDRT, (caddr_t) &rt);
                if(ret < 0) {
                        return -1;
                }
        } else {
                ret = zl_ioctl(SIOCDELRT, (caddr_t) &rt);
                if(ret < 0) {
                        return -1;
                }
        }
        return 0;
}
// bridge
int
zl_ioctl_br_add(const char *name) {
	unsigned long arg[4];
	int ret;
	arg[0] = BRCTL_ADD_BRIDGE;
	arg[1] = (unsigned long) name;
	ret = zl_ioctl(SIOCGIFBR, (caddr_t) arg);
	if(ret < 0 && errno != EINVAL && errno != EEXIST) {
		
		fprintf(stderr, "[%s]\n",  strerror(errno));
		return -1;
	}
	return 0;
}
int
zl_ioctl_br_del(const char *name) {
	unsigned long arg[2];
	int ret;
	arg[0] = BRCTL_DEL_BRIDGE;
	arg[1] = (unsigned long) name;
	ret = zl_ioctl(SIOCGIFBR, (caddr_t) arg);
        if(ret < 0 && errno != EINVAL) {
		fprintf(stderr, "[%d][%s]\n", __LINE__,  strerror(errno));
                return -1;
        }
	return 0;
	
}
int
zl_ioctl_br_addif(const char *name, int ifindex) {
	fprintf(stderr, "add [%d] to [%s]\n", ifindex, name);
	struct ifreq ifreq;
	unsigned long args[2];
	int ret;
	args[0] = BRCTL_ADD_IF;
	args[1] = ifindex;
	strncpy (ifreq.ifr_name, name, IFNAMSIZ);
	ifreq.ifr_data = (void *) args;
	ret = zl_ioctl(SIOCDEVPRIVATE, (caddr_t) &ifreq);
        if(ret < 0) {
                fprintf(stderr, "[%s][%d] [%d][SIOCDEVPRIVATE] is failed ->[%s]<-\n", __func__, __LINE__, ifindex,  strerror(errno));
                return -1;
        }
        return 0;
}
int
zl_ioctl_br_delif(const char *name, int ifindex) {
        struct ifreq ifreq;
        unsigned long args[2];
        int ret;
        args[0] = BRCTL_DEL_IF;
        args[1] = ifindex;
	strncpy (ifreq.ifr_name, name, IFNAMSIZ);
        ifreq.ifr_data = (void *) args;
	ret = zl_ioctl(SIOCDEVPRIVATE, (caddr_t) &ifreq);
        if(ret < 0) {
                fprintf(stderr, "[%s][%d] [SIOCDEVPRIVATE] is failed ->[%s]<-\n", __func__, __LINE__,  strerror(errno));
                return -1;
        }
	return 0;
}
#define MAX_BR_PORTS	256
int
zl_ioctl_br_clean(const char *name) {
	unsigned long args[4];
	struct ifreq ifreq;
	int ifindices[MAX_BR_PORTS];
	int ret;
        args[0] = BRCTL_GET_PORT_LIST;
        args[1] = (unsigned long) ifindices;
        args[2] = MAX_BR_PORTS;
        args[3] = 0;
        strncpy (ifreq.ifr_name, name, IFNAMSIZ);
        ifreq.ifr_data = (void *) args;
	ret = zl_ioctl(SIOCDEVPRIVATE, (caddr_t) &ifreq);
	if(ret < 0) {
                fprintf(stderr, "[%s][%d] [SIOCDEVPRIVATE] is failed ->[%s]<-\n", __func__, __LINE__,  strerror(errno));
                return -1;
        }
	int i;
	for(i = 1; i < MAX_BR_PORTS; i++) {
		if(ifindices[i] > 0) {
			zl_ioctl_br_delif(name, ifindices[i]);
		}
	}
	zl_ioctl_br_del(name);
	return 0;
}
