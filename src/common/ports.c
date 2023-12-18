#include <zl-comm.h>
#include <zl-mem.h>
#include <zl-ttdp.h>
#include <zl-ports.h>
#include <zl-ioctl.h>
extern zl_ttdpd_t *ctx;	// global variable

zl_ttdpd_t*
zl_zl_ttdpd_get(void)
{
	return ctx;
}

zl_etb_vector_entry_t *
zl_etb_vector_list_init(void) {
        zl_etb_vector_entry_t *pVec = (zl_etb_vector_entry_t *)malloc(sizeof(zl_etb_vector_entry_t));
        assert(pVec != NULL);
        INIT_LIST_HEAD(&pVec->list);
        return pVec;
}

zl_etb_vector_entry_t *
zl_etb_vector_list_find(zl_etb_vector_entry_t *plist, uint8_t *mac) {
        assert(plist != NULL);
        struct list_head *pos, *q;
        list_for_each_safe(pos, q, &plist->list) {
                zl_etb_vector_entry_t *v = list_entry(pos, zl_etb_vector_entry_t, list);
                if(!memcmp(v->mac, mac, ETH_ALEN)) {
                        return v;
                }
        }
        return NULL;
}

uint8_t
zl_etb_vector_list_num(zl_etb_vector_entry_t *plist) {
        assert(plist != NULL);
	uint8_t numvec = 0;
        struct list_head *pos, *q;
        list_for_each_safe(pos, q, &plist->list) {
		numvec++;
        }
        return numvec;
}

void
zl_etb_vector_list_add(zl_etb_vector_entry_t *plist, uint8_t *mac) {
        assert(plist != NULL);
        zl_etb_vector_entry_t *v = (zl_etb_vector_entry_t *)malloc(sizeof(zl_etb_vector_entry_t));
        memcpy(v->mac, mac, ETH_ALEN);
        list_add(&(v->list), &(plist->list));
}


void
zl_etb_vector_list_clean(zl_etb_vector_entry_t *plist) {
        assert(plist != NULL);
        struct list_head *pos, *q;
        list_for_each_safe(pos, q, &plist->list) {
                zl_etb_vector_entry_t *v = list_entry(pos, zl_etb_vector_entry_t, list);
                list_del(pos);
                free(v);
        }
}
void
zl_etb_vector_list_free(zl_etb_vector_entry_t *plist) {
        assert(plist != NULL);
        zl_etb_vector_list_clean(plist);
        free(plist);
}

#if 0
uint8_t
zl_etb_vector_list_get_all(zl_etb_vector_entry_t *plist, zl_mac_address_t *dir_etbns, uint8_t *num) {
        assert(plist != NULL);
	uint8_t numvec = *num;
	struct list_head *pos, *q;
        list_for_each_safe(pos, q, &plist->list) {
		zl_etb_vector_entry_t *v = list_entry(pos, zl_etb_vector_entry_t, list);
		memcpy(dir_etbns[numvec].address, v->mac, ETH_ALEN);
                numvec++;
        }
	*num = numvec;
        return numvec;	
}
#endif
void
zl_etb_vector_list_del(zl_etb_vector_entry_t *plist, uint8_t *mac) {
        assert(plist != NULL);
        struct list_head *pos, *q;
        list_for_each_safe(pos, q, &plist->list) {
                zl_etb_vector_entry_t *v = list_entry(pos, zl_etb_vector_entry_t, list);
                if(memcmp(v->mac, mac, ETH_ALEN) == 0) {
			printf("--------zl_etb_vector_list_del--(%d)---- ->[DEL]<- [" ZL_MACSTR "] \n", __LINE__, ZL_MACVAL(mac));
                        list_del(pos);
                        free(v);
                        break;
                }
        }
}


static void
zl_ttdp_ev_hello_time_cb(evutil_socket_t fd, short what, void *uData) {
	zl_port_t *v = (zl_port_t *)(uData);    //port info
	struct timeval tv = {0,  v->timeHello*1000};

	if(ctx->flagHello == 0)
	{	printf("flagHello == 0 hai test file: %s func: %s (%d)\n", __FILE__, __func__, __LINE__);
	        event_add(v->time_event_hello, &tv);
		return;
	}
	if(v->linkStatus == ZL_PORT_DOWN || v->state == ZL_PORT_DOWN)
        {
//              event_add(v->time_event_hello, &tv);
                v->lineStatus.recs_astatus = 1;
        }

        if(v->l2_data) {
              size_t size = 0;
              uint8_t *buff = zl_ttdpd_hello_tlv_encode(ctx, v, NULL, &size);
              uint8_t zl_dst_mac[] = TTDP_HELLO_DEST_MAC_ADDR;
//printf(" HELLO send zl_port_t ifname=%s v->InaugInhi=%d\n", v->ifname, v->timeOutHello);
              zl_port_send_by_port(v, zl_dst_mac, ETH_P_HELLO, buff, size);
    	}
        event_add(v->time_event_hello, &tv);
/*
gettimeofday(&tvest,NULL);
printf("hai test (%d) tvest.tv_sec = %ld tv_usec = %ld \n",  __LINE__, tvest.tv_usec, tvest.tv_usec/1000);
*/
#if 0
	struct timeval tvest;
	gettimeofday(&tvest,NULL);
	time_t msec = time(NULL) * 1000;
	long long  millis = (tvest.tv_sec) * 1000LL + (tvest.tv_usec) / 1e6;
	printf("hai test (%d) tvest.tv_sec = %ld tv_usec = %ld millis=%ld\n",  __LINE__, tvest.tv_sec, tvest.tv_usec/1000, msec);
#endif
}

static void
zl_ttdp_ev_hello_timeout_cb(evutil_socket_t fd, short what, void *uData) {
        zl_port_t *v = (zl_port_t *)(uData);
	struct timeval tvo = {0, v->timeOutHello*1000};     // timeout to send
	struct timeval now = {0 };
	gettimeofday(&now, NULL);
#if 0
	unsigned long long curr_value = now.tv_sec * 1000000 + now.tv_usec;
	unsigned long long last_value =  v->curr_time.tv_sec * 1000000 +  v->curr_time.tv_usec;
	if ((curr_value - last_value) > 130000) {
		printf("Thanh Debug [%s][%d] TIMEOUT [%lld]\n", __func__, __LINE__, curr_value - last_value);
	} else {
		printf("Thanh Debug [%s][%d] --> %lld process Here\n", __func__, __LINE__, curr_value - last_value);
	}
#else
	if(v->flag_timeout)
	{
#if 0
		struct timeval tvnow, tvcmp;
		gettimeofday(&tvnow, NULL);
		zl_timersub(&tvnow, &v->curr_time, &tvcmp);

        printf("FIle: %s func:%s (%d) hai test tvcmp.tv_sec = %ld tvcmp = %ld \n", __FILE__, __func__, __LINE__, tvcmp.tv_sec, tvcmp.tv_usec);
		struct timeval tvo1 = {0, 130000};
#endif
#if 1		
		if(v->timeOutHello == ZL_HELLO_TIMEOUT_FAST)
		{
			printf("TimeOut: " ZL_MACSTR ") \n",  ZL_MACVAL(v->remoteMac));
			struct timeval tvest;
		        gettimeofday(&tvest,NULL);
			v->linkStatus = ZL_PORT_DOWN;
			v->lineStatus.recs_astatus = 0;
			v->timeOutHello = ZL_HELLO_TIMEOUT_SLOW;
			v->timeHello = ZL_HELLO_TIME_SLOW;
			v->InaugInhi = 1;
			v->flag_timeout = 0;
			return;
		}
		v->timeOutHello = ZL_HELLO_TIMEOUT_FAST;
		v->timeHello = ZL_HELLO_TIME_FAST;
		zl_ttdp_ev_hello_time_cb(-1, 0, uData);

		tvo.tv_sec = 0;
		tvo.tv_usec = ZL_HELLO_TIMEOUT_FAST *1000;
                event_add(v->time_event_hello_timeout, &tvo);
#endif
	}
#endif
//	event_add(v->time_event_hello_timeout, &tvo);
}

static void
zl_ttdp_ev_topology_time_cb(evutil_socket_t fd, short what, void *uData) {
//  zl_log_info(" -> Process <-...\n");

	zl_port_t *v = (zl_port_t *)(uData);
	struct timeval tv = {0, v->timeTopo*1000}; // timeout to send
#if 1
	if(v->InaugInhi != 2)
	{
        	event_add(v->time_event_topo, &tv);
//		printf("Not HELLO zl_port_t ifname=%s\n", v->ifname);
         	return;
	}
#endif
	size_t size = 0;
	uint8_t *buff = zl_ttdpd_topology_tlv_encode(ctx, v, NULL, &size);
	uint8_t zl_dst_mac[] = TTDP_TOPOLOGY_MAC_ADDR;
	zl_port_send_all(ctx->pList, zl_dst_mac, ETH_P_TOPOLOGY, buff, size);
	event_add(v->time_event_topo, &tv);
}

static void
zl_port_process(void *uData, const uint8_t *src_addr, zl_ttdpd_protocol_t type, const uint8_t *buff, size_t len) {
	// TODO: More
	if(type == ZL_TTDP_PROTO_HELLO) {
		// TODO: More
		zl_port_t *v = (zl_port_t *)(uData);    //port info
		v->lineStatus.recs_astatus = 2; //check time
		v->linkStatus = ZL_PORT_UP;
		zl_ttdpd_hello_decode(ctx, uData, src_addr, (uint8_t*)buff, len);
	} else if(type == ZL_TTDP_PROTO_TOPOLOGY) {
		// TODO: More
		zl_ttdpd_topology_decode(ctx, uData, src_addr, (uint8_t*)buff, len);
	}

#if 0
	zl_port_t *v = (zl_port_t *)(uData);	//port info
	fprintf(stderr, "\n");
	uint8_t zl_dst_mac[] = TTDP_HELLO_DEST_MAC_ADDR;
	zl_port_send_by_port(v, zl_dst_mac, ETH_P_HELLO, buff, len);
#endif
}
void
zl_send_hello_fast(void *uData)
{
	zl_ttdp_ev_hello_time_cb(-1, 0, uData);
}

void 
zl_port_send_by_port(zl_port_t *v, const uint8_t *dst_addr, uint16_t proto, const uint8_t *buff, size_t len) {
	zl_l2_packet_send(v->l2_data, dst_addr, proto, buff, len);
}
void 
zl_port_send_all(zl_port_t *plist, const uint8_t *dst_addr, uint16_t proto, const uint8_t *buff, size_t len) {
	assert(plist != NULL);
	struct list_head *pos, *q;
	list_for_each_safe(pos, q, &plist->list) {
		zl_port_t *v = list_entry(pos, zl_port_t, list);
		if(v->l2_data) {
			zl_port_send_by_port(v, dst_addr, proto, buff, len);
		}
	}
}
zl_port_t *
zl_port_init(void) {
	zl_port_t *plist = (zl_port_t *)zl_calloc(1, sizeof(zl_port_t));
	assert(plist != NULL);
	INIT_LIST_HEAD(&plist->list);
	return plist;
}
void 
zl_port_free(zl_port_t *plist) {
	assert(plist != NULL);
	zl_port_clean(plist);
	zl_free(plist);
}

zl_port_t* 
zl_port_add(zl_port_t *plist, const char *ifname, zl_port_direct_t direction, zl_port_type_t type) {
	assert(plist != NULL);
	zl_port_t *v = (zl_port_t *)zl_calloc(1, sizeof(zl_port_t));
	snprintf(v->ifname, IFNAMSIZ, "%s", ifname);
	// GET Index
	zl_ioctl_get_index(v->ifname, &v->ifindex);
	// GET HW address
	zl_ioctl_get_hwaddr(v->ifname, v->ifhwaddr);
	// 
	v->direction = direction;
	//line
	v->lineStatus.recs_astatus = 3;
        v->lineStatus.recs_bstatus = 3;
        v->lineStatus.recs_bstatus = 3;
        v->lineStatus.recs_dstatus = 3;
	
	//
	v->type =  type;
	//
	v->state = (zl_ioctl_set_state(v->ifname, TRUE) == 0) ? ZL_PORT_UP:ZL_PORT_DOWN;

	if((v->direction == ZL_PORT_DIR_RIGHT) || (v->direction == ZL_PORT_DIR_LEFT)) {	// discovery port
		v->l2_data = zl_l2_data_init(v->ifname, v->ifhwaddr, zl_port_process, v);
		v->vList = zl_etb_vector_list_init();
		////add time evetn
		v->linkStatus = ZL_PORT_DOWN;
		v->curr_time.tv_sec = 0;
		v->curr_time.tv_usec = 0;
		v->timeHello = ZL_HELLO_TIME_SLOW; //test
		v->timeOutHello = ZL_HELLO_TIMEOUT_SLOW;
		v->flag_timeout = 0;
		v->helloLife = 0;
		v->topoLife = 0;
		v->InaugInhi = 1;
		v->timeTopo = 100;
		memset(v->remoteMac, 0, ETH_ALEN);

#if 1
		v->time_event_hello = event_new(ctx->g_base, -1, 0, zl_ttdp_ev_hello_time_cb, v);
	        event_active(v->time_event_hello, EV_TIMEOUT, 1);
		//time out
		v->time_event_hello_timeout = event_new(ctx->g_base, -1, 0, zl_ttdp_ev_hello_timeout_cb, v);
                event_active(v->time_event_hello_timeout, EV_TIMEOUT, 1);
#endif
#if 1
		//topo
		v->time_event_topo = event_new(ctx->g_base, -1, 0, zl_ttdp_ev_topology_time_cb, v);
               event_active(v->time_event_topo, EV_TIMEOUT, 1);
#endif
#if 0
                //time out
                v->time_event_topo_timeout = event_new(ctx->g_base, -1, 0, zl_ttdp_ev_topology_timeout_cb, v);
                event_active(v->time_event_topo_timeout, EV_TIMEOUT, 1);
#endif
	} else {
		v->l2_data = NULL;
	}
	list_add(&(v->list), &(plist->list));
	return v;
}
void
zl_port_bridge_update(zl_port_t *plist, const char *ifname) {
	assert(plist != NULL);
	struct list_head *pos, *q;
	list_for_each_safe(pos, q, &ctx->pList->list) {
		zl_port_t *v = list_entry(pos, zl_port_t, list);
		if((v->ifindex != 0) && (v->type != ZL_PORT_TYPE_BRIDGE) && (v->direction != ZL_PORT_DIR_CN)) {
			zl_ioctl_br_addif(ifname, v->ifindex);
		}
	}
}
void 
zl_port_clean(zl_port_t *plist) {
	assert(plist != NULL);
	struct list_head *pos, *q;
	list_for_each_safe(pos, q, &plist->list) {
		zl_port_t *v = list_entry(pos, zl_port_t, list);
		if(v->l2_data) {
			zl_l2_data_free(v->l2_data);	// free l2 process
		}
		list_del(pos);
		free(v);
	}
}
zl_port_t *
zl_port_find_by_name(zl_port_t *plist, char *ifname) {
        assert(plist != NULL);
        struct list_head *pos, *q;
        list_for_each_safe(pos, q, &plist->list) {
                zl_port_t *v = list_entry(pos, zl_port_t, list);
		if(!strncmp(v->ifname, ifname, IFNAMSIZ)) {
			return v;
		}
        }
	return NULL;
}
zl_port_t *
zl_port_find_by_index(zl_port_t *plist, int ifindex) {
        assert(plist != NULL);
        struct list_head *pos, *q;
        list_for_each_safe(pos, q, &plist->list) {
                zl_port_t *v = list_entry(pos, zl_port_t, list);
		if(v->ifindex == ifindex) {
                        return v;
                }
        }
	return NULL;
}
zl_port_t *
zl_port_find_by_hwaddr(zl_port_t *plist, uint8_t *mac) {
        assert(plist != NULL);
        struct list_head *pos, *q;
        list_for_each_safe(pos, q, &plist->list) {
                zl_port_t *v = list_entry(pos, zl_port_t, list);
                if(!memcmp(v->ifhwaddr, mac, ETH_ALEN)) {
                        return v;
                }
        }
        return NULL;
}
zl_port_t *
zl_port_bridge_find(zl_port_t *plist) {
        struct list_head *pos, *q;
        list_for_each_safe(pos, q, &plist->list) {
                zl_port_t *v = list_entry(pos, zl_port_t, list);
		if(v->type == ZL_PORT_TYPE_BRIDGE) {
			return v;
		}
	}
	return NULL;
}

int 
zl_l2_packet_send(zl_l2_data_t *l2, const uint8_t *dst_addr, uint16_t proto, const uint8_t *buff, size_t len) {
	struct vlan_ethhdr *vlan_header  = (struct vlan_ethhdr *)zl_calloc(1, sizeof(*vlan_header) + len);
	zl_memcpy(vlan_header->h_dest, dst_addr, ETH_ALEN);
	zl_memcpy(vlan_header->h_source, l2->own_addr, ETH_ALEN);
	vlan_header->h_vlan_proto = htons(ETH_P_VLAN);
	vlan_header->h_vlan_TCI = htons((ETH_P_VLAN_PRIO << 13) | (ETH_P_VLAN_ID & ETH_P_VLAN_ID_MASK));
	vlan_header->h_vlan_encapsulated_proto = htons(proto); 
	zl_memcpy(vlan_header + 1, buff, len);
	int ret = pcap_inject(l2->capture, (uint8_t *)vlan_header, sizeof(*vlan_header) + len);
	zl_free(vlan_header);
	return ret;
}
void 
zl_l2_packet_recv(int sock, short flags, void *udata) {
	zl_l2_data_t *l2 = (zl_l2_data_t *)(udata);
	struct pcap_pkthdr hdr;
	const u_char *packet;
	struct vlan_ethhdr *ethhdr;
	unsigned char *buf;
	size_t len;
	packet = pcap_next(l2->capture, &hdr);

	if (packet == NULL || hdr.caplen < sizeof(*ethhdr))
		return;

	ethhdr = (struct vlan_ethhdr *) packet;
	buf = (unsigned char *) (ethhdr + 1);
	len = hdr.caplen - sizeof(*ethhdr);
	// 
	int zl_proto = htons(ethhdr->h_vlan_encapsulated_proto);
	zl_ttdpd_protocol_t type = ZL_TTDP_PROTO_MAX;	
	if(zl_proto == ETH_P_HELLO) {
		type = ZL_TTDP_PROTO_HELLO;
	} else if(zl_proto == ETH_P_TOPOLOGY) {
		type = ZL_TTDP_PROTO_TOPOLOGY;
	} else {
		fprintf(stderr, "h_vlan_encapsulated_proto [0x%x] is not supported now..\n", zl_proto);
		return;	// not frame
	}
	l2->zl_rx_callback(l2->zl_rx_callback_ctx, ethhdr->h_source, type, buf, len);
}
static int
zl_l2_pcap_init(zl_l2_data_t *v) {
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	pcap_t *handle = pcap_open_live(v->ifname, BUFSIZ, 1, 0, errbuf); 
	if(handle == NULL)	{
		return -1;
	}
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[1024] = {0, };
	/*
	(ether[0] & 1 = 1 and (not ether src own) and 
                 ((ether proto 0x88cc and ether dst 01:80:c2:00:00:0e) or
                 (ether dst 01:80:c2:00:00:10)))
	*/
	uint8_t zl_helo_mac[] = TTDP_HELLO_DEST_MAC_ADDR;
	uint8_t zl_topo_mac[] = TTDP_TOPOLOGY_MAC_ADDR;
	snprintf(filter_exp, 1024, "(ether[0] & 1 = 1 and (not ether src " ZL_MACSTR ") and "
                 " ((ether proto 0x%x and ether dst " ZL_MACSTR ") or "
                 " (ether dst " ZL_MACSTR ")))", ZL_MACVAL(v->own_addr), ETH_P_HELLO,
		ZL_MACVAL(zl_helo_mac), ZL_MACVAL(zl_topo_mac)); 
	fprintf(stderr, "filter_exp = [%s]\n", filter_exp);
	if (pcap_compile(handle, &fp, filter_exp, 0, 0) == -1) {
		pcap_close(handle);
		return -1;
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		pcap_close(handle);
                return -1;
	}
	v->capture = handle;
	return 0;
}
static int
zl_l2_event_init(zl_l2_data_t *v) {
	v->event = event_new(ctx->g_base, pcap_get_selectable_fd(v->capture), EV_READ|EV_PERSIST, zl_l2_packet_recv, v);
	event_add(v->event, NULL); // Active L2 Read Event
	return 0;
}
zl_l2_data_t *
zl_l2_data_init(const char *ifname, const uint8_t *own_addr,
        void (*zl_rx_callback)(void *uData, const uint8_t *src_addr, zl_ttdpd_protocol_t type, const uint8_t *buff, size_t len),
        void *zl_rx_callback_ctx) {
	zl_l2_data_t *v = (zl_l2_data_t *)zl_calloc(1, sizeof(*v));
	strncpy (v->ifname, ifname, IFNAMSIZ);
	zl_memcpy(v->own_addr, own_addr, ETH_ALEN);	// own mac
	v->zl_rx_callback = zl_rx_callback;
	v->zl_rx_callback_ctx = zl_rx_callback_ctx;
	if(zl_l2_pcap_init(v) != 0) {
		goto n_exit;
	}
	if(zl_l2_event_init(v) != 0) {
		goto n_exit;
	}
	return v;
n_exit:
	zl_l2_data_free(v);
	return NULL;
}
static int
zl_l2_event_free(zl_l2_data_t *v) {
        if(v->event)
                event_free(v->event);
        return 0;
}
static int
zl_l2_pcap_free(zl_l2_data_t *v) {
	if(v->capture)
		pcap_close(v->capture);
	return 0;
}
void 
zl_l2_data_free(zl_l2_data_t *v) {
	assert(v != NULL);
	zl_l2_event_free(v);
	zl_l2_pcap_free(v);
	zl_free(v);
}
