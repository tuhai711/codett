#ifndef __ZL_PORTS_H__
#define __ZL_PORTS_H__
//#include <zl-tlv-core.h>

# define zl_timersub(a, b, result)                                               \
  do {                                                                        \
    (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;                             \
    (result)->tv_usec = (a)->tv_usec - (b)->tv_usec;                          \
    if ((result)->tv_usec < 0) {                                              \
      --(result)->tv_sec;                                                     \
      (result)->tv_usec += 1000000;                                           \
    }                                                                         \
  } while (0)

typedef enum {
	ZL_PORT_UP,
	ZL_PORT_DOWN,
	ZL_PORT_MAX,
} zl_port_state_t;
typedef enum {
	ZL_PORT_TYPE_BRIDGE,
	ZL_PORT_TYPE_PHYSICAL,
	ZL_PORT_TYPE_MAX
} zl_port_type_t;
typedef enum {
	ZL_PORT_DIR_NONE,	// CN net
	ZL_PORT_DIR_LEFT,
	ZL_PORT_DIR_RIGHT,
	ZL_PORT_DIR_CN,
	ZL_PORT_DIR_MAX
}zl_port_direct_t;
typedef enum {
        ZL_TTDP_PROTO_HELLO,
        ZL_TTDP_PROTO_TOPOLOGY,
        // TODO: More
        ZL_TTDP_PROTO_MAX
} zl_ttdpd_protocol_t;

///line////
typedef struct zl_port_line_s {
        uint8_t recs_astatus:2;
  uint8_t recs_bstatus:2;
  uint8_t recs_cstatus:2;
  uint8_t recs_dstatus:2;
} zl_port_line_t;

typedef struct zl_l2_data_s zl_l2_data_t;
typedef struct zl_port_s zl_port_t;
typedef struct zl_etb_vector_entry_s zl_etb_vector_entry_t;

struct zl_etb_vector_entry_s {
        uint8_t mac[ETH_ALEN];
        // link list pointer
        struct list_head list;
};


struct zl_l2_data_s {
	pcap_t *capture;	// PCAP Handler
	struct event *event;
	char ifname[IFNAMSIZ];
	uint8_t own_addr[ETH_ALEN];
	void (*zl_rx_callback)(void *ctx, const uint8_t *src_addr, zl_ttdpd_protocol_t type, const uint8_t *buff, size_t len);
	void *zl_rx_callback_ctx;
};

int zl_l2_packet_send(zl_l2_data_t *l2, const uint8_t *dst_addr, uint16_t proto, const uint8_t *buff, size_t len);
void zl_l2_packet_recv(int sock, short flags, void *udata);
zl_l2_data_t * zl_l2_data_init(const char *ifname, const uint8_t *own_addr, 
	void (*zl_rx_callback)(void *ctx, const uint8_t *src_addr, zl_ttdpd_protocol_t type, const uint8_t *buff, size_t len),
	void *zl_rx_callback_ctx);
void  zl_l2_data_free(zl_l2_data_t *l2);

struct zl_port_s {
	char ifname[IFNAMSIZ];
	uint32_t ifindex;
	uint8_t ifhwaddr[ETH_ALEN];	// HW Address
	zl_port_state_t state;		//	zl_port_state_t
	zl_port_type_t type;		// 	zl_port_type_t
	zl_port_direct_t direction;	//	zl_port_direct_t
	zl_port_line_t lineStatus;	//	zl_port_direct_t
	zl_port_state_t linkStatus;	//
	uint8_t cnId:6;
	uint8_t SubnetId; //map from list
	uint8_t hostIp; //map from list
	uint32_t helloLife;
	uint32_t topoLife;
	uint8_t timeOutHello;	//	zl_port_direct_t
	uint8_t timeHello;	//	zl_port_direct_t
	uint8_t timeOutTopo;   //      zl_port_direct_t
        uint8_t timeTopo;      //      zl_port_direct_t
	uint8_t flag_timeout;
//	uint8_t flag_Topotimeout;
  	uint8_t InaugInhi;
	uint8_t remoteMac[ETH_ALEN];///DIR1 DIR2
	zl_etb_vector_entry_t *vList;	// vector mac list
	struct timeval curr_time;
	struct event *time_event_hello;
	struct event *time_event_hello_timeout;
	struct event *time_event_topo;
//        struct event *time_event_topo_timeout;
	zl_l2_data_t *l2_data;		// l2 handler
	struct list_head list;
};

zl_port_t *zl_port_init(void);
void zl_port_free(zl_port_t *plist);
zl_port_t* zl_port_add(zl_port_t *plist, const char *ifname, zl_port_direct_t direction, zl_port_type_t type);
void zl_port_send_by_port(zl_port_t *v, const uint8_t *dst_addr, uint16_t proto, const uint8_t *buff, size_t len);
void zl_port_send_all(zl_port_t *plist, const uint8_t *dst_addr, uint16_t proto, const uint8_t *buff, size_t len);
void zl_port_clean(zl_port_t *plist);
zl_port_t *zl_port_find_by_name(zl_port_t *plist, char *ifname);
zl_port_t *zl_port_find_by_index(zl_port_t *plist, int ifindex);
zl_port_t *zl_port_find_by_hwaddr(zl_port_t *plist, uint8_t *mac);
zl_port_t *zl_port_bridge_find(zl_port_t *plist);
void zl_port_bridge_update(zl_port_t *plist, const char *ifname);
void zl_send_hello_fast(void *uData);
///
zl_etb_vector_entry_t *zl_etb_vector_list_init(void);
zl_etb_vector_entry_t * zl_etb_vector_list_find(zl_etb_vector_entry_t *plist, uint8_t *mac);
uint8_t zl_etb_vector_list_num(zl_etb_vector_entry_t *plist);
void zl_etb_vector_list_free(zl_etb_vector_entry_t *plist);
void zl_etb_vector_list_clean(zl_etb_vector_entry_t *plist);
void zl_etb_vector_list_add(zl_etb_vector_entry_t *plist, uint8_t *mac);
zl_etb_vector_entry_t *zl_etb_vector_list_index_find(zl_etb_vector_entry_t *plist);
void zl_etb_vector_list_del(zl_etb_vector_entry_t *plist, uint8_t *mac);
//uint8_t zl_etb_vector_list_get_all(zl_etb_vector_entry_t *plist, zl_mac_address_t *dir_etbns, uint8_t *num);
//
#endif	//	__ZL_PORTS_H__
