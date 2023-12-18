#ifndef __Z_TTDP_H__
#define __Z_TTDP_H__
#include <zl-comm.h>
#include <zl-ports.h>
#include <uuid/uuid.h>
// Address of ETBN
//00001010. 1bb00000. 00000000.v0tttttt/18
#define TTDP_ETBN_IP_ADDR_MASK		{0x0A, 0x70, 0x00, 0xBF}	// 10.x.0.1/18
//00001010. 1bb00000. 00tttttt.hhhhhhhh/18
#define TTDP_ETBN_HOST_ADDR_MASK	{0x0A, 0x70, 0x3F, 0xFF}

// BPF Filter 
//	HELLO: 01-80-C2-00-00-0E		//	
// 	TOPOLOGY: 01-80-C2-00-00-10	//
/*	(ether[0] & 1 = 1 and
                 ((ether proto 0x88cc and ether dst 01:80:c2:00:00:0e) or
                 (ether dst 01:80:c2:00:00:10)))
*/

#define TTDP_FILTER_F					\
	{ 0x30, 0, 0, 0x00000000 }, \
	{ 0x54, 0, 0, 0x00000001 }, \
	{ 0x15, 0, 9, 0x00000001 }, \
	{ 0x28, 0, 0, 0x0000000c }, \
	{ 0x15, 0, 2, 0x000088cc }, \
	{ 0x20, 0, 0, 0x00000002 }, \
	{ 0x15, 2, 0, 0xc200000e }, \
	{ 0x20, 0, 0, 0x00000002 }, \
	{ 0x15, 0, 3, 0xc2000010 }, \
	{ 0x28, 0, 0, 0x00000000 }, \
	{ 0x15, 0, 1, 0x00000180 }, \
	{ 0x6, 0, 0, 0x00040000 },  \
	{ 0x6, 0, 0, 0x00000000 }

//	CSTINFO:	239.192.0.3:61375	//
#define TTDP_MCAST_IP_ADDRESS	0xefc00003	// 239.192.0.3
#define TTDP_MCAST_DST_PORT		61375

#define ZL_MSG_SIZE_MAX	16384	// 16k

#define ZL_HELLO_TIME_SLOW 100
#define ZL_HELLO_TIMEOUT_SLOW 130
#define ZL_HELLO_TIME_FAST 15
#define ZL_HELLO_TIMEOUT_FAST 45
#define ZL_TOPO_TIME 100
#define ZL_TOPO_TIMEOUT 400

typedef struct zl_ttdpd_s zl_ttdpd_t;
typedef struct zl_fdb_entry_s zl_fdb_list_t;

typedef struct zl_ttdpd_connectivity_s 	zl_ttdpd_connectivity_t;
typedef struct zl_ttdpd_connectivity_list_s 	zl_ttdpd_connectivity_list_t;
typedef struct zl_ttdpd_directory_s 		zl_ttdpd_directory_t;
typedef struct zl_ttdpd_directory_train_list_s 		zl_ttdpd_directory_train_list_t;
typedef struct zl_ttdpd_directory_cn_list_s 		zl_ttdpd_directory_cn_list_t;
typedef struct zl_ttdpd_directory_cn_s 		zl_ttdpd_directory_cn_t;
typedef struct zl_ttdpd_connectivity_vector_s zl_ttdpd_connectivity_vector_t;
typedef struct zl_ttdpd_line_s zl_ttdpd_line_t;

///	--------------------------------------
typedef enum {
	ZL_TTDPD_ORIENTATION_ERROR,			// 00
	ZL_TTDPD_ORIENTATION_DIRECT,		// 01
	ZL_TTDPD_ORIENTATION_INVERSE,		// 02
	ZL_TTDPD_ORIENTATION_UNDEFINED,	// 03
	ZL_TTDPD_ORIENTATION_MAX
} zl_ttdpd_orientation_t;

struct zl_ttdpd_connectivity_s {
	uint8_t orientation;		// zl_ttdpd_orientation_t
	uint8_t reserved;
	uint8_t mac[ETH_ALEN];	// 6 bytes mac address
};


struct zl_ttdpd_connectivity_vector_s {
  uint8_t mac_dir1[ETH_ALEN];  // 6 bytes mac address
  uint8_t mac_own[ETH_ALEN];  // 6 bytes mac address
  uint8_t mac_dir2[ETH_ALEN];  // 6 bytes mac address
};
typedef struct zl_ttdpd_connectivity_list_sort_s
{	
	uint8_t numEtb;
	zl_ttdpd_connectivity_t connectivity;
	struct list_head list;
}zl_ttdpd_connectivity_list_sort_t;
///	--------------------------------------
typedef struct zl_ttdp_etb_cn_s {
	uuid_t CstUUID;
	uint8_t flagCn;
	uint8_t flagIni;
        uint32_t pCnEtb;
	uint8_t nEtbnCst;
	uint8_t nCnCst;
	uint8_t SubnetId; //list
	uint8_t orientationCst; 
	uint32_t cnToEtbnList[32];
  	uint8_t cnTypes[32];
}zl_ttdp_etb_cn_t;
struct zl_ttdpd_connectivity_list_s {
	uint8_t numEtb;
	///dictory//
	zl_ttdp_etb_cn_t etbCn;
//	uuid_t CstUUID;
//	uint32_t pCnEtb;
//	zl_ttdpd_directory_cn_list_t *cnList;	
	struct event *timeout_topo_event;
	uint8_t flag_Topotimeout;
	zl_ttdpd_connectivity_t connectivity;
	// link list pointer
	struct list_head list;
};
///	--------------------------------------
struct zl_ttdpd_directory_s  {
//	uint8_t CstUUID[16];
	uuid_t CstUUID;
	uint32_t CnId;
	uint8_t SubnetId;
	uint8_t EtbnId;
	uint8_t nEtbnCst;
        uint8_t nCnCst;
	uint8_t etbRole;
	uint8_t etbOrientation; //Vehicle
	uint8_t cstOrientation;	//consist
};

typedef struct zl_ttdpd_directory_sub_s  {
        uuid_t CstUUID;
        uint8_t CnId;
        uint8_t SubnetId;
        uint8_t EtbnId;
        uint8_t cstOrientation; //consist
}zl_ttdpd_directory_sub_t;

typedef struct zl_ttdpd_directory_etb_s  {
        uint8_t EtbnId;
        zl_ttdpd_directory_sub_t directory_sub;
        struct list_head list;
}zl_ttdpd_directory_etb_t;

struct zl_ttdpd_directory_cn_s  {
        uint8_t CnId;
	zl_ttdpd_directory_etb_t *directory_etb;
	struct list_head list;
};

struct zl_ttdpd_directory_cn_list_s{
	zl_ttdpd_directory_sub_t directory;
	zl_ttdp_etb_cn_t etbCn;
	uint8_t hostIp;
	struct list_head list;
};

struct zl_fdb_entry_s {
        uint8_t mac[ETH_ALEN];
        uint32_t ifindex;
        // link list pointer
        struct list_head list;
};

///	--------------------------------------
struct zl_ttdpd_s {
	// bridge interface
	char ifname[IFNAMSIZ];
	uint8_t ifaddr[ETH_ALEN]; 	// mac address of ifname
	//
	zl_ttdpd_directory_t cfx;	// itself config
	uint8_t flagCn;
	uint8_t flagHello;
	uint8_t flagTopology;
	uint8_t flagDel;
	//haiadd
  	uint8_t EtbInhi;
  	uint8_t Inauguration;
  	uint8_t ConnTableValid;
  	uint8_t EtbTopoCntValid;
  	uint32_t ConnTableCrc;
  	uint32_t EtbTopoCnt;
	uint32_t etbCns;
  	uint8_t cnLengthen:2;
  	uint8_t cnShorten:2;
	zl_ttdpd_connectivity_vector_t conVector;
	
//	zl_ttdpd_line_t lineStatus;
	// event
	struct event_base *g_base;
	// time
	struct event *time_topo_event;
//	uint16_t topo_time;
	// netlink
	evutil_socket_t nl_sock;                // netlink socket
	int32_t nl_sequence;
	struct event *link_event;       // netlink
	zl_fdb_list_t *fList;	// FDB list
	// list port -
	zl_port_t *pList;	// port list;
	zl_port_t *pDir1; //map
	zl_port_t *pDir2; //map
	zl_ttdpd_connectivity_list_t *cList;	//	zl_ttdpd_connectivity_list_t
	zl_ttdpd_connectivity_list_t *cLocal;
	zl_ttdpd_connectivity_t comTmp[32];
	zl_ttdpd_directory_cn_list_t	*dList;
};
///	--------------------------------------
uint32_t zl_ttdpd_etbn_address(uint8_t b, uint8_t v, uint8_t t);
uint32_t zl_ttdpd_etbn_host_address(uint8_t b, uint8_t t, uint8_t h);
uint32_t zl_ttdpd_etbn_subnet_address(uint8_t b, uint8_t s, uint16_t h);
///	--------------------------------------
zl_ttdpd_connectivity_list_t *zl_ttdpd_connectivity_list_init(void);
void zl_ttdpd_connectivity_list_free(zl_ttdpd_connectivity_list_t *plist);
void zl_ttdpd_connectivity_list_clean(zl_ttdpd_connectivity_list_t *plist);
zl_ttdpd_connectivity_list_t* zl_ttdpd_connectivity_list_find(zl_ttdpd_connectivity_list_t *plist, uint8_t *data, uuid_t CstUUID, uint8_t *pEtbnCst);
zl_ttdpd_connectivity_list_t* zl_ttdpd_connectivity_list_find_update_etb(zl_ttdpd_connectivity_list_t *plist, uint8_t *data, uuid_t CstUUID, uint8_t pEtbnCst);
void zl_ttdpd_connectivity_list_add(zl_ttdpd_t *ctx, zl_ttdpd_connectivity_t *data, uint8_t pNum, zl_ttdp_etb_cn_t *etbCn);
void zl_ttdpd_connectivity_list_add_sort (zl_ttdpd_t *ctx, zl_ttdpd_connectivity_t *data, uint8_t pNum, zl_ttdp_etb_cn_t *etbCn);
void zl_ttdp_ttdpd_connectivity_list_default(zl_ttdpd_t *ctx, uint8_t pNum);
uint32_t zl_ttdp_checksum_connectivity(zl_ttdpd_t *ctx);
//uint32_t zl_ttdp_checksum_connectivity(zl_ttdpd_connectivity_list_t *pList);
void zl_ttdpd_connectivity_list_print(zl_ttdpd_connectivity_list_t *plist);
uint8_t zl_ttdpd_topology_get_CnCst(zl_ttdpd_t *ctx);
uint8_t zl_ttdpd_topology_get_nEtbnCst(zl_ttdpd_connectivity_list_t *plist, uuid_t CstUUID);
///	--------------------------------------
zl_ttdpd_directory_cn_list_t *zl_ttdpd_directory_cn_list_init(void);
void zl_ttdpd_directory_cn_list_free(zl_ttdpd_directory_cn_list_t *plist);
void zl_ttdpd_directory_cn_list_clean(zl_ttdpd_directory_cn_list_t *plist);

zl_ttdpd_directory_cn_list_t* 
zl_ttdpd_directory_cn_list_add(zl_ttdpd_directory_cn_list_t *plist, zl_ttdpd_directory_sub_t *pCnSub, zl_ttdp_etb_cn_t *etbCn);

void zl_ttdp_directory_table(zl_ttdpd_t *ctx);
void zl_ttdpd_directory_cn_default(zl_ttdpd_t *ctx);
uint32_t zl_ttdp_checksum_directory(zl_ttdpd_t *ctx);
///	--------------------------------------
int zl_cfx_load_file(void *data);
///	--------------------------------------
void zl_ttdpd_event_init(zl_ttdpd_t *ctx);
void zl_ttdpd_event_free(zl_ttdpd_t *ctx);
void zl_ttdpd_event_loop(zl_ttdpd_t *ctx);
///	--------------------------------------
zl_ttdpd_t * zl_ttdpd_init(void);
zl_ttdpd_t* zl_zl_ttdpd_get(void);// get from port
void zl_ttdpd_load(zl_ttdpd_t *ctx);	// load configure itself
void zl_ttdpd_loop(zl_ttdpd_t *ctx);
void zl_ttdpd_free(zl_ttdpd_t *ctx);
///	--------------------------------------
zl_fdb_list_t *zl_fdb_list_init(void);
void zl_fdb_list_free(zl_fdb_list_t *plist);
void zl_fdb_list_clean(zl_fdb_list_t *plist);
void zl_fdb_list_add(zl_fdb_list_t *plist, uint8_t *mac, int ifindex);
zl_fdb_list_t *zl_fdb_list_find(zl_fdb_list_t *plist, uint8_t *mac);
zl_fdb_list_t *zl_fdb_list_index_find(zl_fdb_list_t *plist, int ifindex);
void zl_fdb_list_del(zl_fdb_list_t *plist, uint8_t *mac, int ifindex);
///	--------------------------------------
void *zl_ttdpd_hello_encode(zl_ttdpd_t *ctx, int *size);
void * zl_ttdpd_topology_encode(zl_ttdpd_t *ctx, int *size);
void * zl_ttdpd_hello_tlv_encode(zl_ttdpd_t *ctx, zl_port_t *phyport, void *data, size_t *size);
void * zl_ttdpd_topology_tlv_encode(zl_ttdpd_t *ctx, zl_port_t *phyport, void *data, size_t *size);
void zl_ttdpd_hello_decode(zl_ttdpd_t *ctx, void *uData, const uint8_t *src_addr, void *data, size_t size);
void zl_ttdpd_topology_decode(zl_ttdpd_t *ctx, void *uData, const uint8_t *src_addr, void *data, size_t size);
void zl_thread_lock(void);
void zl_thread_unlock(void);
//////////////
uint32_t setBit(uint32_t data, uint8_t pos);
uint32_t clearNthBit(uint32_t data, uint8_t pos);
#define SET     1
#define NOT_SET 0
int isNthBitSet(unsigned int data,unsigned int pos);
unsigned int countSetBits(unsigned int n);
void zl_ttdp_uuid_print(uuid_t pCstUUID);
void zl_ttdpd_directory_cn_list_print(zl_ttdpd_directory_cn_list_t *plist);
uint8_t zl_ttdpd_topology_get_EtbCn(zl_ttdpd_t *ctx, uint32_t *pEtbnList);
uint8_t zl_ttdp_directory_check_ebtnum_consist(zl_ttdpd_t *ctx, uint8_t nEtbnCst,  uuid_t CstUUID);
/////
#endif	//	__Z_TTDP_H__
