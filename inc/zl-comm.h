#ifndef __Z_COMMON_H__
#define __Z_COMMON_H__
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <sys/ioctl.h>
#include <net/if.h>
#include <fcntl.h>
#include <signal.h>
#include <arpa/inet.h>
#include <net/route.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <filter.h>
#include <errno.h>
// vlan
#include <linux/if_bridge.h>
#include <linux/if_vlan.h>
// event
#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
// netlink
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <pcap.h>
// local
#include <zl-log.h>
#include <list.h>
#include <zl-tlv-type.h>
#ifndef TRUE
#define TRUE (1)
#endif	// TRUE
#ifndef FALSE
#define FALSE (0)
#endif	// FALSE
#define ETH_P_VLAN_ID_MASK      0x0FFF
#define ETH_P_VLAN_PCI_MASK     0xE000
#define ETH_P_VLAN      0x8100
#define ETH_P_LLDP      0x88CC
#define ETH_P_TTDP_VLAN_ID 0x1EC        // 0x1ec
//
#define ETH_P_VLAN_PRIO 7
#define ETH_P_VLAN_ID   0x1EC
#define ETH_P_HELLO     0x88CC
#define ETH_P_TOPOLOGY  0x894C
//
#define TTDP_HELLO_DEST_MAC_ADDR        {0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e}
#define TTDP_TOPOLOGY_MAC_ADDR          {0x01, 0x80, 0xc2, 0x00, 0x00, 0x10}
#define TTDP_ALL_HOSTS_ADDR             {239, 192, 0, 0}
#define TTDP_ETBN_HOSTS_ADDR            {239, 192, 0, 1}
#define TTDP_TOPOLOGY_ADVERTISING_ADDR  {239, 192, 0, 2}
#define TTDP_CONSIST_INFO_GROUP_ADDR    {239, 192, 0, 3}
#define ZL_MACVAL(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define ZL_MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"
#endif	//	__Z_COMMON_H__
