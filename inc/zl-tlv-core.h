/* zl-tlv-core.h
 *
 * Copyright 2019 Leesoo Ahn <yisooan@fedoraproject.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __ZL_TLV_CORE_H__
#define __ZL_TLV_CORE_H__

#include <stdint.h>

#include <zl-macro.h>
#include <zl-tlv-common.h>

/* -- End Of LLDPDU (Mandatory) -- */
typedef zl_tlv_cmn_t zl_tlv_end_lldpdu_t;

/* -- Chassis ID (Mandatory) -- */
typedef struct _zl_tlv_chassis_id_t zl_tlv_chassis_id_t;
struct _zl_tlv_chassis_id_t
{
  /* 0: Reserved
   * 1: Chassis component
   * 2: Interface alias
   * 3: Port component
   * 4: MAC address
   * 5: Network address
   * 6: Interface name
   * 7: Locally assigned
   * 8-255: Reserved
   */
  uint8_t       subtype;
  uint8_t       value[6];	// mac
} zl_1byte_pack;

/* -- Port ID (Mandatory) -- */
typedef struct _zl_tlv_port_id_t zl_tlv_port_id_t;
struct _zl_tlv_port_id_t
{
  /* 0: Reserved
   * 1: Interface alias
   * 2: Port component
   * 3: MAC address
   * 4: Network address
   * 5: Interface name
   * 6: Agent circuit ID
   * 7: Locally assigned
   * 8-255: Reserved
   */
  uint8_t       subtype;
  uint8_t       value;
} zl_1byte_pack;

/* -- Time To Live (Mandatory) -- */
typedef struct _zl_tlv_ttl_t zl_tlv_ttl_t;
struct _zl_tlv_ttl_t
{
  uint16_t      value;
} zl_1byte_pack;
typedef struct _zl_tlv_hello_t zl_tlv_hello_t;
struct _zl_tlv_hello_t
{
  	uint8_t       oui[3];
  	uint8_t       subtype;
	uint16_t tlv_cs;
  	uint32_t version;
  	uint32_t lifesign;
//  uint8_t line;
	uint32_t etb_topo_cnt;
  	uint8_t vendor[32];
	uint8_t recs_astatus:2;
	uint8_t recs_bstatus:2;
	uint8_t recs_cstatus:2;
	uint8_t recs_dstatus:2;
  	uint8_t timeout_management;
  	uint8_t src_id[6];
  	uint8_t src_port_id;
  	uint8_t egressline;
  
	uint8_t egress_dir;
	uint8_t reserved1:6;
	uint8_t inaugh_init:2;
	
  	uint8_t remoteid[6];
	uint16_t reserved2;
  	uuid_t cstuuid;
} zl_1byte_pack;

typedef struct zl_mac_address
{
  uint8_t address[ETH_ALEN];
} zl_mac_address_t;

typedef struct zl_etb_link_info_s
{
	uint8_t  etbn_linea:2;
	uint8_t  etbn_lineb:2;
	uint8_t  etbn_linec:2;
	uint8_t  etbn_lined:2;
  	uint8_t  etbn_dira;
  	uint8_t  etbn_dirb;
  	uint8_t  etbn_dirc;
  	uint8_t  etbn_dird;
}zl_etb_link_info_t;


typedef struct _zl_tlv_etb_t zl_tlv_etb_t;
struct _zl_tlv_etb_t
{
  uint8_t  protocol_id[4];
  uint32_t protocol_version;
  uint32_t lifesign;
  uuid_t  cst_uuid;
  
  uint8_t  etbn_inaugState;
  uint8_t  etbn_node_role;
  uint8_t  reserved1:6;
  uint8_t  etbn_inhibit:2;
  
  uint8_t  reserved2:6;
  uint8_t  remote_inhibit:2;
  uint8_t  cstOrientation; ///add more
  uint32_t contablecrc32;
  zl_etb_link_info_t etbn_dir1; 
  zl_etb_link_info_t etbn_dir2;
  
  uint8_t  macaddress_dir1[ETH_ALEN];
  uint8_t  own_macaddress[ETH_ALEN];
  uint8_t  macaddress_dir2[ETH_ALEN];
  uint8_t  ndir1_etbn;
  uint8_t  ndir2_etbn;
  uint16_t  reserved3;
  //size 68 
  zl_mac_address_t dir_etbns[62];
//  zl_mac_address_t *dir1_etbns;
 // zl_mac_address_t *dir2_etbns;
//  uint32_t  padding;
} zl_1byte_pack;

typedef struct _zl_tlv_cn_t zl_tlv_cn_t;
struct _zl_tlv_cn_t
{
  uint32_t etb_topo_cnt;
  uint8_t own_entb_nb;

  uint8_t  lengthen:2;
  uint8_t  shorten:2;
  uint8_t  reserved1:4;

  uint8_t nEtbnCst;
  uint8_t nCnCst;
  uint32_t cnToEtbnList[32];
  uint8_t cnTypes[32];
 // uint32_t  padding;
} zl_1byte_pack;
#endif
