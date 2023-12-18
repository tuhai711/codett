/* zl-tlv-type.h
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

#ifndef __ZL_TLV_TYPE_H__
#define __ZL_TLV_TYPE_H__
enum
{
  /* -- Mandatory TLVs -- */
  TLV_END_OF_LLDPDU = 0,
  TLV_CHASSIS_ID,
  TLV_PORT_ID,
  TLV_TIME_TO_LIVE,

  /* -- Basic TLVs -- */
  TLV_PORT_DESCRIPTION = 4,
  TLV_SYSTEM_NAME,
  TLV_SYSTEM_DESCRIPTION,
  TLV_SYSTEM_CAPABILITIES,
  TLV_MANAGEMENT_ADDRESS,

  /* Elements between 9 and 126 are reserved */
  
	/* -- Organizationally Specific TLV -- */
  TLV_ORG_SPECIFIC = 127
};

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

enum {
	TLV_CHASSIS_SUBTYPE_RESERVED,
	TLV_CHASSIS_SUBTYPE_COMPONENT,
	TLV_CHASSIS_SUBTYPE_ALIAS,
	TLV_CHASSIS_SUBTYPE_PORT_COMPONENT,
	TLV_CHASSIS_SUBTYPE_MAC_ADDRESS,
	TLV_CHASSIS_SUBTYPE_NETWORK_ADDRESS,
	TLV_CHASSIS_SUBTYPE_INTF_NAME,
	TLV_CHASSIS_SUBTYPE_LOCALLY_ASSIGNED,
	TLV_CHASSIS_SUBTYPE_MAX
};
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

enum {
	TLV_PORT_SUBTYPE_RESERVED,
	TLV_PORT_SUBTYPE_INTF_ALIAS,
	TLV_PORT_SUBTYPE_COMPONENT,
	TLV_PORT_SUBTYPE_MAC_ADDRESS,
	TLV_PORT_SUBTYPE_NETWORK_ADDRESS,
	TLV_PORT_SUBTYPE_INTF_NAME,
	TLV_PORT_SUBTYPE_AGENT_ID,
	TLV_PORT_SUBTYPE_LOCALLY_ASSIGNED,
	TLV_PORT_SUBTYPE_MAX
};
/* .... .... .... ...X : Other
 * .... .... .... ..X. : Repeater
 * .... .... .... .X.. : Bridge
 * .... .... .... X... : WLAN Access Point
 * .... .... ...X .... : Router
 * .... .... ..X. .... : Telephone
 * .... .... .X.. .... : DOCSIS cable device
 * .... .... X... .... : Station Only
 * XXXX XXXX .... .... : Reserved */

enum {
	TLV_SYSTEM_CAPS_OTHER,
	TLV_SYSTEM_CAPS_REPEATED,
	TLV_SYSTEM_CAPS_BRIDGE,
	TLV_SYSTEM_CAPS_WLAN_ACCESS_POINT,
	TLV_SYSTEM_CAPS_ROUTER,
	TLV_SYSTEM_CAPS_TELEPHONE,
	TLV_SYSTEM_CAPS_DOCSIS,
	TLV_SYSTEM_CAPS_STATION,
	TLV_SYSTEM_CAPS_MAX,
};
#endif
