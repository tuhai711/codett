/* zl-tlv-common.h
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

#ifndef __ZL_TLV_COMMON_H__
#define __ZL_TLV_COMMON_H__

#include <stdint.h>
#include <arpa/inet.h>

#include <zl-macro.h>
#include <zl-tlv-type.h>

/* -- Common Type -- */
typedef struct _zl_tlv_cmn_t zl_tlv_cmn_t;
struct _zl_tlv_cmn_t
{
  uint8_t   type : 7;
  uint16_t  length : 9;
} zl_1byte_pack;

#define GET_TLV_COMMON_INSTANCE(tlv) (zl_tlv_cmn_t *)tlv

static inline void
zl_tlv_common_serialize (zl_tlv_cmn_t *common)
{
  uint16_t val = 0;

  zl_ret_if_fail (common != NULL);

  val |= (common->type << 9);
  val |= (common->length);

  *(uint16_t *)common = htons (val);
}
static inline void
zl_tlv_common_deserialize (zl_tlv_cmn_t *common)
{
	zl_ret_if_fail (common != NULL);
	uint16_t val = ntohs(*(uint16_t *)common);
	common->type = (val >> 9) & 0xff;
	common->length = val & 0x1ff;
}
/* -- Organizationally Specific TLV Type -- */
typedef struct _zl_tlv_org_t zl_tlv_org_t;
struct _zl_tlv_org_t
{
  zl_tlv_cmn_t  parent;

  uint8_t       oui[3];
  uint8_t       subtype;
} zl_1byte_pack;

#endif
