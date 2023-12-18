#ifndef __ZL_TLV_H__
#define	__ZL_TLV_H__
#include <zl-comm.h>

typedef struct zl_tlv_s {
	int type;
	int length;
	void *data;
	struct list_head list;	// link list
} zl_tlv_t;
//-----------------------------------------------------------------
zl_tlv_t *zl_tlv_init(void);
//-----------------------------------------------------------------
void zl_tlv_clean(zl_tlv_t *plist);
//-----------------------------------------------------------------
void zl_tlv_free(zl_tlv_t *plist);
//-----------------------------------------------------------------
void zl_tlv_add(zl_tlv_t *plist, int type, int length, void *data);
//-----------------------------------------------------------------
void zl_tlv_del(zl_tlv_t *plist, int type);
zl_tlv_t *zl_tlv_pop(zl_tlv_t *plist);
//-----------------------------------------------------------------
zl_tlv_t *zl_tlv_find(zl_tlv_t *plist, int type);
//-----------------------------------------------------------------
void *zl_tlv_encode(zl_tlv_t *plist, size_t *size);
//-----------------------------------------------------------------
zl_tlv_t *zl_tlv_decode(void *data, size_t size);
//-----------------------------------------------------------------
#endif	//	__ZL_TLV_H__
