#include <zl-comm.h>
#include <zl-mem.h>
#include <zl-tlv-common.h>
#include <tlv.h>
zl_tlv_t *
zl_tlv_init(void) {
	zl_tlv_t *v = (zl_tlv_t *)zl_calloc(1, sizeof(zl_tlv_t));
	assert(v != NULL);
	INIT_LIST_HEAD(&v->list);
	return v;
}
void 
zl_tlv_clean(zl_tlv_t *plist) {
  assert(plist != NULL);
  struct list_head *pos, *q;
  list_for_each_safe(pos, q, &plist->list) {
    zl_tlv_t *v = list_entry(pos, zl_tlv_t, list);
    list_del(pos);
		zl_free(v->data);
    zl_free(v);
  }
}
void 
zl_tlv_free(zl_tlv_t *plist) {
	assert(plist != NULL);
	zl_tlv_clean(plist);
	zl_free(plist);
}
void 
zl_tlv_add(zl_tlv_t *plist, int type, int length, void *data) {
	assert(plist != NULL);
	zl_tlv_t *v = (zl_tlv_t *)zl_calloc(1, sizeof(zl_tlv_t));
	v->type = type;
	v->length = length;
	v->data = zl_calloc(length, sizeof(void));
	zl_memcpy(v->data, data, length);
	list_add(&(v->list), &(plist->list));
}
zl_tlv_t *
zl_tlv_pop(zl_tlv_t *plist) {
	assert(plist != NULL);
	struct list_head *pos, *q;
	list_for_each_prev_safe(pos, q, &plist->list) {
		zl_tlv_t *v = list_entry(pos, zl_tlv_t, list);
		list_del(pos);
		return v;
	}
	return NULL;
}
void 
zl_tlv_del(zl_tlv_t *plist, int type) {
	assert(plist != NULL);
	struct list_head *pos, *q;
	list_for_each_safe(pos, q, &plist->list) {
		zl_tlv_t *v = list_entry(pos, zl_tlv_t, list);
		if(v->type == type) {
			list_del(pos);
			zl_free(v->data);
			zl_free(v);
		}
	}
}
zl_tlv_t *
zl_tlv_find(zl_tlv_t *plist, int type) {
	assert(plist != NULL);
	struct list_head *pos, *q;
	list_for_each_safe(pos, q, &plist->list) {
		zl_tlv_t *v = list_entry(pos, zl_tlv_t, list);
		if(v->type == type) {
			return v;
		}
	}
	return NULL;
}
void *
zl_tlv_encode(zl_tlv_t *plist, size_t *size) {
	assert(plist != NULL);
	struct list_head *pos, *q;
	void *buff = zl_calloc(1, sizeof(void));
	size_t nBytes = 0;
	list_for_each_prev_safe(pos, q, &plist->list) {
		zl_tlv_t *v = list_entry(pos, zl_tlv_t, list);
		zl_tlv_cmn_t tz = {v->type, v->length};
		zl_tlv_common_serialize(&tz);
		// encode tlv header
		buff = zl_realloc(buff, nBytes + sizeof(zl_tlv_cmn_t) + v->length);
		zl_memcpy(buff + nBytes, &tz, sizeof(zl_tlv_cmn_t));
		nBytes += sizeof(zl_tlv_cmn_t);
		// encode tlv payload
		memcpy(buff + nBytes, v->data, v->length);
		nBytes += v->length;
	}
	*size = nBytes;
	return buff;
}
zl_tlv_t *
zl_tlv_decode(void *data, size_t size) {
	assert(data != NULL);
	zl_tlv_t *plist = zl_tlv_init();
	size_t index = 0;
	while(index < size) {
		zl_tlv_cmn_t *tz = (zl_tlv_cmn_t *)(data + index);
		zl_tlv_common_deserialize(tz);
		index += sizeof(zl_tlv_cmn_t);
		zl_tlv_add(plist, tz->type, tz->length, data + index);
		index += tz->length;
	}
	return plist;
}
