#include <pthread.h>
#include <zl-comm.h>
#include <zl-sock.h>
#include <zl-mem.h>
#include <zl-ports.h>
#include <zl-ioctl.h>
#include <zl-ttdp.h>
#include <zl-ini.h>
#include <crc.h>
/// --------------------------------------
pthread_mutex_t _mutex = PTHREAD_MUTEX_INITIALIZER;

uint32_t setBit(uint32_t data, uint8_t pos)
{
    return (data|(1 << pos));
}
uint32_t clearNthBit(uint32_t data, uint8_t pos)
{
    return (data & (~(1 << pos)));
}
int isNthBitSet(unsigned int data,unsigned int pos)
{
    return ((data & (1 << pos))? SET : NOT_SET);
}
unsigned int countSetBits(unsigned int n)
{
    unsigned int count = 0;
    while (n) {
        count += n & 1;
        n >>= 1;
    }
    return count;
}

void
zl_thread_lock(void) {
	pthread_mutex_lock(&_mutex);
}
void
zl_thread_unlock(void) {
	pthread_mutex_unlock(&_mutex);
}

uint32_t
zl_ttdpd_etbn_address(uint8_t b, uint8_t v, uint8_t t) {
	uint32_t val = (0x0A << 24) | ((0x80 | (b << 5)) << 16) | ((v << 8) | (t & 0x3F));
	return val;
}
uint32_t 
zl_ttdpd_etbn_host_address(uint8_t b, uint8_t t, uint8_t h) {
	uint32_t val = (0x0A << 24) | ((0x80 | (b << 5)) << 16) | ((t & 0x3F) << 8) | (h & 0xFF);
	return val;
}
uint32_t
zl_ttdpd_etbn_subnet_address(uint8_t b, uint8_t s, uint16_t h) {
	uint32_t val = (0x0A << 24) | 
		((0x80 | b << 6 | ((s >> 2) | 0x08)) << 16) | 
		((s << 6 | h >> 8) << 8) | (h & 0xff);
	return val;
}
/// --------------------------------------
zl_ttdpd_connectivity_list_t *
zl_ttdpd_connectivity_list_init(void) {
	zl_ttdpd_connectivity_list_t *pCon = (zl_ttdpd_connectivity_list_t *)malloc(sizeof(zl_ttdpd_connectivity_list_t));
	assert(pCon != NULL);
	INIT_LIST_HEAD(&pCon->list);
	return pCon;
}
void 
zl_ttdpd_connectivity_list_free(zl_ttdpd_connectivity_list_t *plist) {
	assert(plist != NULL);
	zl_ttdpd_connectivity_list_clean(plist);
	free(plist);
}
void 
zl_ttdpd_connectivity_list_clean(zl_ttdpd_connectivity_list_t *plist) {
	assert(plist != NULL);
	struct list_head *pos, *q;
	list_for_each_safe(pos, q, &plist->list) {
		zl_ttdpd_connectivity_list_t *v = list_entry(pos, zl_ttdpd_connectivity_list_t, list);
		list_del(pos);
		if(v->timeout_topo_event != NULL)
                                event_free(v->timeout_topo_event);
		free(v);
	}
}

zl_ttdpd_connectivity_list_t*
zl_ttdpd_connectivity_list_find(zl_ttdpd_connectivity_list_t *plist, uint8_t *data, uuid_t CstUUID, uint8_t *pEtbnCst) {
        assert(plist != NULL);
	uint8_t pCount = 0;
        struct list_head *pos, *q;
	zl_ttdpd_connectivity_list_t *tmp = NULL;
        list_for_each_safe(pos, q, &plist->list) {
                zl_ttdpd_connectivity_list_t *v = list_entry(pos, zl_ttdpd_connectivity_list_t, list);
		//update ETB in consic ///
		 if(uuid_compare(v->etbCn.CstUUID, CstUUID) == 0)
                {
                        pCount++;
                }

		if(memcmp(v->connectivity.mac, data, ETH_ALEN) == 0)
		{
			tmp = v;
//			return v;
		}
        }
	*pEtbnCst = pCount;
	return tmp;
}
zl_ttdpd_connectivity_list_t* //find local and update numETB in consist
zl_ttdpd_connectivity_list_find_update_etb(zl_ttdpd_connectivity_list_t *plist, uint8_t *data, uuid_t CstUUID, uint8_t pEtbnCst)
{
	assert(plist != NULL);
        struct list_head *pos, *q;
        zl_ttdpd_connectivity_list_t *tmp = NULL;
        list_for_each_safe(pos, q, &plist->list) {
                zl_ttdpd_connectivity_list_t *v = list_entry(pos, zl_ttdpd_connectivity_list_t, list);
                //update ETB in consic ///
                 if(uuid_compare(v->etbCn.CstUUID, CstUUID) == 0 && pEtbnCst > 0)
                {
                	v->etbCn.nEtbnCst = pEtbnCst;
                }

                if(memcmp(v->connectivity.mac, data, ETH_ALEN) == 0)
                {
                        tmp = v;
//                      return v;
                }
        }
        return tmp;
}

void
zl_ttdp_vector_del(zl_ttdpd_t* ctx, uint8_t *data)
{
	if(ctx->pDir1 != NULL)
		zl_etb_vector_list_del(ctx->pDir1->vList, data);
	if(ctx->pDir2 != NULL)
		zl_etb_vector_list_del(ctx->pDir2->vList, data);
#if 0
	zl_port_t *pLocal;
	if(ctx->cfx.etbOrientation == 1)
		pLocal = ctx->pDir1;
	else if(ctx->cfx.etbOrientation == 2)
		pLocal = ctx->pDir2;
	if(pLocal != NULL)
	{
		zl_ttdpd_connectivity_list_t* v = zl_ttdpd_connectivity_list_find(ctx->cList, ctx->ifaddr);
		if(v != NULL)
		{
			v->numEtb = zl_etb_vector_list_num(pLocal->vList);
		}

         	ctx->cfx.EtbnId = zl_etb_vector_list_num(pLocal->vList)+1;
	}
#endif //update own after del
}

void
zl_ttdpd_connectivity_del(zl_ttdpd_t* ctx, zl_ttdpd_connectivity_list_t *data) {
	zl_thread_lock();
        assert(ctx->cList != NULL);
        struct list_head *pos, *q;
        list_for_each_safe(pos, q, &ctx->cList->list) {
                zl_ttdpd_connectivity_list_t *v = list_entry(pos, zl_ttdpd_connectivity_list_t, list);
                if(memcmp(v->connectivity.mac, data->connectivity.mac, ETH_ALEN) == 0) {
			printf("----------(%d)---- ->[DEL]<- [" ZL_MACSTR "] \n", __LINE__, ZL_MACVAL(v->connectivity.mac));
ctx->flagCn = 1;
                        zl_ttdp_vector_del(ctx, data->connectivity.mac);
#if 0
			if(v->timeout_topo_event != NULL)
				event_free(v->timeout_topo_event);
			list_del(pos);
                        free(v); 
#endif
                        break;
                }
        }
//	ctx->ConnTableCrc = zl_ttdp_checksum_connectivity(ctx);
//	ctx->ConnTableCrc = zl_ttdp_checksum_connectivity(ctx->cList);
	zl_ttdpd_connectivity_list_clean(ctx->cList);
        zl_ttdp_ttdpd_connectivity_list_default(ctx, 0);
	ctx->EtbInhi = 1;
	zl_thread_unlock();
}

void
zl_ttdpd_connectivity_list_print(zl_ttdpd_connectivity_list_t *plist) {
        assert(plist != NULL);
        struct list_head *pos, *q;
//        list_for_each_safe(pos, q, &plist->list) {
	printf("ConVector Table:\n");
	printf("\tMAC address		   Orientation\n");
	list_for_each_prev_safe (pos, q, &plist->list) {
                zl_ttdpd_connectivity_list_t *v = list_entry(pos, zl_ttdpd_connectivity_list_t, list);
                printf("\t[" ZL_MACSTR "]	%10d\n", ZL_MACVAL(v->connectivity.mac), v->connectivity.orientation);
        }
}

uint8_t
zl_ttdpd_topology_get_CnCst(zl_ttdpd_t *ctx)
{
	assert(ctx->cList != NULL);
	uint8_t pCnCst = 0;
        struct list_head *pos, *q;
         list_for_each_prev_safe (pos, q, &ctx->cList->list) {
                zl_ttdpd_connectivity_list_t *v = list_entry(pos, zl_ttdpd_connectivity_list_t, list);
		if(uuid_compare(v->etbCn.CstUUID, ctx->cfx.CstUUID) == 0)
                {
                        pCnCst++;//
                }
		if(memcmp(v->connectivity.mac, ctx->ifaddr, ETH_ALEN) == 0)
			ctx->cLocal = v;  /// use update 
        }
	if(ctx->cLocal != NULL)
		ctx->cLocal->etbCn.nEtbnCst = pCnCst;
	return pCnCst;
}
uint8_t
zl_ttdpd_topology_get_nEtbnCst(zl_ttdpd_connectivity_list_t *plist, uuid_t CstUUID)
{
        assert(plist != NULL);
        uint8_t nEtbnCst = 0;
        struct list_head *pos, *q;
         list_for_each_prev_safe (pos, q, &plist->list) {
                zl_ttdpd_connectivity_list_t *v = list_entry(pos, zl_ttdpd_connectivity_list_t, list);
                if(uuid_compare(v->etbCn.CstUUID, CstUUID) == 0)
                {
                        nEtbnCst++;//
                }

        }
        return nEtbnCst;
}
static void
zl_ttdp_ev_topology_timeout_cb(evutil_socket_t fd, short what, void *uData) {
        //check init all
        zl_log_info(" -> Process <- ...\n");
	zl_ttdpd_t* ctx = zl_zl_ttdpd_get();
        zl_ttdpd_connectivity_list_t *v = (zl_ttdpd_connectivity_list_t *)(uData);
	uint8_t tmpaddr[ETH_ALEN] = { 0, };
	if(memcmp(ctx->ifaddr, v->connectivity.mac, ETH_ALEN ) == 0
		|| memcmp(v->connectivity.mac, tmpaddr, ETH_ALEN ) == 0)
	{
		return;
	}
	if(v->flag_Topotimeout == 0)
	{
		v->flag_Topotimeout = 1;
	        struct timeval tvo = {0, 400000};     // timeout to send
		event_add(v->timeout_topo_event, &tvo);
		return;
	}
       
        if(v->flag_Topotimeout)
        {
		printf("-------------- ->[DEL]<- [" ZL_MACSTR "] \n",  ZL_MACVAL(v->connectivity.mac));
		zl_ttdpd_connectivity_del(ctx, v);
                ///
        }
}

void 
zl_ttdpd_connectivity_list_add(zl_ttdpd_t *ctx, zl_ttdpd_connectivity_t *data, uint8_t pNum, zl_ttdp_etb_cn_t *etbCn) {
	assert(ctx->cList != NULL);
	data->reserved = 0;
	zl_ttdpd_connectivity_list_t *v = (zl_ttdpd_connectivity_list_t *)malloc(sizeof(zl_ttdpd_connectivity_list_t));
	v->numEtb = pNum;
	printf(" (%d) ------------- ->[ADD]<- [" ZL_MACSTR "] -ifaddr =[" ZL_MACSTR "] pNum = %d\n", __LINE__, ZL_MACVAL(data->mac), ZL_MACVAL(ctx->ifaddr), pNum);	
	v->flag_Topotimeout = 0;
	v->timeout_topo_event = event_new(ctx->g_base, -1, 0, zl_ttdp_ev_topology_timeout_cb, v);
	event_active(v->timeout_topo_event, EV_TIMEOUT, 1);
	memcpy(&v->etbCn, etbCn, sizeof(zl_ttdp_etb_cn_t));
	memcpy(&v->connectivity, data, sizeof(zl_ttdpd_connectivity_t));
	list_add(&(v->list), &(ctx->cList->list));
}

#if 0
void
zl_ttdpd_connectivity_list_add_sort (zl_ttdpd_t *ctx, zl_ttdpd_connectivity_t *data, uint8_t pNum, zl_ttdp_etb_cn_t *etbCn)
{
	assert(ctx->cList != NULL);
	struct list_head *pos, *q;
	uint8_t i;
	zl_ttdpd_connectivity_list_t *v = NULL;
	data->reserved = 0;
	list_for_each_prev_safe(pos, q, &ctx->cList->list) 
	{
		v = list_entry(pos, zl_ttdpd_connectivity_list_t, list);
		if(v->numEtb == pNum)
		{
			memcpy(&v->connectivity, data, sizeof(zl_ttdpd_connectivity_t));
			memcpy(&v->etbCn, etbCn, sizeof(zl_ttdp_etb_cn_t));
		}
	}
	if(v == NULL)
	{
		zl_ttdpd_connectivity_list_add(ctx, data, pNum, etbCn);
		return;
	}
	if(v->numEtb < pNum)
	{
		for(i = v->numEtb+1; i <= pNum; i++)
		{
			if(i < pNum)
			{
				zl_ttdpd_connectivity_t tmpCon;
				memset(tmpCon.mac, 0, ETH_ALEN);
				tmpCon.orientation = 0;
				tmpCon.reserved = 0;
				zl_ttdpd_connectivity_list_add(ctx, &tmpCon, i, etbCn);
			}else
			{
				zl_ttdpd_connectivity_list_add(ctx, data, i, etbCn);
			}
		}
	}

}
#else
void
zl_ttdpd_connectivity_list_add_sort (zl_ttdpd_t *ctx, zl_ttdpd_connectivity_t *data, uint8_t pNum, zl_ttdp_etb_cn_t *etbCn)
{
        assert(ctx->cList != NULL);
        struct list_head *pos, *q;
        //uint8_t i;
        zl_ttdpd_connectivity_list_t *v = NULL;
	data->reserved = 0;
	zl_ttdpd_connectivity_t data_tmp;
	zl_ttdp_etb_cn_t etbCn_tmp;
	uuid_t CstUUID;
	memcpy(CstUUID, etbCn->CstUUID, 16);
	uint8_t pNum_tmp;
        list_for_each_prev_safe(pos, q, &ctx->cList->list)
        {
		v = list_entry(pos, zl_ttdpd_connectivity_list_t, list);
		if(v->numEtb > pNum)
		{
			memcpy(&data_tmp, &v->connectivity, sizeof(zl_ttdpd_connectivity_t));
			memcpy(&etbCn_tmp, &v->etbCn, sizeof(zl_ttdp_etb_cn_t));
			pNum_tmp = v->numEtb;
			
			v->numEtb = pNum;
			memcpy(&v->connectivity, data, sizeof(zl_ttdpd_connectivity_t));
			memcpy(&v->etbCn, etbCn, sizeof(zl_ttdp_etb_cn_t));
			
			pNum = pNum_tmp;
			memcpy(data, &data_tmp, sizeof(zl_ttdpd_connectivity_t));
			memcpy(etbCn, &etbCn_tmp,sizeof(zl_ttdp_etb_cn_t));
		}
        }
        if(v == NULL)
        {
                zl_ttdpd_connectivity_list_add(ctx, data, pNum, etbCn);
                return;
        }
        if(v->numEtb < pNum)
        {
//                for(i = v->numEtb+1; i <= pNum; i++)
                {
                  zl_ttdpd_connectivity_list_add(ctx, data, pNum, etbCn);
                }
        }

}
#endif

/// --------------------------------------
zl_ttdpd_directory_cn_list_t *
zl_ttdpd_directory_cn_list_init(void) {
  zl_ttdpd_directory_cn_list_t *ctx = (zl_ttdpd_directory_cn_list_t *)malloc(sizeof(zl_ttdpd_directory_cn_list_t));
  assert(ctx != NULL);
  INIT_LIST_HEAD(&ctx->list);
  return ctx;
}
void
zl_ttdpd_directory_cn_list_free(zl_ttdpd_directory_cn_list_t *plist) {
  assert(plist != NULL);
  zl_ttdpd_directory_cn_list_clean(plist);
  free(plist);
}
void
zl_ttdpd_directory_cn_list_clean(zl_ttdpd_directory_cn_list_t *plist) {
  assert(plist != NULL);
  struct list_head *pos, *q;
  list_for_each_safe(pos, q, &plist->list) {
    zl_ttdpd_directory_cn_list_t *v = list_entry(pos, zl_ttdpd_directory_cn_list_t, list);
    list_del(pos);
    free(v);
  }
}
zl_ttdpd_directory_cn_list_t*
zl_ttdpd_directory_cn_list_add(zl_ttdpd_directory_cn_list_t *plist, zl_ttdpd_directory_sub_t *pCnSub, zl_ttdp_etb_cn_t *etbCn) {
	assert(plist != NULL);
        zl_ttdpd_directory_cn_list_t *v = (zl_ttdpd_directory_cn_list_t *)malloc(sizeof(zl_ttdpd_directory_cn_list_t));
	v->hostIp = 0;
        memcpy(&v->directory, pCnSub, sizeof(zl_ttdpd_directory_cn_list_t));
        memcpy(&v->etbCn, etbCn, sizeof(zl_ttdp_etb_cn_t));
        list_add(&(v->list), &(plist->list));
	return v;
}

/// --------------------------------------
zl_ttdpd_connectivity_list_sort_t *
zl_ttdpd_connectivity_list_sort_init(void) {
        zl_ttdpd_connectivity_list_sort_t *pCon = (zl_ttdpd_connectivity_list_sort_t *)malloc(sizeof(zl_ttdpd_connectivity_list_sort_t));
        assert(pCon != NULL);
        INIT_LIST_HEAD(&pCon->list);
        return pCon;
}

void
zl_ttdpd_connectivity_list_sort_clean(zl_ttdpd_connectivity_list_sort_t *plist) {
        assert(plist != NULL);
        struct list_head *pos, *q;
        list_for_each_safe(pos, q, &plist->list) {
                        zl_ttdpd_connectivity_list_sort_t *v = list_entry(pos, zl_ttdpd_connectivity_list_sort_t, list);
                        list_del(pos);
                   ///clean more
                        free(v);
        }
}

void
zl_ttdpd_connectivity_list_sort_free(zl_ttdpd_connectivity_list_sort_t *plist) {
        assert(plist != NULL);
        zl_ttdpd_connectivity_list_sort_clean(plist);
	free(plist);
} 


/// --------------------------------------

void
zl_ttdp_uuid_print(uuid_t pCstUUID)
{
        char uuid_str[37];
        uuid_unparse_lower(pCstUUID, uuid_str);
        printf("uuid=%s\n", uuid_str);
}

/// --------------------------------------
zl_ttdpd_t *
zl_ttdpd_init(void) {
	zl_ttdpd_t *v = (zl_ttdpd_t *)malloc(sizeof(zl_ttdpd_t));
	assert(v != NULL);
	memset(v, 0, sizeof(zl_ttdpd_t));
	v->pDir1 = NULL;
	v->pDir2 = NULL;
	v->cLocal = NULL;
	v->cList = zl_ttdpd_connectivity_list_init();
	v->dList = zl_ttdpd_directory_cn_list_init();
	v->pList = zl_port_init();
	v->fList = zl_fdb_list_init();
	zl_ttdpd_event_init(v);	// init event
	v->flagTopology = 0;
        v->flagHello = 0;//port later

	return v;
}
void 
zl_ttdpd_free(zl_ttdpd_t *ctx) {
	assert(ctx != NULL);
	if(ctx->cList) {
		zl_ttdpd_connectivity_list_free(ctx->cList);
	}
	if(ctx->dList) {
		zl_ttdpd_directory_cn_list_free(ctx->dList);
	}
	if(ctx->pList) {
		zl_port_free(ctx->pList);
	}
	if(ctx->fList) {
		zl_fdb_list_free(ctx->fList);
	}
	zl_ttdpd_event_free(ctx);
}

zl_port_t *
zl_ttdp_update_subnet_local_interface(zl_ttdpd_t *ctx,  zl_ttdpd_directory_cn_list_t *pDir)
{
	zl_port_t *v;
        struct list_head *pos, *q;
        list_for_each_safe(pos, q, &ctx->pList->list) {
                v = list_entry(pos, zl_port_t, list);
		if(v->cnId == pDir->directory.CnId && v->direction == ZL_PORT_DIR_CN) {
                        v->SubnetId = pDir->directory.SubnetId;
			v->hostIp = pDir->hostIp;
			return v;
                }
        }
	return NULL;
}

uint32_t
zl_ttdp_checksum_directory(zl_ttdpd_t *ctx)//zl_ttdpd_directory_cn_list_t *plist)
{
	assert(ctx->dList != NULL);
	void *buff = zl_calloc(1, sizeof(void));
	int n_bytes = 0;
	uint32_t csum = 0;
 	struct list_head *pos, *q;
	 list_for_each_safe(pos, q, &ctx->dList->list) {
	    	zl_ttdpd_directory_cn_list_t *v = list_entry(pos, zl_ttdpd_directory_cn_list_t, list);
		zl_ttdp_uuid_print(v->directory.CstUUID);
		if(uuid_compare(v->directory.CstUUID, ctx->cfx.CstUUID) == 0
			&& v->directory.EtbnId == ctx->cfx.EtbnId) ///update subnet id to port cn
		{
			zl_ttdp_update_subnet_local_interface(ctx, v);
		}
		buff = zl_realloc(buff, n_bytes + sizeof(zl_ttdpd_directory_sub_t));
		memcpy(buff + n_bytes, &v->directory, sizeof(zl_ttdpd_directory_sub_t));
		n_bytes += sizeof(zl_ttdpd_directory_sub_t);
	}
#if 0
  	list_for_each_safe(pos, q, &plist->list) {
    	zl_ttdpd_directory_cn_list_t *v = list_entry(pos, zl_ttdpd_directory_cn_list_t, list);
		buff = zl_realloc(buff, n_bytes + sizeof(zl_ttdpd_directory_t));
		memcpy(buff + n_bytes, &v->directory, sizeof(zl_ttdpd_directory_t));
		n_bytes += sizeof(zl_ttdpd_directory_t);
  	}
#endif
	if(n_bytes > 0)
		csum = get_xcrc32(buff, n_bytes);
	return csum;
}

void
zl_ttdp_directory_update_local(zl_ttdpd_connectivity_list_t *pLocal, zl_ttdp_etb_cn_t *etbCn)
{
	int i;
	etbCn->nCnCst = pLocal->etbCn.nCnCst;
	
	for(i = 0; i < pLocal->etbCn.nEtbnCst; i++)
	{
		etbCn->cnToEtbnList[i] = pLocal->etbCn.cnToEtbnList[i];
	}
	//// more////
}

zl_ttdpd_directory_cn_list_t*
zl_ttdp_directory_sort(zl_ttdpd_t *ctx, zl_ttdpd_directory_sub_t *pCnSub, zl_ttdp_etb_cn_t *etbCn)
{
	assert(ctx->dList != NULL);
        struct list_head *pos, *q;
	//int i;
        zl_ttdpd_directory_sub_t tmpNext;
	zl_ttdp_etb_cn_t tmbEtbCn;
        zl_ttdpd_directory_cn_list_t *v = NULL;
        list_for_each_prev_safe(pos, q, &ctx->dList->list)
        {
                v = list_entry(pos, zl_ttdpd_directory_cn_list_t, list);
		//update diclocal
		if(ctx->cfx.EtbnId == v->directory.EtbnId)
		{
			if(ctx->cLocal != NULL)
				zl_ttdp_directory_update_local(ctx->cLocal, &v->etbCn);
		}
		if(pCnSub->cstOrientation == 1)
		{
			if(uuid_compare(v->directory.CstUUID, pCnSub->CstUUID) > 0 
				|| ((uuid_compare(v->directory.CstUUID, pCnSub->CstUUID) == 0) && (v->directory.CnId > pCnSub->CnId))
				|| ((uuid_compare(v->directory.CstUUID, pCnSub->CstUUID) == 0) && (v->directory.CnId == pCnSub->CnId) && (v->directory.EtbnId > pCnSub->EtbnId)))
			{
				memcpy(&tmpNext, &v->directory, sizeof(zl_ttdpd_directory_sub_t));
				memcpy(&tmbEtbCn, &v->etbCn, sizeof(zl_ttdp_etb_cn_t));
				
				memcpy(&v->directory, pCnSub, sizeof(zl_ttdpd_directory_sub_t));
				memcpy(&v->etbCn, etbCn, sizeof(zl_ttdp_etb_cn_t));


				memcpy(pCnSub, &tmpNext, sizeof(zl_ttdpd_directory_sub_t));
				memcpy(etbCn, &tmbEtbCn, sizeof(zl_ttdp_etb_cn_t));
			}else if((uuid_compare(v->directory.CstUUID, pCnSub->CstUUID) == 0) && (v->directory.CnId == pCnSub->CnId) && (v->directory.EtbnId == pCnSub->EtbnId))
			{
				memcpy(&v->directory, pCnSub, sizeof(zl_ttdpd_directory_sub_t));
				memcpy(&v->etbCn, etbCn, sizeof(zl_ttdp_etb_cn_t));
				return v;
			}
		}else if(pCnSub->cstOrientation == 2)
                {
                        if(uuid_compare(v->directory.CstUUID, pCnSub->CstUUID) > 0
                                || ((uuid_compare(v->directory.CstUUID, pCnSub->CstUUID) == 0) && (v->directory.CnId < pCnSub->CnId))
                                || ((uuid_compare(v->directory.CstUUID, pCnSub->CstUUID) == 0) && (v->directory.CnId == pCnSub->CnId) && (v->directory.EtbnId > pCnSub->EtbnId)))
                        {
				memcpy(&tmpNext, &v->directory, sizeof(zl_ttdpd_directory_sub_t));
                                memcpy(&tmbEtbCn, &v->etbCn, sizeof(zl_ttdp_etb_cn_t));

                                memcpy(&v->directory, pCnSub, sizeof(zl_ttdpd_directory_sub_t));
                                memcpy(&v->etbCn, etbCn, sizeof(zl_ttdp_etb_cn_t));


                                memcpy(pCnSub, &tmpNext, sizeof(zl_ttdpd_directory_sub_t));
                                memcpy(etbCn, &tmbEtbCn, sizeof(zl_ttdp_etb_cn_t));

                        }else if((uuid_compare(v->directory.CstUUID, pCnSub->CstUUID) == 0) && (v->directory.CnId == pCnSub->CnId) && (v->directory.EtbnId == pCnSub->EtbnId))
                        {
                                memcpy(&v->directory, pCnSub, sizeof(zl_ttdpd_directory_sub_t));
				memcpy(&v->etbCn, etbCn, sizeof(zl_ttdp_etb_cn_t));
                                return v;
                        }
                }
        }
        if(v == NULL)
        {
		v = zl_ttdpd_directory_cn_list_add(ctx->dList, pCnSub, etbCn);
		return v;
        }
	if(uuid_compare(v->directory.CstUUID, pCnSub->CstUUID) < 0)
//		|| (uuid_compare(v->directory.CstUUID, pCnSub->CstUUID) == 0 &&  v->directory.CnId < pCnSub->CnId))
        {
		zl_ttdpd_directory_cn_list_add(ctx->dList, pCnSub, etbCn);
	}else if(uuid_compare(v->directory.CstUUID, pCnSub->CstUUID) == 0)
	{
		if(pCnSub->cstOrientation == 1)
		{
			if((v->directory.CnId < pCnSub->CnId)
				|| ((v->directory.CnId == pCnSub->CnId) && (v->directory.EtbnId < pCnSub->EtbnId)))
			{
				zl_ttdpd_directory_cn_list_add(ctx->dList, pCnSub, etbCn);
			}
		}else if(pCnSub->cstOrientation == 2)
                {
                        if((v->directory.CnId > pCnSub->CnId)
				||((v->directory.CnId == pCnSub->CnId) && (v->directory.EtbnId < pCnSub->EtbnId)))
			{
                                zl_ttdpd_directory_cn_list_add(ctx->dList, pCnSub, etbCn);
			}
                }
	}
	return NULL; ///
}
uint8_t
zl_ttdpd_directory_check_subid(zl_ttdpd_directory_sub_t *directory, zl_ttdp_etb_cn_t *etbCn)
{
	int i, cnCount = 0;
	for(i = 0; i < etbCn->nEtbnCst; i ++)
	{
		if(isNthBitSet(etbCn->cnToEtbnList[i], directory->CnId-1) == 1)
		{
			cnCount++;
		}
	}
	return cnCount;
}

void
zl_ttdpd_directory_cn_list_print(zl_ttdpd_directory_cn_list_t *plist) {
        assert(plist != NULL);
        struct list_head *pos, *q;
	printf("		%-30s %8s %10s %10s %16s\n","CstUUID", "CN Id", "SubNet Id", "ETB Id", "CstOrientation");
//	printf("	----------------------------------------------------------------------------------------------\n");
        list_for_each_prev_safe(pos, q, &plist->list) {
                zl_ttdpd_directory_cn_list_t *v = list_entry(pos, zl_ttdpd_directory_cn_list_t, list);
		char uuid_str[37];
        	uuid_unparse_lower(v->directory.CstUUID, uuid_str);
                //zl_ttdp_uuid_print(v->directory.CstUUID);
		printf("	%36s	%5d %10d %10d %12d\n", uuid_str,v->directory.CnId, v->directory.SubnetId, v->directory.EtbnId, v->directory.cstOrientation);
//		printf("	----------------------------------------------------------------------------------------------\n");
        }
}

void
zl_ttdpd_directory_cn_list_getsubnetid(zl_ttdpd_directory_cn_list_t *plist) {
	assert(plist != NULL);
	struct list_head *pos, *q;
	uint8_t pSubIdPre = 0, pCnCurr = 0, pCnIpCurr = 0;
  	list_for_each_prev_safe(pos, q, &plist->list) {
    		zl_ttdpd_directory_cn_list_t *v = list_entry(pos, zl_ttdpd_directory_cn_list_t, list);
		v->hostIp = 1;
		if(pSubIdPre == 0)
		{
			v->directory.SubnetId = 1;
		}else
		{
#if 0
			if(v->etbCn.nEtbnCst == 1 && v->etbCn.nCnCst == 1)
			{
				 v->directory.SubnetId =  v->directory.EtbnId;
			}else
#endif
			{
				if(zl_ttdpd_directory_check_subid(&v->directory, &v->etbCn) > 1)
				{
					if(v->directory.CnId == pCnCurr)
					{
						v->directory.SubnetId = pSubIdPre;
						v->hostIp = pCnIpCurr+1;
					}else
					{
						v->directory.SubnetId = pSubIdPre+1;
					}
				}else
				{
					v->directory.SubnetId = pSubIdPre + 1;
				}
			}
						
		}
		pCnCurr = v->directory.CnId;
		pSubIdPre = v->directory.SubnetId;
		pCnIpCurr = v->hostIp;
		zl_ttdp_uuid_print(v->directory.CstUUID);
  	}
}
uint8_t
zl_ttdp_directory_check_ebtnum_consist(zl_ttdpd_t *ctx, uint8_t nEtbnCst, uuid_t CstUUID)
{
	assert(ctx->cList != NULL);
        struct list_head *pos, *q;
        zl_ttdpd_connectivity_list_t *v = NULL;
        list_for_each_prev_safe(pos, q, &ctx->cList->list)
        {
		v = list_entry(pos, zl_ttdpd_connectivity_list_t, list);
		if(v->etbCn.flagIni == 0)
		{
			return 0;
		}
	}
	return 1;
}
void
zl_ttdp_directory_table(zl_ttdpd_t *ctx)
{
	assert(ctx->cList != NULL);
        struct list_head *pos, *q;
	int i;
//        uint8_t fLagSort = 0;
        zl_ttdpd_connectivity_list_t *v = NULL;
        list_for_each_prev_safe(pos, q, &ctx->cList->list)
        {
                v = list_entry(pos, zl_ttdpd_connectivity_list_t, list);
		zl_ttdpd_directory_sub_t pCnSub;
		zl_ttdp_etb_cn_t etbCn;
		memcpy(&etbCn, &v->etbCn, sizeof(zl_ttdp_etb_cn_t));
		memcpy(pCnSub.CstUUID, v->etbCn.CstUUID, 16);
		pCnSub.SubnetId =  v->etbCn.SubnetId;
		pCnSub.EtbnId = v->numEtb+1;
		pCnSub.cstOrientation = v->etbCn.orientationCst;
		for(i = 0; i < 32; i++)
                {
                        if(isNthBitSet(v->etbCn.pCnEtb, i) == 1)
                        {
				pCnSub.CnId = i+1;
				zl_ttdp_directory_sort(ctx, &pCnSub, &etbCn);
                        }
                }
        }
	zl_ttdpd_directory_cn_list_getsubnetid(ctx->dList);
	ctx->EtbTopoCnt = zl_ttdp_checksum_directory(ctx);
			zl_ttdpd_directory_cn_list_print(ctx->dList);
//exit(0);
}



void
zl_ttdpd_connectivity_list_add_etb(zl_ttdpd_connectivity_list_sort_t *pList, const zl_ttdpd_connectivity_t *data, uint8_t pNum) {
        assert(pList != NULL);
//        data->reserved = 0;
        zl_ttdpd_connectivity_list_sort_t *v = (zl_ttdpd_connectivity_list_sort_t *)malloc(sizeof(zl_ttdpd_connectivity_list_sort_t));
        v->numEtb = pNum;
        memcpy(&v->connectivity, data, sizeof(zl_ttdpd_connectivity_t));
	v->connectivity.reserved = 0;
        list_add(&(v->list), &(pList->list));
}

/// create new
void
zl_ttdpd_connectivity_list_add_sort_etb(zl_ttdpd_connectivity_list_sort_t *pList, const zl_ttdpd_connectivity_list_t *data)
{
        assert(pList != NULL);
        struct list_head *pos, *q;
//        uint8_t fLagSort = 0;
	zl_ttdpd_connectivity_list_sort_t tmpNext;
	zl_ttdpd_connectivity_list_sort_t tmpCurr;
	tmpCurr.numEtb = data->numEtb;
        memcpy(&tmpCurr.connectivity, &data->connectivity, sizeof(zl_ttdpd_connectivity_t));
	zl_ttdpd_connectivity_list_sort_t *v = NULL;
        list_for_each_prev_safe(pos, q, &pList->list)
        {
                v = list_entry(pos, zl_ttdpd_connectivity_list_sort_t, list);
                if(v->numEtb > tmpCurr.numEtb)
                {
			tmpNext.numEtb = v->numEtb;	
			memcpy(&tmpNext.connectivity, &v->connectivity, sizeof(zl_ttdpd_connectivity_t));

			v->numEtb = tmpCurr.numEtb;
                        memcpy(&v->connectivity, &tmpCurr.connectivity, sizeof(zl_ttdpd_connectivity_t));

			tmpCurr.numEtb = tmpNext.numEtb;
			memcpy(&tmpCurr.connectivity, &tmpNext.connectivity, sizeof(zl_ttdpd_connectivity_t));	
                }
        }
        if(v == NULL)
        {
                zl_ttdpd_connectivity_list_add_etb(pList, &tmpCurr.connectivity, tmpCurr.numEtb);
		return;
        }
	if(v->numEtb < tmpCurr.numEtb) //<=
	{
		zl_ttdpd_connectivity_list_add_etb(pList, &tmpCurr.connectivity, tmpCurr.numEtb);
	}
#if 0
	if(fLagSort == 0)
	{
		if(v->numEtb < data->numEtb)
		{
			zl_ttdpd_connectivity_list_add_etb(pList, &data->connectivity, data->numEtb);
		}
	}else if(fLagSort > 0)
	{
		if(v->numEtb < tmpNext.numEtb)
                {
                        zl_ttdpd_connectivity_list_add_etb(pList, &tmpNext.connectivity, tmpNext.numEtb);
                }
	}
#endif

}


#if 1
//update check sum and update etbs in consist
uint32_t
zl_ttdp_checksum_connectivity(zl_ttdpd_t *ctx)
{
  assert(ctx->cList != NULL);
  void *buff = zl_calloc(1, sizeof(void));
  int n_bytes = 0;
  uint32_t csum = 0;
  struct list_head *pos, *q;
	ctx->cfx.nEtbnCst = 0;
  list_for_each_safe(pos, q, &ctx->cList->list) {
    zl_ttdpd_connectivity_list_t *v = list_entry(pos, zl_ttdpd_connectivity_list_t, list);
    buff = zl_realloc(buff, n_bytes + sizeof(zl_ttdpd_connectivity_t));
    memcpy(buff + n_bytes, &v->connectivity, sizeof(zl_ttdpd_connectivity_t));
    n_bytes += sizeof(zl_ttdpd_connectivity_t);
	//update num etb in consist
#if 1
	if(uuid_compare(ctx->cfx.CstUUID, v->etbCn.CstUUID) == 0)
	{
		ctx->cfx.nEtbnCst ++; 
	}
#endif
  }
  if(n_bytes > 0)
  {
    csum = get_xcrc32(buff, n_bytes);
    free(buff);
  }
  return csum;
}
#else
uint32_t
zl_ttdp_checksum_connectivity_sort(zl_ttdpd_connectivity_list_sort_t *plist)
{
	  assert(plist != NULL);
	  void *buff = zl_calloc(1, sizeof(void));
	  int n_bytes = 0;
	  uint32_t csum = 0;
	  struct list_head *pos, *q;
	  list_for_each_safe(pos, q, &plist->list) { //list_for_each_prev_safe
	    	zl_ttdpd_connectivity_list_sort_t *v = list_entry(pos, zl_ttdpd_connectivity_list_sort_t, list);
	    	buff = zl_realloc(buff, n_bytes + sizeof(zl_ttdpd_connectivity_t));
	    	memcpy(buff + n_bytes, &v->connectivity, sizeof(zl_ttdpd_connectivity_t));
	    	n_bytes += sizeof(zl_ttdpd_connectivity_t);
	  }
	  if(n_bytes > 0)
	  {
	    	csum = get_xcrc32(buff, n_bytes);
	    	free(buff);
	  }
	  return csum;
}
uint32_t
zl_ttdp_checksum_connectivity(zl_ttdpd_connectivity_list_t *plist)
{
	uint32_t csum = 0;
	zl_ttdpd_connectivity_list_sort_t *pListSort = zl_ttdpd_connectivity_list_sort_init();
	struct list_head *pos, *q;
	list_for_each_safe(pos, q, &plist->list) {
	    	zl_ttdpd_connectivity_list_t *v = list_entry(pos, zl_ttdpd_connectivity_list_t, list);
		zl_ttdpd_connectivity_list_add_sort_etb(pListSort, v);		
	}
	csum = zl_ttdp_checksum_connectivity_sort(pListSort);
	zl_ttdpd_connectivity_list_sort_free(pListSort);
	return csum;
}
#endif

void
zl_ttdp_ttdpd_connectivity_list_default(zl_ttdpd_t *ctx, uint8_t pNum)
{
	zl_ttdpd_connectivity_t con_own;
	zl_ttdp_etb_cn_t etbCn;
	memset(&etbCn, 0, sizeof(zl_ttdp_etb_cn_t));
	memcpy(con_own.mac, ctx->ifaddr, ETH_ALEN);
        con_own.orientation = ctx->cfx.etbOrientation;
        con_own.reserved = 0;
	etbCn.orientationCst = ctx->cfx.cstOrientation;
	memcpy(etbCn.CstUUID, ctx->cfx.CstUUID, 16);
	etbCn.flagCn = 1;
	etbCn.flagIni = 1;
	etbCn.pCnEtb =  ctx->etbCns;//ctx->cfx.CnId; // add bit
	etbCn.nEtbnCst =   1;//ctx->cfx.nEtbnCst;
	etbCn.nCnCst =   ctx->cfx.nCnCst;
	etbCn.cnToEtbnList[0] = etbCn.pCnEtb; //FIRST
        zl_ttdpd_connectivity_list_add(ctx, &con_own,  pNum, &etbCn);
        ctx->ConnTableCrc = zl_ttdp_checksum_connectivity(ctx);
//        ctx->ConnTableCrc = zl_ttdp_checksum_connectivity(ctx->cList);
}

void zl_ttdpd_directory_cn_default(zl_ttdpd_t *ctx)
{
	zl_ttdpd_directory_sub_t pEtbDic;
	zl_ttdp_etb_cn_t etbCn;
	int i;
	memcpy(pEtbDic.CstUUID, ctx->cfx.CstUUID, 16);
	pEtbDic.CnId = 0;
	pEtbDic.SubnetId = ctx->cfx.EtbnId;
	pEtbDic.EtbnId = ctx->cfx.EtbnId; //need update
	pEtbDic.cstOrientation = ctx->cfx.cstOrientation;

	memset(&etbCn, 0, sizeof(zl_ttdp_etb_cn_t));
        memcpy(etbCn.CstUUID, ctx->cfx.CstUUID, 16);
        etbCn.orientationCst = ctx->cfx.cstOrientation;/////////pConnectivity.orientation;
        etbCn.flagCn = 1;
        etbCn.flagIni = 1;
        etbCn.pCnEtb =  ctx->etbCns;//ctx->cfx.CnId; // add bit
        etbCn.nEtbnCst =   ctx->cfx.nEtbnCst;
        etbCn.nCnCst =   ctx->cfx.nCnCst;
        etbCn.cnToEtbnList[0] = ctx->etbCns; //FIRST

        for(i = 0; i < 32; i++)
	{
		if(isNthBitSet(ctx->etbCns, i) == 1)
		{
			pEtbDic.CnId = i+1;
			//zl_ttdpd_directory_cn_list_add(ctx->dList, &pEtbDic, 1);
			zl_ttdp_directory_sort(ctx, &pEtbDic, &etbCn);
		}
	}
	ctx->EtbTopoCnt = zl_ttdp_checksum_directory(ctx);
}

void 
zl_ttdpd_load(zl_ttdpd_t *ctx) {	//
	ctx->etbCns = 0;
	if(zl_cfx_load_file(ctx) != 0) {
		return;
	}
	// add port to bridge
	zl_port_t *t_intf = zl_port_bridge_find(ctx->pList);
	if(t_intf) {
		zl_port_bridge_update(ctx->pList, t_intf->ifname); //not add port CN
		
		zl_ioctl_get_hwaddr(t_intf->ifname, t_intf->ifhwaddr);
		// Update 
		zl_memcpy(ctx->ifname, t_intf->ifname, IFNAMSIZ);
		zl_memcpy(ctx->ifaddr, t_intf->ifhwaddr, ETH_ALEN);
	}
	zl_ttdpd_directory_t *cfx = (zl_ttdpd_directory_t *)&ctx->cfx;
#if 1
	int i;
	fprintf(stderr, "cfx->CstUUID[");
	for(i = 0; i < 16; i++) {
		fprintf(stderr, "0x%.2x ", cfx->CstUUID[i]);
	}
	fprintf(stderr, "]\n");
	//add cn
for(i = 0; i < 32; i++)
{
	if(isNthBitSet(ctx->etbCns, i) == 1)
	{
		printf("i=%d\n", i);
	}
}
//exit(1);
#endif
	char uuid_str[37];      // ex. "1b4e28ba-2fa1-11d2-883f-0016d3cca427" + "\0"
        uuid_unparse_lower(cfx->CstUUID, uuid_str);
	printf("uuid_str: %s\n", uuid_str);
	fprintf(stderr, "cfx->CnId  = [%d]\n", cfx->CnId);
	//////
	cfx->SubnetId = 1;
	cfx->EtbnId = 1;
//	cfx->CstOrientation = 0x01;
	ctx->EtbInhi = 1;
	
	ctx->Inauguration = 1;
	ctx->ConnTableValid = 1;
	ctx->EtbTopoCntValid = 1;
	ctx->cnLengthen = 1;//cnLengthen
	ctx->cnShorten = 1;//cnLengthen
//	ctx->hello_time = 130;
//	ctx->topo_time = 100;
	memcpy(ctx->conVector.mac_own, ctx->ifaddr, ETH_ALEN);
	memset(ctx->conVector.mac_dir1, 0, ETH_ALEN);
	memset(ctx->conVector.mac_dir2, 0, ETH_ALEN);
	
	//add conect table default
	zl_ttdp_ttdpd_connectivity_list_default(ctx, 0);
	//add networ directory
	//zl_ttdpd_directory_cn_default(ctx);
//	zl_ttdpd_directory_cn_list_add(ctx->dList, &ctx->cfx);
	ctx->EtbTopoCnt = zl_ttdp_checksum_directory(ctx);
	ctx->flagHello = 1;
	ctx->flagCn = 0;
}
void 
zl_ttdpd_loop(zl_ttdpd_t *ctx) {
	assert(ctx != NULL);
	zl_ttdpd_event_loop(ctx);

}

zl_fdb_list_t *
zl_fdb_list_init(void) {
        zl_fdb_list_t *ctx = (zl_fdb_list_t *)malloc(sizeof(zl_fdb_list_t));
        assert(ctx != NULL);
        INIT_LIST_HEAD(&ctx->list);
        return ctx;
}
void
zl_fdb_list_free(zl_fdb_list_t *plist) {
        assert(plist != NULL);
        zl_fdb_list_clean(plist);
        free(plist);
}
void
zl_fdb_list_clean(zl_fdb_list_t *plist) {
        assert(plist != NULL);
        struct list_head *pos, *q;
        list_for_each_safe(pos, q, &plist->list) {
                zl_fdb_list_t *v = list_entry(pos, zl_fdb_list_t, list);
                list_del(pos);
                free(v);
        }
}
void
zl_fdb_list_add(zl_fdb_list_t *plist, uint8_t *mac, int ifindex) {
        assert(plist != NULL);
        zl_fdb_list_t *v = (zl_fdb_list_t *)malloc(sizeof(zl_fdb_list_t));
	memcpy(v->mac, mac, ETH_ALEN);
	v->ifindex = ifindex;
        list_add(&(v->list), &(plist->list));
}
void
zl_fdb_list_del(zl_fdb_list_t *plist, uint8_t *mac, int ifindex) {
        assert(plist != NULL);
        struct list_head *pos, *q;
        list_for_each_safe(pos, q, &plist->list) {
                zl_fdb_list_t *v = list_entry(pos, zl_fdb_list_t, list);
		if((memcmp(v->mac, mac, ETH_ALEN) == 0) && (v->ifindex == ifindex)) {
			list_del(pos);
			free(v);
			break;
		}
        }
}
zl_fdb_list_t *
zl_fdb_list_find(zl_fdb_list_t *plist, uint8_t *mac) {
	assert(plist != NULL);
	struct list_head *pos, *q;
        list_for_each_safe(pos, q, &plist->list) {
		zl_fdb_list_t *v = list_entry(pos, zl_fdb_list_t, list);
		if(!memcmp(v->mac, mac, ETH_ALEN)) {
			return v;
		}
	}
	return NULL;
}

zl_fdb_list_t *
zl_fdb_list_index_find(zl_fdb_list_t *plist, int ifindex) {
        assert(plist != NULL);
        struct list_head *pos, *q;
        list_for_each_safe(pos, q, &plist->list) {
                zl_fdb_list_t *v = list_entry(pos, zl_fdb_list_t, list);
                if(v->ifindex == ifindex) {
                        return v;
                }
        }
        return NULL;
}
