#include <zl-comm.h>
#include <zl-ttdp.h>
#include <tlv.h>
#include <zl-mem.h>
#include <zl-ttdp.h>
#include <zl-tlv-core.h>
#include <zl-ports.h>
#include <zl-ioctl.h>

void
zl_ttdpd_hello_log(zl_tlv_hello_t *hello_val)
{
	int i;
	 printf("hello_val->oui: ");
	for(i = 0; i < sizeof(hello_val->oui); i++)
	{
		printf("0x%02x ", hello_val->oui[i]);
		
	}
	printf("\n");
	printf("hello_val->subtype = %02x\n", hello_val->subtype);
	printf("hello_val->version = %x\n", ntohl(hello_val->version));
 	 printf("hello_val->lifesign = %d\n", ntohl(hello_val->lifesign));
  	printf("hello_val->etb_topo_cnt = %x\n", ntohl(hello_val->etb_topo_cnt));
	printf("hello_val->vendor = %s\n", hello_val->vendor);
//  printf("hello_val->line = %d \n", hello_val->line);
	printf("hello_val->recs_astatus = %d\n", hello_val->recs_astatus);
	printf("hello_val->recs_astatus = %d\n", hello_val->recs_bstatus);
	printf("hello_val->recs_astatus = %d\n", hello_val->recs_bstatus);
	printf("hello_val->recs_astatus = %d\n", hello_val->recs_cstatus);
	printf("hello_val->timeout_management = %d\n", hello_val->timeout_management);
	 printf("hello_val->sourceid ");
	for(i = 0; i < sizeof(hello_val->src_id); i++)
	{
		printf(" %02x ", hello_val->src_id[i]);
		
	}
	printf("\n");
	printf("hello_val->source_etbn_port = %d\n", hello_val->src_port_id);
	printf("hello_val->egressline = %d\n", hello_val->egressline);
	printf("hello_val->egress_direction = %d\n", hello_val->egress_dir);
	printf("hello_val->remoteid: ");
	for(i = 0; i < sizeof(hello_val->remoteid); i++)
	{
		printf("%02x ", hello_val->remoteid[i]);
		
	}
	zl_ttdp_uuid_print(hello_val->cstuuid);
#if 0
	 printf("\n");
	 printf("hello_val->cstuuid: ");
	for(i = 0; i < sizeof(hello_val->cstuuid); i++)
	{
		printf("0x%02x ", hello_val->cstuuid[i]);
		
	}
	 printf("\n");
#endif
	printf("hello_val->inaugurationflag = %d\n", hello_val->inaugh_init);
	printf("hello_val->reserved = %d\n", hello_val->reserved1);
//	printf("hello_val->franechecsequence = 0x%x \n", hello_val->franechecsequence);
}


void 
zl_ttdpd_hello_decode(zl_ttdpd_t *ctx, void *uData, const uint8_t *src_addr, void *data, size_t size) {
	// TODO: More

	zl_tlv_t *tlist = zl_tlv_decode(data, size);
	zl_tlv_t *n;
//	int i;
	while((n = zl_tlv_pop(tlist)) != NULL) {
	if(n->type == 0x01)
	{
		zl_tlv_chassis_id_t chassis_val;
		zl_memcpy(&chassis_val, n->data, n->length);	
	}else if(n->type == 0x02)
	{
		zl_tlv_port_id_t port_val;
	    	zl_memcpy(&port_val, n->data, n->length);
	}else if(n->type == 0x03)
	{
		zl_tlv_ttl_t ttl_val;
		zl_memcpy(&ttl_val, n->data, n->length);
	}else if(n->type == 0x7f)
	{
		zl_port_t *v = (zl_port_t *)(uData);    //port info
		zl_tlv_hello_t hello_val;
		zl_memcpy(&hello_val, n->data, n->length);
	//	hello_val.version = ntohs(hello_val.version);
		//hello_val.lifesign = ntohs(hello_val.version);
	//  hello_val.etb_topo_cnt = ntohs(hello_val.etb_topo_cnt);
	 // hello_val.franechecsequence = htons(hello_val.franechecsequence);
		//zl_ttdpd_hello_log(&hello_val);
		//check crc
		if(v->direction == ZL_PORT_DIR_LEFT)
		{
			memcpy(ctx->conVector.mac_dir1, hello_val.src_id, ETH_ALEN);
		}else if(v->direction == ZL_PORT_DIR_RIGHT)
                {
                        memcpy(ctx->conVector.mac_dir2, hello_val.src_id, ETH_ALEN);
                }
		v->InaugInhi = 2; 
		v->timeOutHello = hello_val.timeout_management;
		memcpy(v->remoteMac, hello_val.src_id, ETH_ALEN);
//		gettimeofday(&v->curr_time, NULL);
		
		if(hello_val.timeout_management == ZL_HELLO_TIMEOUT_FAST)
		{
			//send hello now.
			 v->timeOutHello = ZL_HELLO_TIMEOUT_SLOW; ///send slow
			zl_send_hello_fast(uData);
//			zl_ttdp_ev_hello_time_cb(-1, 0, uData);
		}			
		
		struct timeval tvo = {0, ZL_HELLO_TIMEOUT_SLOW*1000};     // timeout to send 15
                event_add(v->time_event_hello_timeout, &tvo);
		v->flag_timeout = 1;
		v->timeHello = ZL_HELLO_TIME_SLOW;
	}	
	zl_free(n->data);
	zl_free(n);
	}
//	free(data);	
}

#if 0
void
zl_ttdp_vector_table_update_etbnum(zl_ttdpd_t *ctx, zl_tlv_etb_t *tlvetb)
{
	zl_ttdpd_connectivity_list_t *v = zl_ttdpd_connectivity_list_find(ctx->cList, tlvetb->own_macaddress);
	if(v != NULL)
        {
                if(v->connectivity.orientation == ctx->cfx.etbOrientation)
                {
                        //remote
			v->numEtb = tlvetb->ndir1_etbn;
                        //local
                }else if(v->connectivity.orientation != ctx->cfx.etbOrientation)
                {
                        if(ctx->cfx.etbOrientation == 2)
                        {
				v->numEtb = tlvetb->ndir1_etbn;
                        }else if (ctx->cfx.etbOrientation == 1)
                        {
				v->numEtb = tlvetb->ndir2_etbn;
                        }

                }
        }
}
#endif

void
zl_ttdp_topo_set_ip_etbn(zl_ttdpd_t *ctx)
{
        uint32_t ip = zl_ttdpd_etbn_address(0, 1, ctx->cfx.EtbnId);
        struct sockaddr_in newsin;
        struct sockaddr_in oldsin;
         memset(&newsin, 0, sizeof(struct sockaddr));
         memset(&oldsin, 0, sizeof(struct sockaddr));
        newsin.sin_family = AF_INET;
        newsin.sin_addr.s_addr = ntohl(ip);
        zl_ioctl_get_addr(ctx->ifname, &oldsin);
    //    printf("ConnTableCrc=%d and The IP address is %s %s\n", ctx->ConnTableCrc, inet_ntoa(newsin.sin_addr), ctx->ifname);
//        if(memcmp(&oldsin, &newsin, sizeof(struct sockaddr_in)) == 0)
 //               return;
        zl_ioctl_set_addr (ctx->ifname, &newsin);
}

void
zl_ttdp_topo_set_ip_cn_port(const char *ifname, uint8_t SubnetId, uint8_t hostIp)
{
  //      uint32_t ip = zl_ttdpd_etbn_address(0, ctx->cLocal.etbCn.SubnetId, ctx->cfx.SubnetId);
        uint32_t ip = zl_ttdpd_etbn_subnet_address(0, SubnetId, hostIp);
        struct sockaddr_in newsin;
        struct sockaddr_in oldsin;
        memset(&newsin, 0, sizeof(struct sockaddr));
        memset(&oldsin, 0, sizeof(struct sockaddr));
        newsin.sin_family = AF_INET;
        newsin.sin_addr.s_addr = ntohl(ip);
        zl_ioctl_get_addr(ifname, &oldsin);
        printf("	IP address CN is %s - Interface: %s \n", inet_ntoa(newsin.sin_addr), ifname);
        if(memcmp(&oldsin, &newsin, sizeof(struct sockaddr_in)) == 0)
                return;
        zl_ioctl_set_addr (ifname, &newsin);
}

void
zl_ttdp_topo_set_ip_cn(zl_ttdpd_t *ctx)
{
	zl_port_t *v;
        struct list_head *pos, *q;
	printf("\n");
        list_for_each_safe(pos, q, &ctx->pList->list) {
                v = list_entry(pos, zl_port_t, list);
		if(v->direction == ZL_PORT_DIR_CN)
			zl_ttdp_topo_set_ip_cn_port(v->ifname, v->SubnetId, v->hostIp);
        }
}

uint8_t
zl_ttdp_vector_list_check(zl_ttdpd_t *ctx, zl_port_t *pPort, uint8_t *mac)
{
	if(ctx->pDir1 == NULL || ctx->pDir2 == NULL)
	{
		if(zl_etb_vector_list_find(pPort->vList, mac) == NULL)
			return 0;

	}else
	{
		if(zl_etb_vector_list_find(ctx->pDir1->vList, mac) == NULL && zl_etb_vector_list_find(ctx->pDir2->vList, mac) == NULL)
			return 0;
	}
	return 1;
}
void
zl_ttdp_ttdpd_connectivity_local(zl_ttdpd_t *ctx, zl_ttdpd_connectivity_t *con_own, uint8_t pNum, zl_ttdp_etb_cn_t *etbCn)
{
	memset(con_own, 0, sizeof(zl_ttdpd_connectivity_t));
	memset(etbCn, 0, sizeof(zl_ttdp_etb_cn_t));
        memcpy(con_own->mac, ctx->ifaddr, ETH_ALEN);
        con_own->orientation = ctx->cfx.etbOrientation;
        con_own->reserved = 0;
        memcpy(etbCn->CstUUID, ctx->cfx.CstUUID, 16);
	etbCn->orientationCst = ctx->cfx.cstOrientation;/////////pConnectivity.orientation;
	etbCn->flagCn = 1;
	etbCn->flagIni = 1;
        etbCn->pCnEtb =  ctx->etbCns;//ctx->cfx.CnId; // add bit
        etbCn->nEtbnCst =   ctx->cfx.nEtbnCst;
        etbCn->nCnCst =   ctx->cfx.nCnCst;
        etbCn->cnToEtbnList[0] = ctx->etbCns; //FIRST
        zl_ttdpd_connectivity_list_add_sort(ctx, con_own,  pNum, etbCn);
//        ctx->ConnTableCrc = zl_ttdp_checksum_connectivity(ctx->cList);
//      ctx->EtbTopoCnt = zl_ttdp_checksum_directory(ctx->dList);
}
uint8_t
zl_ttdp_orientation_list_check(zl_ttdpd_connectivity_list_t* pEtb, zl_ttdpd_t *ctx, zl_port_t *pPort,  zl_tlv_etb_t *tlvetb, uint8_t pCount, uint8_t pEtbnCst)
{
	zl_ttdpd_connectivity_t pConnectivity;
	zl_ttdp_etb_cn_t pEtbCn;
	memcpy(pConnectivity.mac, tlvetb->own_macaddress, ETH_ALEN);
	if(ctx->pDir1 == NULL || ctx->pDir2 == NULL)
        {
		if(pPort->direction == ZL_PORT_DIR_LEFT)
		{
			if(zl_etb_vector_list_find(pPort->vList, tlvetb->own_macaddress) != NULL && pCount >= tlvetb->ndir1_etbn)
				pConnectivity.orientation =  ctx->cfx.etbOrientation;
			else if(zl_etb_vector_list_find(pPort->vList, tlvetb->own_macaddress) != NULL && pCount < tlvetb->ndir1_etbn)
				 pConnectivity.orientation =  (~ctx->cfx.etbOrientation) & 0x03;
			else
				return 0;
		}else if(pPort->direction == ZL_PORT_DIR_RIGHT)
		{
			if(zl_etb_vector_list_find(pPort->vList, tlvetb->own_macaddress) != NULL && pCount < tlvetb->ndir1_etbn)
				pConnectivity.orientation = ctx->cfx.etbOrientation;
			else if (zl_etb_vector_list_find(pPort->vList, tlvetb->own_macaddress) != NULL && pCount >= tlvetb->ndir1_etbn)
				pConnectivity.orientation = (~ctx->cfx.etbOrientation) & 0x03;
			else
				return 0;
		}
	}else
	{
		if((zl_etb_vector_list_find(ctx->pDir1->vList, tlvetb->own_macaddress) != NULL && pCount >= tlvetb->ndir1_etbn)
                || (zl_etb_vector_list_find(ctx->pDir2->vList, tlvetb->own_macaddress) != NULL && pCount < tlvetb->ndir1_etbn))
		{
			//pConnectivity.orientation = 1;
			pConnectivity.orientation =  ctx->cfx.etbOrientation;
		}else if((zl_etb_vector_list_find(ctx->pDir1->vList, tlvetb->own_macaddress) != NULL && pCount < tlvetb->ndir1_etbn)
			|| (zl_etb_vector_list_find(ctx->pDir2->vList, tlvetb->own_macaddress) != NULL && pCount >= tlvetb->ndir1_etbn))
		{
			//pConnectivity.orientation = 2;
			 pConnectivity.orientation =  (~ctx->cfx.etbOrientation) & 0x03;
		}else
			return 0;
	}
//	pEtb = zl_ttdpd_connectivity_list_find(ctx->cList, tlvetb->own_macaddress);
//	if(zl_ttdpd_connectivity_list_find(ctx->cList, tlvetb->own_macaddress) == NULL)
	{
		memset(&pEtbCn, 0, sizeof(zl_ttdp_etb_cn_t));
		pEtbCn.flagCn = 0;
		pEtbCn.nEtbnCst = pEtbnCst;
		//upadate orientation consist same etb if only 1 ETB 
		pEtbCn.orientationCst = tlvetb->cstOrientation;//pConnectivity.orientation;
	        memcpy(pEtbCn.CstUUID, tlvetb->cst_uuid, 16);
		pConnectivity.reserved = 0;
		if(pConnectivity.orientation == ctx->cfx.etbOrientation)
		{
			//remote
			if(pEtb == NULL)
				zl_ttdpd_connectivity_list_add_sort(ctx, &pConnectivity, tlvetb->ndir1_etbn, &pEtbCn);
			else
			{
				pEtb->numEtb = tlvetb->ndir1_etbn; //check aad CN later
			}
//			zl_ttdpd_connectivity_list_add_sort (ctx, &pConnectivity, tlvetb->ndir1_etbn, &pEtbCn);
			//local
		}else if(pConnectivity.orientation != ctx->cfx.etbOrientation)
		{
			if(ctx->cfx.etbOrientation == 2)
			{
				if(pEtb == NULL)
					zl_ttdpd_connectivity_list_add_sort(ctx, &pConnectivity, tlvetb->ndir1_etbn, &pEtbCn);
				else
				{
                                	pEtb->numEtb = tlvetb->ndir1_etbn; //check aad CN later
					pEtbnCst = 0;
//					pEtb->etbCn.pCnEtb =  ctx->etbCns;
//				        pEtb->etbCn.nEtbnCst =  ctx->cfx.nEtbnCst;
				}
//				zl_ttdpd_connectivity_list_add_sort (ctx, &pConnectivity, tlvetb->ndir1_etbn, &pEtbCn);
				
			}else if (ctx->cfx.etbOrientation == 1)
			{
				if(pEtb == NULL)
					zl_ttdpd_connectivity_list_add_sort(ctx, &pConnectivity, tlvetb->ndir2_etbn, &pEtbCn);
				else{
					//pEtb->etbCn.pCnEtb =  ctx->etbCns;
                                        //pEtb->etbCn.nEtbnCst =  ctx->cfx.nEtbnCst;
					pEtb->numEtb = tlvetb->ndir2_etbn;
					pEtbnCst = 0;
				}
				//zl_ttdpd_connectivity_list_add_sort (ctx, &pConnectivity, tlvetb->ndir2_etbn, &pEtbCn);
			}
			
		}
		///update to directory_train
#if 0
		zl_ttdpd_directory_consists_list_t *pEtb = zl_ttdpd_directory_consists_list_find(pTrain->consists, EtbnId);
		if(pEtb == NULL)
		{
			zl_ttdpd_directory_consists_list_add(pTrain->consists, pEtb, EtbnId);	
		}
#endif
      }	
	zl_ttdpd_connectivity_list_t* pConLoc = zl_ttdpd_connectivity_list_find_update_etb(ctx->cList, ctx->ifaddr, tlvetb->cst_uuid, pEtbnCst);
//	if( pConLoc == NULL)
	{
		memset(&pEtbCn, 0, sizeof(zl_ttdp_etb_cn_t));
		zl_port_t *pLocal = NULL;
		if(ctx->cfx.etbOrientation == 1)
			pLocal = ctx->pDir1;
		else if(ctx->cfx.etbOrientation == 2)
			pLocal = ctx->pDir2;
		if(pLocal != NULL)
		{
			//local
			if( pConLoc == NULL)
			{
				zl_ttdp_ttdpd_connectivity_local(ctx, &pConnectivity, zl_etb_vector_list_num(pLocal->vList), &pEtbCn);
			}else
			{
				pConLoc->numEtb = zl_etb_vector_list_num(pLocal->vList);
			}
			ctx->cfx.EtbnId = zl_etb_vector_list_num(pLocal->vList)+1;
		}else {
			//local
			if(pConLoc == NULL)
				zl_ttdp_ttdpd_connectivity_local(ctx, &pConnectivity, 0, &pEtbCn);
			else
				pConLoc->numEtb = 0;
			ctx->cfx.EtbnId = 1;
		}
	}
	ctx->ConnTableCrc = zl_ttdp_checksum_connectivity(ctx);
/// not sot	ctx->ConnTableCrc = zl_ttdp_checksum_connectivity(ctx->cList);
#if 0
	if(ctx->ConnTableCrc == ntohl(tlvetb->contablecrc32))
	{
		zl_ttdp_topo_set_ip_etbn(ctx);
                ctx->EtbInhi = 2;
		ctx->ConnTableValid = 2;
	}
#endif
//	printf("ConnTableCrc=%d\n", ctx->ConnTableCrc);
	zl_ttdpd_connectivity_list_print(ctx->cList);
	return 1;
}


void
zl_ttdpd_topology_decode(zl_ttdpd_t *ctx, void *uData, const uint8_t *src_addr, void *data, size_t size) {
  	zl_tlv_t *tlist = zl_tlv_decode(data, size);
  	zl_tlv_t *n;
  	int i;
	zl_port_t *pPort = (zl_port_t *)(uData);
	zl_tlv_etb_t tlvetb;
	zl_ttdpd_connectivity_list_t *pEtb = NULL;
	uint8_t pEtbnCst = 0;
  while((n = zl_tlv_pop(tlist)) != NULL) {
  if(n->type == 0x01)
  {
	zl_thread_lock();
    zl_memcpy(&tlvetb, n->data, n->length);
	zl_fdb_list_t *pFdb = zl_fdb_list_find(ctx->fList, tlvetb.own_macaddress);
	if(pFdb != NULL)
	{
		if(pFdb->ifindex != pPort->ifindex)
		{
			zl_thread_unlock();
			return;
		}
	}
	if(zl_ttdp_vector_list_check(ctx, pPort, tlvetb.own_macaddress) == 0)
	{
		zl_ttdpd_connectivity_list_clean(ctx->cList);
		zl_ttdp_ttdpd_connectivity_list_default(ctx, 0);
		zl_etb_vector_list_add(pPort->vList, tlvetb.own_macaddress);
		ctx->ConnTableValid = 1;
	}else
	{
		pEtb = zl_ttdpd_connectivity_list_find(ctx->cList, tlvetb.own_macaddress, tlvetb.cst_uuid, &pEtbnCst);
		if(pEtb != NULL)
		{
			struct timeval tvo = {0, 400000};     // timeout to send
			if(pEtb->timeout_topo_event != NULL)
			{
				event_add(pEtb->timeout_topo_event, &tvo);
			}
			pEtbnCst = 0;
		}else
		{
			if(memcmp(tlvetb.own_macaddress, ctx->ifaddr, ETH_ALEN) != 0)
				pEtbnCst ++;
		}
		if(ctx->ConnTableCrc == ntohl(tlvetb.contablecrc32))
		{
			printf("----------------------------------------------------------\n");
			ctx->cfx.nEtbnCst = zl_ttdpd_topology_get_CnCst(ctx);//
			if(tlvetb.etbn_inaugState == 1)
			{
				//update posi
				//zl_ttdp_vector_table_update_etbnum(ctx, &tlvetb);
			}
			if(ctx->ConnTableValid != 2)
			{
				//update dictory defaut
				zl_ttdpd_directory_cn_list_clean(ctx->dList);
				zl_ttdpd_directory_cn_default(ctx);
				zl_ttdp_topo_set_ip_etbn(ctx);
				ctx->EtbInhi = 2;
			}else
			{
				zl_ttdp_topo_set_ip_etbn(ctx);
				ctx->EtbInhi = 2;
			}
//			ctx->cfx.nCnCst = zl_ttdpd_topology_get_CnCst(ctx, ctx->cfx.CstUUID);// 
			zl_ttdpd_connectivity_list_print(ctx->cList);

			struct sockaddr_in oldsin;
			memset(&oldsin, 0, sizeof(struct sockaddr));
			zl_ioctl_get_addr(ctx->ifname, &oldsin);

                        printf("\n\tETBN ID: %d - The IP address %s is: %s \n", ctx->cfx.EtbnId, ctx->ifname, inet_ntoa(oldsin.sin_addr));
			printf("----------------------------------------------------------\n");
			//check ...
//			break;
			ctx->ConnTableValid = 2;
		}else
		{
#if 0
			zl_ttdpd_directory_train_list_t *pTrain = zl_ttdpd_directory_train_list_find(ctx->tList, tlvetb.cst_uuid);
			if(pTrain == NULL)
			{
				zl_ttdpd_directory_train_list_add(ctx, pTrain, tlvetb.cst_uuid);
			}
#endif

			ctx->ConnTableValid = 1;
			uint8_t nLoc = zl_etb_vector_list_num(pPort->vList);
                        uint8_t nRem = tlvetb.ndir1_etbn + tlvetb.ndir2_etbn;
                        if(ctx->pDir1 != NULL && ctx->pDir2 != NULL)
			{
                                nLoc = zl_etb_vector_list_num(ctx->pDir1->vList) + zl_etb_vector_list_num(ctx->pDir2->vList);
			}
			if(nLoc > nRem)
			{
				printf("nLoc:%d > nRem:%dfile: %s func: %s (%d) \n", nLoc, nRem, __FILE__, __func__, __LINE__);
				///
//				break;	
			}else if(nLoc < nRem)
			{
				printf("nLoc:%d < nRem:%dfile: %s func: %s (%d) \n", nLoc, nRem, __FILE__, __func__, __LINE__);
				zl_ttdpd_connectivity_list_clean(ctx->cList);
		                zl_ttdp_ttdpd_connectivity_list_default(ctx, 0);
//				break;
			}else
			{
				for(i = 0; i < nRem; i++){
					if(memcmp(ctx->ifaddr, tlvetb.dir_etbns[i].address, ETH_ALEN) == 0){
						zl_ttdp_orientation_list_check(pEtb, ctx, pPort, &tlvetb, i, pEtbnCst);
						break;
					}
				}
			}
		}
	}
	zl_thread_unlock();

	}else if(n->type == 0x02)
  	{
		if(ctx->ConnTableValid == 1)
		{
			return;
		}
		zl_tlv_cn_t tlv_cn;
		zl_memcpy(&tlv_cn, n->data, n->length);
#if 1
		zl_thread_lock();
		if(ntohl(tlv_cn.etb_topo_cnt) != ctx->EtbTopoCnt)
		{
			if(pEtb != NULL)
			{
				memcpy(pEtb->etbCn.cnToEtbnList, tlv_cn.cnToEtbnList,  tlv_cn.nEtbnCst * sizeof(uint32_t));
				if(tlv_cn.nEtbnCst < pEtb->etbCn.nEtbnCst && pEtb->etbCn.flagCn == 0){
					ctx->flagCn++; //or ++ //delay send hell
				}
				if(tlv_cn.nEtbnCst == 1)
				{
					pEtb->etbCn.pCnEtb = ntohl(tlv_cn.cnToEtbnList[0]);
					pEtb->etbCn.flagCn = 1;
				}
				///update local
				for(i = 0; i < tlv_cn.nEtbnCst; i++)
				{
					pEtb->etbCn.cnToEtbnList[i] = ntohl(tlv_cn.cnToEtbnList[i]);
					printf("CNs=%d\n",pEtb->etbCn.cnToEtbnList[i]);
					if(ctx->cLocal != NULL && tlv_cn.nEtbnCst == ctx->cfx.nEtbnCst 
						&& uuid_compare(ctx->cfx.CstUUID, tlvetb.cst_uuid) == 0)
                                        {
                                                ctx->cLocal->etbCn.cnToEtbnList[i] =  ntohl(tlv_cn.cnToEtbnList[i]);////
						
                                        }
				}
				for(i = 0; i < tlv_cn.nCnCst; i++)
                                {
                                        pEtb->etbCn.cnTypes[i] = ntohl(tlv_cn.cnToEtbnList[i]);
					if(ctx->cLocal != NULL && tlv_cn.nEtbnCst == ctx->cfx.nEtbnCst)
					{
						ctx->cLocal->etbCn.cnTypes[i] =  pEtb->etbCn.cnTypes[i];////
					}
                                }
				if(pEtb->etbCn.nEtbnCst == tlv_cn.nEtbnCst)
					pEtb->etbCn.flagIni = 1;
				else
					pEtb->etbCn.flagIni = 0;
				/// check nEtbnCst all
				if(zl_ttdp_directory_check_ebtnum_consist(ctx, tlv_cn.nEtbnCst, pEtb->etbCn.CstUUID) == 1)
				{
					//sort zl_ttdpd_directory_list_t       *dList
					zl_ttdp_directory_table(ctx);	
				}	
			}
		}else{
//			printf("lifesign = %d ctx->EtbTopoCnt = %d\n", ntohl(tlvetb.lifesign), ctx->EtbTopoCnt);
			printf("----------------------------------------------------------\n");
			printf("Train network directory: \n");
			zl_ttdpd_directory_cn_list_print(ctx->dList);
			zl_ttdp_topo_set_ip_cn(ctx);
			printf("----------------------------------------------------------\n");
		}
		
		zl_thread_unlock();
#endif
	}
  	zl_free(n->data);
  	zl_free(n);
  }
//  free(data);
}

