#include <zl-comm.h>
#include <zl-mem.h>
#include <tlv.h>
#include <zl-ttdp.h>
#include <zl-tlv-core.h>


uint8_t
zl_etb_vector_list_get_all(zl_etb_vector_entry_t *plist, zl_mac_address_t *dir_etbns, uint8_t *num) {
        assert(plist != NULL);
        uint8_t numvec = *num;
        struct list_head *pos, *q;
        list_for_each_safe(pos, q, &plist->list) {
                zl_etb_vector_entry_t *v = list_entry(pos, zl_etb_vector_entry_t, list);
                memcpy(dir_etbns[numvec].address, v->mac, ETH_ALEN);
                numvec++;
        }
        *num = numvec;
        return numvec;
}


void
zl_tlv_hello_add_value (zl_tlv_hello_t *destlvhello,
            uint8_t *oui,
            uint8_t  subtype,
            uint32_t version,
            uint32_t lifesign,
	    uint32_t etb_topo_cnt,
            uint8_t *vendor,
	    zl_port_line_t lineStatus,
            uint8_t timeout_management,
            uint8_t *sourceid,
            uint8_t source_etbn_port,
            uint8_t egressline,
            uint8_t egress_dir,
            uint8_t *remoteid,
            uuid_t cstuuid,
            uint8_t inaugurationflag,
            uint16_t reserved2)
{
  	memcpy(destlvhello->oui, oui, sizeof(destlvhello->oui));
  	destlvhello->subtype = subtype;
  	destlvhello->version = htonl(version);
  	destlvhello->lifesign = htonl(lifesign);
	destlvhello->etb_topo_cnt = htonl(etb_topo_cnt);
	destlvhello->tlv_cs = 0;
	memcpy(destlvhello->vendor, vendor, sizeof(destlvhello->vendor));
	destlvhello->recs_astatus = lineStatus.recs_astatus;	
	destlvhello->recs_bstatus = 3;	
	destlvhello->recs_cstatus = 3;	
	destlvhello->recs_dstatus = 3;	

  	destlvhello->timeout_management = timeout_management;
	memcpy(destlvhello->src_id, sourceid, sizeof(destlvhello->src_id));
	destlvhello->src_port_id = source_etbn_port;
	destlvhello->egressline = egressline;
	destlvhello->egress_dir = egress_dir;
	destlvhello->reserved1 = 0;
	destlvhello->inaugh_init = inaugurationflag;
	destlvhello->reserved2 = 0;
	memcpy(destlvhello->remoteid, remoteid, sizeof(destlvhello->remoteid));
	memcpy(destlvhello->cstuuid,  cstuuid, sizeof(destlvhello->cstuuid));
	destlvhello->reserved2 = 0;
//  memcpy(destlvhello->reserved2, reserved2, sizeof(destlvhello->reserved));
//  destlvhello->franechecsequence = htons(franechecsequence);
}

void *
zl_ttdpd_hello_tlv_encode(zl_ttdpd_t *ctx, zl_port_t *phyport, void *data, size_t *size) {
	int n_bytes = *size;
	size_t z_bytes = 0;
	// Init
	zl_tlv_t *plist = zl_tlv_init();
	// 	zl_tlv_chassis_id_t
	zl_tlv_chassis_id_t t_chassis = {0, };
	t_chassis.subtype = TLV_CHASSIS_SUBTYPE_MAC_ADDRESS;
	zl_memcpy(&t_chassis.value, ctx->ifaddr, ETH_ALEN);

	zl_tlv_add(plist, TLV_CHASSIS_ID, sizeof(zl_tlv_chassis_id_t), &t_chassis);
	//	zl_tlv_port_id_t
	zl_tlv_port_id_t t_port = {0, };
	t_port.subtype = TLV_PORT_SUBTYPE_AGENT_ID;
	t_port.value = 0;

	zl_tlv_add(plist, TLV_PORT_ID, sizeof(zl_tlv_port_id_t), &t_port);
	//	zl_tlv_ttl_t
	zl_tlv_ttl_t t_ttl = {0, };
	t_ttl.value = htons(128);
	zl_tlv_add(plist, TLV_TIME_TO_LIVE, sizeof(zl_tlv_ttl_t), &t_ttl);
#if 1
	/* hello */
	
  	uint8_t oui_val[] = {0x20, 0x0E, 0x95};
 	uint8_t vendor[] = "Netvision";
 	phyport->helloLife++;
	zl_tlv_hello_t tlvhello;
	zl_tlv_hello_add_value(&tlvhello, oui_val, 0x01, 0x01000000, phyport->helloLife, ctx->EtbTopoCnt, vendor , 
				phyport->lineStatus, phyport->timeOutHello, ctx->ifaddr, phyport->ifindex, 'A', phyport->direction, phyport->remoteMac, ctx->cfx.CstUUID, phyport->InaugInhi, 0);
	  zl_tlv_add(plist, TLV_ORG_SPECIFIC, sizeof(zl_tlv_hello_t), &tlvhello);
#endif
	//  zl_tlv_end_lldpdu_t
	zl_tlv_add(plist, TLV_END_OF_LLDPDU, 0, NULL);	// END of TLV
	// encode
	void *x = zl_tlv_encode(plist, &z_bytes);
	// Free
	data = zl_realloc(data, n_bytes + z_bytes);
	memcpy(data + n_bytes, x, z_bytes);

	free(x);	// free
	zl_tlv_free(plist);	// free
	*size += z_bytes;
	return data;
}
void *
zl_ttdpd_hello_header_encode(zl_ttdpd_t *ctx, void *data, int *size) {
	struct vlan_ethhdr *hdr = zl_calloc(1, sizeof(*hdr));
	uint8_t _h_dst_mac[] = TTDP_HELLO_DEST_MAC_ADDR;
	zl_memcpy(hdr->h_dest, _h_dst_mac, ETH_ALEN);
	zl_memcpy(hdr->h_source, ctx->ifaddr, ETH_ALEN);
	hdr->h_vlan_proto = htons(ETH_P_VLAN);
	hdr->h_vlan_TCI = htons(ETH_P_TTDP_VLAN_ID | ETH_P_VLAN_PCI_MASK);
	hdr->h_vlan_encapsulated_proto = htons(ETH_P_LLDP);
	void *msg = zl_calloc(1, sizeof(struct vlan_ethhdr));
	zl_memcpy(msg, hdr, sizeof(struct vlan_ethhdr));
	*size += sizeof(struct vlan_ethhdr);
	zl_free(hdr);
	return msg;
}

void *
zl_ttdpd_topology_header_encode(zl_ttdpd_t *ctx, void *data, int *size) {
  struct vlan_ethhdr *hdr = zl_calloc(1, sizeof(*hdr));
  uint8_t _h_dst_mac[] = TTDP_TOPOLOGY_MAC_ADDR;
  zl_memcpy(hdr->h_dest, _h_dst_mac, ETH_ALEN);
  zl_memcpy(hdr->h_source, ctx->ifaddr, ETH_ALEN);
  hdr->h_vlan_proto = htons(ETH_P_VLAN);
  hdr->h_vlan_TCI = htons(ETH_P_TTDP_VLAN_ID | ETH_P_VLAN_PCI_MASK);
  hdr->h_vlan_encapsulated_proto = htons(ETH_P_TOPOLOGY);
  void *msg = zl_calloc(1, sizeof(struct vlan_ethhdr));
  zl_memcpy(msg, hdr, sizeof(struct vlan_ethhdr));
  *size += sizeof(struct vlan_ethhdr);
  zl_free(hdr);
  return msg;
}


uint8_t
zl_ttdpd_topology_get_EtbCn(zl_ttdpd_t *ctx, uint32_t *pEtbnList)
{
	uint8_t pCount = 0;
	struct list_head *pos, *q;
        list_for_each_prev_safe(pos, q, &ctx->cList->list) {
                zl_ttdpd_connectivity_list_t *v = list_entry(pos, zl_ttdpd_connectivity_list_t, list);
                if(uuid_compare(v->etbCn.CstUUID, ctx->cfx.CstUUID) == 0)
                {
			if(v->etbCn.flagCn != 1) //check ETB send first message
			{
				pCount = 1;
				pEtbnList[0] = htonl(ctx->etbCns);
				break;
			}
//			if(ctx->flagCn == 1) //check all ETB receive first message
			if(ctx->flagCn > 0) //check all ETB receive first message
			{
				pCount = 1;
                                pEtbnList[0] = htonl(ctx->etbCns);
//				ctx->flagCn = 0;
				ctx->flagCn--;
                                break;	
			}
			pEtbnList[pCount] = htonl(v->etbCn.pCnEtb);
                        pCount ++;
                }
        }
	
	return pCount;
}

void *
zl_ttdpd_topology_tlv_encode(zl_ttdpd_t *ctx, zl_port_t *phyport, void *data, size_t *size) {
  int n_bytes = *size;
  size_t z_bytes = 0;
  // Init
  zl_tlv_t *plist = zl_tlv_init();
  /* etb */
  uint8_t protocol_id[] = "TTDP";
  uint32_t protocol_version = 64;
 // uint8_t  etbn_inaugState = 0x02;

  //etb
	phyport->topoLife++;
  	zl_tlv_etb_t tlvetb;
	zl_memcpy(tlvetb.protocol_id, protocol_id, sizeof(tlvetb.protocol_id));
	tlvetb.protocol_version = htonl(protocol_version);
	tlvetb.lifesign = htonl(phyport->topoLife);
  	zl_memcpy(tlvetb.cst_uuid, ctx->cfx.CstUUID, sizeof(tlvetb.cst_uuid));
	tlvetb.etbn_inaugState = ctx->EtbInhi;
	tlvetb.etbn_node_role = ctx->cfx.etbRole; //master
	tlvetb.reserved1 = 0;
	tlvetb.etbn_inhibit = 0x02; // alow set ip
 

	tlvetb.reserved2 = 0;
	tlvetb.remote_inhibit = 3; //UNDEFINED
	tlvetb.cstOrientation = ctx->cfx.cstOrientation;
	tlvetb.contablecrc32 = htonl(ctx->ConnTableCrc);
///
	if(ctx->pDir1 != NULL)
	{
		tlvetb.etbn_dir1.etbn_linea  = ctx->pDir1->lineStatus.recs_astatus;
                tlvetb.etbn_dir1.etbn_lineb  = 3;
                tlvetb.etbn_dir1.etbn_linec  = 3;
                tlvetb.etbn_dir1.etbn_lined  = 3;
                tlvetb.etbn_dir1.etbn_dira = 'A';
                tlvetb.etbn_dir1.etbn_dirb = '-';
                tlvetb.etbn_dir1.etbn_dirc = '-';
                tlvetb.etbn_dir1.etbn_dird = '-';
	}else
	{
		tlvetb.etbn_dir1.etbn_linea  = 3;
                tlvetb.etbn_dir1.etbn_lineb  = 3;
                tlvetb.etbn_dir1.etbn_linec  = 3;
                tlvetb.etbn_dir1.etbn_lined  = 3;
                tlvetb.etbn_dir1.etbn_dira = '-';
                tlvetb.etbn_dir1.etbn_dirb = '-';
                tlvetb.etbn_dir1.etbn_dirc = '-';
                tlvetb.etbn_dir1.etbn_dird = '-';
	}

	if(ctx->pDir2 != NULL)
        {
                tlvetb.etbn_dir2.etbn_linea  = ctx->pDir2->lineStatus.recs_astatus;
                tlvetb.etbn_dir2.etbn_lineb  = 3;
                tlvetb.etbn_dir2.etbn_linec  = 3;
                tlvetb.etbn_dir2.etbn_lined  = 3;
                tlvetb.etbn_dir2.etbn_dira = 'A';
                tlvetb.etbn_dir2.etbn_dirb = '-';
                tlvetb.etbn_dir2.etbn_dirc = '-';
                tlvetb.etbn_dir2.etbn_dird = '-';
        }else
        {
                tlvetb.etbn_dir2.etbn_linea  = 3;
                tlvetb.etbn_dir2.etbn_lineb  = 3;
                tlvetb.etbn_dir2.etbn_linec  = 3;
                tlvetb.etbn_dir2.etbn_lined  = 3;
                tlvetb.etbn_dir2.etbn_dira = '-';
                tlvetb.etbn_dir2.etbn_dirb = '-';
                tlvetb.etbn_dir2.etbn_dirc = '-';
                tlvetb.etbn_dir2.etbn_dird = '-';
        }

	zl_memcpy(tlvetb.macaddress_dir1, ctx->conVector.mac_dir2, ETH_ALEN);
	zl_memcpy(tlvetb.own_macaddress, ctx->conVector.mac_own, ETH_ALEN);
	zl_memcpy(tlvetb.macaddress_dir2, ctx->conVector.mac_dir2, ETH_ALEN);
	uint8_t numetb = 0;
	if(ctx->pDir1 != NULL)
	{
		tlvetb.ndir1_etbn = zl_etb_vector_list_get_all(ctx->pDir1->vList, tlvetb.dir_etbns, &numetb);
	}else
	{
		tlvetb.ndir1_etbn = 0;	
	}
	if(ctx->pDir2 != NULL)
        {
		tlvetb.ndir2_etbn = zl_etb_vector_list_get_all(ctx->pDir2->vList, tlvetb.dir_etbns, &numetb) - tlvetb.ndir1_etbn;
        }else
        {
                tlvetb.ndir2_etbn = 0;
        }

	tlvetb.reserved3 = 0;
	int i;
#if 0
	tlvetb.dir1_etbns = (zl_mac_address_t*)malloc(tlvetb.ndir1_etbn*sizeof(zl_mac_address_t));
	tlvetb.dir2_etbns = (zl_mac_address_t*)malloc(tlvetb.ndir2_etbn*sizeof(zl_mac_address_t));
	for(i = 0; i < tlvetb.ndir1_etbn; i++)
	{
		zl_memcpy(&tlvetb.dir1_etbns[i], "123456", 6);
	}
	for(i = 0; i < tlvetb.ndir2_etbn; i++)
	{
		zl_memcpy(&tlvetb.dir2_etbns[i], "222222", 6);
	}
#endif
	//tlvetb.padding = 0;
	size_t size_v = sizeof(zl_tlv_etb_t) - (62 - tlvetb.ndir2_etbn - tlvetb.ndir1_etbn)*ETH_ALEN;;
//	size_t size_v = 72;
	zl_tlv_add(plist, 0x01, size_v, &tlvetb);
  //cn
	  zl_tlv_cn_t tlv_cn;
	  
	  tlv_cn.etb_topo_cnt = htonl(ctx->EtbTopoCnt);
	  tlv_cn.own_entb_nb = 1;
	  tlv_cn.lengthen = ctx->cnLengthen; //check HELLO
	  tlv_cn.shorten = ctx->cnShorten;
	  tlv_cn.reserved1 = 0;
	  tlv_cn.nEtbnCst = 0;//ctx->cfx.nEtbnCst;
	  tlv_cn.nCnCst  = ctx->cfx.nCnCst;
#if 1
//  size_v = 8 + tlv_cn.nEtbnCst*sizeof(uint32_t) + tlv_cn.nCnCst*sizeof(uint32_t);
//  if(tlv_cn.nEtbnCst > 0)
	if(ctx->ConnTableValid == 2)
  	{
		tlv_cn.nEtbnCst = zl_ttdpd_topology_get_EtbCn(ctx, tlv_cn.cnToEtbnList);
  	}
	if(tlv_cn.nCnCst > 0)
	{
//		tlv_cn.cnTypes = (uint8_t*)malloc(tlv_cn.nCnCst*sizeof(uint8_t));
		for(i = 0; i < tlv_cn.nCnCst; i++)
        	{
                	tlv_cn.cnTypes[i] = 2;
        	}
	}
	size_v = sizeof(zl_tlv_cn_t);
#endif
//	size_v = size_v + 8 + 4;
//  tlv_cn.padding = 0;
  zl_tlv_add(plist, 0x02, size_v, &tlv_cn);
  // encode
  void *x = zl_tlv_encode(plist, &z_bytes);
  // Free
  data = zl_realloc(data, n_bytes + z_bytes);
  memcpy(data + n_bytes, x, z_bytes);
#if 0
	if(tlv_cn.cnToEtbnList == NULL)
		free(tlv_cn.cnToEtbnList);
	if(tlv_cn.cnTypes == NULL)
		free(tlv_cn.cnTypes);
//	free(tlvetb.dir1_etbns);
//	free(tlvetb.dir2_etbns);
#endif
  free(x);  // free
  zl_tlv_free(plist); // free
  *size += z_bytes;
  return data;
}

void *
zl_ttdpd_hello_encode(zl_ttdpd_t *ctx, int *size) {
	// HDR
	void *buff = zl_ttdpd_hello_header_encode(ctx, NULL, size);
	// TLV
	//buff = zl_ttdpd_hello_tlv_encode(ctx, buff, size);
	return buff;
}

void *
zl_ttdpd_topology_encode(zl_ttdpd_t *ctx, int *size) {
  // HDR
  void *buff = zl_ttdpd_topology_header_encode(ctx, NULL, size);
  // TLV
//  buff = zl_ttdpd_topology_tlv_encode(ctx, buff, size);
  return buff;
}

