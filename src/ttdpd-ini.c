#include <zl-comm.h>
#include <zl-ini.h>
#include <zl-ioctl.h>
#include <zl-ttdp.h>
typedef struct {
	const char *zPath;
} _zl_cfx_list_t;
_zl_cfx_list_t zList[] = {
	{"/etc/ttdpd/ttdpd.ini"},
	{"./etc/ttdpd/ttdpd.ini"},
	{"../etc/ttdpd/ttdpd.ini"}
};
static int
zl_cfx_uuid_parse(const char *buff, size_t size, uint8_t *data) {
	int i = 0, h = 0;
	while(i < size) {
		if(buff[i] == '-') {
			i++;
		} else {
			char z_temp[2] = {0, };
			memcpy(&z_temp, &buff[i], sizeof(z_temp));
			i += 2;	//
			data[h++] = (uint8_t )strtol(z_temp, NULL, 16);
		}
	}
	return 0;
}

//#define SET_BIT(value, pos) (value |= (1U<< pos))
//#define CLEAR_BIT(value, pos) (value &= (~(1U<< pos)))
static int
zl_cfx_ini_cb(void* user, const char* section, 
				const char* name, const char *value) {
	zl_ttdpd_t *ctx = (zl_ttdpd_t *)(user);
	zl_ttdpd_directory_t *cfx = (zl_ttdpd_directory_t *)&ctx->cfx;
	#define MATCH(s, n) strcmp(section, s) == 0 && strcmp(name, n) == 0

	if (MATCH("default", "CstUUID")) {
		 uuid_parse(value, cfx->CstUUID);
//		zl_cfx_uuid_parse(value, strlen(value), cfx->CstUUID); 
	}else if (MATCH("default", "etbOrientation")) {
                cfx->etbOrientation = atoi(value) & 0xff;
        }else if (MATCH("default", "cstOrientation")) {
                cfx->cstOrientation = atoi(value) & 0xff;
        }else if (MATCH("default", "CnId")) {
		cfx->CnId = atoi(value) & 0xff;
	} else if (MATCH("default", "cstNumETB")) {
                cfx->nEtbnCst = atoi(value) & 0xff;
        }else if (MATCH("default", "cstNumCN")) {
                cfx->nCnCst = atoi(value) & 0xff;
        }else if (MATCH("default", "etbRole")) {
                cfx->etbRole = atoi(value) & 0xff;
        }else if (MATCH("default", "Bridge_Intf")) {	// TODO: More
		fprintf(stderr, "[%s]\n", value);
		zl_ioctl_set_state(value, FALSE);	// SET ENABLE BR
		zl_ioctl_br_del(value);
		zl_ioctl_br_add(value);	//
		zl_ioctl_set_state(value, TRUE);	// SET ENABLE BR
		zl_port_add(ctx->pList, value, ZL_PORT_DIR_NONE, ZL_PORT_TYPE_BRIDGE);
	} else if (MATCH("default", "L_Intf")) {	// TODO: More
		ctx->pDir1 = zl_port_add(ctx->pList, value, ZL_PORT_DIR_LEFT, ZL_PORT_TYPE_PHYSICAL);
	} else if (MATCH("default", "R_Intf")) {	// TODO: More
		ctx->pDir2 = zl_port_add(ctx->pList, value, ZL_PORT_DIR_RIGHT, ZL_PORT_TYPE_PHYSICAL);
	} else if (MATCH("default", "C_Intf")) {	// TODO: More
		printf("-----%s------\n", value);
		char tmpstr[64] = {0,};
		memcpy(tmpstr, value, strlen(value));
		char * token = strtok(tmpstr, " ");
		token = strtok(NULL, " ");
		zl_port_t* cnPort = zl_port_add(ctx->pList, tmpstr, ZL_PORT_DIR_CN, ZL_PORT_TYPE_PHYSICAL);
		cnPort->cnId = atoi(token);
		ctx->etbCns = setBit(ctx->etbCns, cnPort->cnId-1);
	} else {
		return 0;
	}
	
	return 1;
}
static int
zl_cfx_load_file_cb(void *data, const char *fname) {
	if(ini_parse(fname, zl_cfx_ini_cb, data) < 0) {
		return -1;
	}
	return 0;
}
int
zl_cfx_load_file(void *data) {
	int i;
	for(i = 0; i < sizeof(zList)/ sizeof(_zl_cfx_list_t); i++) {
		if(zl_cfx_load_file_cb(data, zList[i].zPath) == 0) {
			return 0;
		}
	}
	return -1;
}
