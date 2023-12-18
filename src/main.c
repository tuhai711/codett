#include <zl-comm.h>
#include <zl-ttdp.h>
#include <zl-ioctl.h>
#include <zl-ports.h>
zl_ttdpd_t *ctx = NULL;
int 
main(int argc, char *argv[]) {
//
#if 0
	zl_port_t v;
	int i = 0;
	snprintf(v.ifname, IFNAMSIZ, "eth%d", i);
	zl_if_get_addr(&v);
	return 0;
///
	int v = zl_ioctl_br_add("br0");
	fprintf(stderr, "v = [%d]\n", v);
	int z = zl_ioctl_br_del("br0");
	fprintf(stderr, "z = [%d]\n", z);
	
	return 0;
#endif
//
	ctx = zl_ttdpd_init();
	if(ctx) {
		zl_ttdpd_load(ctx);	//	Load configure
		zl_ttdpd_loop(ctx);
		zl_ttdpd_free(ctx);
	}
	return 0;
}
