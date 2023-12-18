#ifndef __ZL_CRC_H__
#define __ZL_CRC_H__
// CRC
#define CRC_INIT_VECTOR 0xffffffff
unsigned int xcrc32 (const unsigned char *buf, int len, unsigned int init);
void *frame_checksum_calc(void *buff, int *size);
int frame_checksum_check(void *buff, int size);
unsigned int get_xcrc32 (const unsigned char *buf, int len);
#endif	//	__ZL_CRC_H__
