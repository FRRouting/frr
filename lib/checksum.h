extern int in_cksum(void *, int);
#define FLETCHER_CHECKSUM_VALIDATE 0xffff
extern uint16_t fletcher_checksum(unsigned char *, const size_t len,
				  const uint16_t offset);
