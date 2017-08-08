extern int in_cksum(void *, int);
#define FLETCHER_CHECKSUM_VALIDATE 0xffff
extern u_int16_t fletcher_checksum(u_char *, const size_t len,
				   const uint16_t offset);

/* For Emacs:          */
/* Local Variables:    */
/* indent-tabs-mode: t */
/* c-basic-offset: 8   */
/* End:                */
