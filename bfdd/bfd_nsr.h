/* Experimental observer hook: not a checkpoint commit or send gate. */
#ifndef CNLAB_BFD_NSR_H
#define CNLAB_BFD_NSR_H
#include "lib/hook.h"
struct bfd_session;
DECLARE_HOOK(cnlab_bfd_state, (struct bfd_session *bs, const char *phase), (bs, phase));
DECLARE_HOOK(cnlab_bfd_send_blocked, (struct bfd_session *bs), (bs));
#endif
