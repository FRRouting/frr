#ifndef _VTYSH_EXTENSIONS_H
#define _VTYSH_EXTENSIONS_H

#include <stdbool.h>
#include "lib/vty.h"

DECLARE_MTYPE(VTYSH_EXT);

struct vtysh_ext {
    char *name;
    void *handle;
    bool loaded;
    struct vtysh_ext *next;
};

void vtysh_register_extension(char *name);
int vtysh_load_extensions(void);
void vtysh_unload_extensions(void);

void vtysh_show_extensions(struct vty *vty);

#endif /* _VTYSH_EXTENSIONS_H */
