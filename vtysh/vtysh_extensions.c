#include <dlfcn.h>
#include <stdio.h>

#include "memory.h"
#include "vtysh_extensions.h"
#include "lib/vty.h"
#include "vtysh.h"

DEFINE_MTYPE(MVTYSH, VTYSH_EXT, "Vtysh extension");
DEFINE_MTYPE(MVTYSH, VTYSH_EXT_NAME, "Vtysh extension name");

static struct vtysh_ext *extensions = NULL;

static struct vtysh_ext *find_extension(char *name)
{
    for(struct vtysh_ext *e = extensions; e != NULL; e = e->next)
        if (strcmp(e->name, name) == 0)
            return e;
    return NULL;
}
static int vtysh_load_extension(struct vtysh_ext *e)
{
    e->handle = dlopen(e->name, RTLD_GLOBAL | RTLD_NOW);
    if (e->handle) {
        int (*ext_load)(void);
        *(void **)&ext_load = dlsym(e->handle, "vtysh_extension");
        if (*ext_load) {
            int r;
            if ((r = (*ext_load)()) == 0)
                e->loaded = true;
            return r;
        } else {
            fprintf(stderr, " Failed to init vtysh extension '%s': %s\n", e->name, dlerror());
            return -1;
        }
    } else {
        fprintf(stderr, " Failed to load vtysh extension '%s': %s\n", e->name, dlerror());
        return -1;
    }
}

int vtysh_load_extensions(void)
{
    struct vtysh_ext *e;
    for (e = extensions; e ; e = e->next) {
        if (vtysh_load_extension(e) != 0)
            return -1;
    }
    return 0;
}
void vtysh_unload_extensions(void)
{
    struct vtysh_ext *e;
    for (e = extensions; e ; e = e->next) {
        if (e->loaded)
            dlclose(e->handle);
        if (e->name)
            XFREE(MTYPE_VTYSH_EXT_NAME, e->name);
        XFREE(MTYPE_VTYSH_EXT, e);
    }
}
void vtysh_register_extension(char *name)
{
    assert(name);
    if (find_extension(name) != NULL) {
        fprintf(stderr, "Omitting extension %s: it appears to be already registered", name);
        return;
    }
    struct vtysh_ext *e = XCALLOC(MTYPE_VTYSH_EXT, sizeof(*e));
    e->name = XSTRDUP(MTYPE_VTYSH_EXT_NAME, name);
    e->next = extensions;
    extensions = e;
}

void vtysh_show_extensions(struct vty *vty)
{
    struct vtysh_ext *e;
    for (e = extensions; e ; e = e->next) {
        vty_out(vty, " Extension: %s\n", e->name);
        vty_out(vty, "    status: %s\n\n", e->loaded ? "loaded" : "not-loaded");
    }
}
