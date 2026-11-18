/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Allocate an unused local ID for a never-committed, TX-fenced shadow.
 * The source discriminator itself is never changed. Caller is on bfdd's
 * main loop and must reject any collision with an applied/live session. */
static bool cnlab_bfd_reserve_snapshot_id(struct bfd_session *target, uint32_t desired,
                                        bool (*uncommitted)(struct bfd_session *),
                                        uint64_t *relocations)
{
    struct bfd_session *collision=bfd_id_lookup(desired);
    if (!collision || collision==target) return true;
    if (!uncommitted(collision)) return false;
    uint32_t old=collision->discrs.my_discr, temporary=old;
    unsigned tries;
    for (tries=0;tries<4096;tries++) {
        temporary++;
        if (!temporary) temporary=1;
        if (!bfd_id_lookup(temporary)) break;
    }
    if (tries==4096 || bfd_id_delete(old)!=collision) return false;
    collision->discrs.my_discr=temporary;
    if (!bfd_id_insert(collision)) {
        collision->discrs.my_discr=old;
        bfd_id_insert(collision);
        return false;
    }
    (*relocations)++;
    return true;
}
