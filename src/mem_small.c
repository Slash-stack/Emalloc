/******************************************************
 * Copyright Grégory Mounié 2018                      *
 * This code is distributed under the GLPv3+ licence. *
 * Ce code est distribué sous la licence GPLv3+.      *
 ******************************************************/

#include <assert.h>
#include "mem.h"
#include "mem_internals.h"

void *
emalloc_small(unsigned long size)
{
    // modified by zerhounb & notariob

    // si la liste chaînée est vide on met à jour arena.chunkpool
    if (arena.chunkpool == NULL) {
        unsigned long size_chunkpool = mem_realloc_small();
        // on place tous les 96 octets, l’adresse de l’élément suivant qui est 96 octets plus loin.
        void** tete= arena.chunkpool;
        for (unsigned long _i = 0; _i < size_chunkpool - CHUNKSIZE; _i += CHUNKSIZE) {
            *tete = (void *) (tete + CHUNKSIZE / 8);
            tete = tete + CHUNKSIZE / 8;
        }
        // pour la dernière chunk on la marque à null
        *tete = NULL;
    }
    void** tete = arena.chunkpool;
    // on seuvegarde la tete de la liste qui sera l'espace alloué
    void* newmem  = *tete;
    // on fait pointer la liste chaînée sur la prochaine chunk
    tete = *tete;

    return mark_memarea_and_get_user_ptr(newmem, CHUNKSIZE, SMALL_KIND);
}

void efree_small(Alloc a) {

    // modified by zerhounb & notariob

    // on fait pointer a.ptr sur la tete de la liste chaînée
    void** ptr = a.ptr;
    *ptr = (void *) &arena.chunkpool;
    // on insére a.ptr dans la tête de la liste chaînée
    void** ptr2 = arena.chunkpool;
    *ptr2 = (void *) a.ptr;
}
