/******************************************************
 * Copyright Grégory Mounié 2018                      *
 * This code is distributed under the GLPv3+ licence. *
 * Ce code est distribué sous la licence GPLv3+.      *
 ******************************************************/

#include <stdint.h>
#include <assert.h>
#include <math.h>
#include "mem.h"
#include "mem_internals.h"

unsigned int puiss2(unsigned long size) {
    unsigned int p=0;
    size = size -1; // allocation start in 0
    while(size) {  // get the largest bit
	p++;
	size >>= 1;
    }
    if (size > (1 << p))
	p++;
    return p;
}

void *
emalloc_medium(unsigned long size)
{
    assert(size < LARGEALLOC);
    assert(size > SMALLALLOC);

    // modified by zerhounb & notariob

    uint64_t taille = size + 32;
    unsigned int indice = puiss2(taille);
    if ((1 << indice) >= LARGEALLOC) return emalloc_large((1 << indice));
    // On cherche le premier bloc vide plus grand que la taille demandée
    unsigned int indice_bloc_vide = indice;
    while (indice_bloc_vide < (FIRST_ALLOC_MEDIUM_EXPOSANT + arena.medium_next_exponant) && arena.TZL[indice_bloc_vide] == NULL) {
        indice_bloc_vide++;
    }

    // si on trouve immédiatement le bloc de la bonne taille
    if (indice_bloc_vide == indice || arena.TZL[indice] != NULL) {
        void** ptr_to_alloc = &arena.TZL[indice];
        arena.TZL[indice] = *ptr_to_alloc;
        return mark_memarea_and_get_user_ptr(*ptr_to_alloc, (1 << indice), MEDIUM_KIND);
    }
    // si on ne trouve pas de bloc libre
    else if (indice_bloc_vide == FIRST_ALLOC_MEDIUM_EXPOSANT + arena.medium_next_exponant) {
        mem_realloc_medium();
    }

    // si on arrive ici on a forcément un bloc libre dans arena.TZL[indice_bloc_vide]
    void* ptr_to_alloc = arena.TZL[indice_bloc_vide];
    // on fait pointer arena.TZL[indice_bloc_vide] vers la prochaine adresse
    arena.TZL[indice_bloc_vide] = *((void**)ptr_to_alloc);

    // il faut diviser les bloc jusqu'à arriver à la bonne taille
    while (indice_bloc_vide != indice) {
        indice_bloc_vide--;
        void* addr_buddy = (void*)((uint64_t)ptr_to_alloc ^ (1 << indice_bloc_vide));
        // on chaîne l'adresse du buddy dans la bonne case
        *((void**)addr_buddy) = arena.TZL[indice_bloc_vide];
        arena.TZL[indice_bloc_vide] = addr_buddy;
    }

    return mark_memarea_and_get_user_ptr(ptr_to_alloc, (1 << indice), MEDIUM_KIND);
}


void efree_medium(Alloc a) {

    // modified by zerhounb & notariob

    uint64_t bloc_size = a.size;
    uint64_t buddy_found = 0;

    while (bloc_size < TZL_SIZE) {
        buddy_found = 0;

        // on calcule l'adresse du buddy
        void* buddy = (void*) (((uint64_t)a.ptr) ^ bloc_size);

        // on cherche si le buddy est présent dans la bonne case de TZL
        unsigned int indice = puiss2(bloc_size);

        // on parcours la liste chaînée des adresses de taille a.size
        void* ptr = arena.TZL[indice];
        void* previous_ptr = NULL;

        while (ptr != NULL) {
            // si on trouve le buddy, il faut l'enlever
            if (ptr == buddy) {

                buddy_found = 1;
                if (previous_ptr == NULL) {
                    arena.TZL[indice] = *(void**)ptr;
                } else {
                    *(void**)previous_ptr = *(void**)ptr;
                }

                void** new_ptr = a.ptr;
                *new_ptr = ((a.ptr < buddy) ? a.ptr : buddy);
                bloc_size <<= 1;
                break;
            }
            previous_ptr = ptr;
            ptr = *((void **)ptr);
        }
        if (!buddy_found) break;
    }

    // il ne nous reste plus qu'à insérer le bloc dans le bon emplacement de arena.TZL

    /*
    // on fait pointer a.ptr sur la tete de la liste chaîné
    unsigned int indice = puiss2(bloc_size);
    void** ptr = a.ptr;
    *ptr = (void *) arena.TZL[indice];
    // on insére a.ptr dans la tête de la liste chaînée
    void** ptr2 = arena.TZL[indice];
    *ptr2 = (void *) a.ptr;*/
}


