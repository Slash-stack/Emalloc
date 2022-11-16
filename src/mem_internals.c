/******************************************************
 * Copyright Grégory Mounié 2018                      *
 * This code is distributed under the GLPv3+ licence. *
 * Ce code est distribué sous la licence GPLv3+.      *
 ******************************************************/

#include <sys/mman.h>
#include <assert.h>
#include <stdint.h>
#include "mem.h"
#include "mem_internals.h"

unsigned long knuth_mmix_one_round(unsigned long in)
{
    return in * 6364136223846793005UL % 1442695040888963407UL;
}

void *mark_memarea_and_get_user_ptr(void *ptr, unsigned long size, MemKind k)
{
    // modified by zerhounb & notariob

    unsigned long memkind;

    switch (k) {
        case SMALL_KIND:
            memkind = 0UL;
            break;
        case MEDIUM_KIND:
            memkind = 1UL;
            break;
        case LARGE_KIND:
            memkind = 2UL;
            break;
    }

    *((uint64_t*)(ptr)) = (uint64_t) size;
    uint64_t magic = (knuth_mmix_one_round((uint64_t)ptr) & ~(0b111UL)) | memkind;


    *((uint64_t*)(ptr + 8)) = magic;
    *((uint64_t*)(ptr + size - 16)) = magic;
    *((uint64_t*)(ptr + size - 8)) = (uint64_t) size;

    return (void *)(ptr + 16);
}

Alloc
mark_check_and_get_alloc(void *ptr)
{
    // modified by zerhounb & notariob

    // on lit la taille aux bons emplacements (on vérifie également que la même taille est lue dans les deux
    // bouds du fichier)

    uint64_t size_begin = *(uint64_t *) (ptr - 16);
    //uint64_t size_end = *(uint64_t *) (ptr - 16 + size_begin - 8);
    //assert(size_begin == size_end);

    // on lit le nombre magic aux bons emplacements (on vérifie également que le même nombre magic est lu dans les deux
    // bouds du fichier)
    uint64_t magic_begin = *(uint64_t *) (ptr - 8);
    //uint64_t magic_end = *(uint64_t *) (ptr + size_begin - 32);
    //assert(magic_begin == magic_end);

    // on isole les 3 bits de poids faibles pour avoir le bon type d'allocation
    MemKind k = magic_begin & (0b111UL);

    // on vérifie la cohérence de la valeur magique
    assert(magic_begin == ((knuth_mmix_one_round((unsigned long)(ptr - 16)) & ~(0b111UL)) | k));
    Alloc a = {ptr - 16, k, size_begin};
    return a;
}


unsigned long
mem_realloc_small() {
    assert(arena.chunkpool == 0);
    unsigned long size = (FIRST_ALLOC_SMALL << arena.small_next_exponant);
    arena.chunkpool = mmap(0,
			   size,
			   PROT_READ | PROT_WRITE | PROT_EXEC,
			   MAP_PRIVATE | MAP_ANONYMOUS,
			   -1,
			   0);
    if (arena.chunkpool == MAP_FAILED)
	handle_fatalError("small realloc");
    arena.small_next_exponant++;
    return size;
}

unsigned long
mem_realloc_medium() {
    uint32_t indice = FIRST_ALLOC_MEDIUM_EXPOSANT + arena.medium_next_exponant;
    assert(arena.TZL[indice] == 0);
    unsigned long size = (FIRST_ALLOC_MEDIUM << arena.medium_next_exponant);
    assert( size == (1 << indice));
    arena.TZL[indice] = mmap(0,
			     size*2, // twice the size to allign
			     PROT_READ | PROT_WRITE | PROT_EXEC,
			     MAP_PRIVATE | MAP_ANONYMOUS,
			     -1,
			     0);
    if (arena.TZL[indice] == MAP_FAILED)
	handle_fatalError("medium realloc");
    // align allocation to a multiple of the size
    // for buddy algo
    arena.TZL[indice] += (size - (((intptr_t)arena.TZL[indice]) % size));
    arena.medium_next_exponant++;
    return size; // lie on allocation size, but never free
}


// used for test in buddy algo
unsigned int
nb_TZL_entries() {
    int nb = 0;
    
    for(int i=0; i < TZL_SIZE; i++)
	if ( arena.TZL[i] )
	    nb ++;

    return nb;
}
