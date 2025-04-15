#include <stdio.h>
#include <assert.h>
#include "mempool.h"

void test_allocation_liberation() {
    printf("Test: Allocation et Libération\n");

    struct memptype  *pool =  mphead_create(1024*1024*8); // Création d'un pool de 8Mo
    assert(pool != NULL);

    void *ptr = mpalloc(pool,350);
    assert(ptr != NULL);

    mpfree(pool, ptr);

    mphead_delete(&pool);
    printf(" -> OK\n");
}

void test_multiple_allocation_liberation() {

    uint32_t i;
    printf("Test: loop Allocation et Libération\n");

    struct memptype  *pool =  mphead_create(1024*1024*8); // Création d'un pool de 8Mo
    assert(pool != NULL);


    for(i = 0; i<500; i++) {
        void *ptr = mpalloc(pool,350);
        assert(ptr != NULL);

        mpfree(pool, ptr);
    }
    mphead_delete(&pool);
    printf(" -> OK\n");
}


void test_500_allocations() {
    printf("Test: Allocation Maximale\n");

    struct memptype *pool = mphead_create(10000); // Création d'un pool de 8Mo
    assert(pool != NULL);

    void *ptrs[5000];
    for (int i = 0; i < 500; i++) {
      ptrs[i] = mpalloc(pool,356);
        assert(ptrs[i] != NULL);
    }

    void *ptr_extra = mpalloc(pool,350);
    assert(ptr_extra != NULL); // Devrait pas échouer

    mphead_delete(&pool);
    printf(" -> OK\n");
}


void test_500_allocations_liberations() {
    printf("Test: 500 Allocations liberations\n");

    struct memptype *pool = mphead_create(10000); // Création d'un pool de 8Mo
    assert(pool != NULL);

    void *ptrs[5000];
    for (int i = 0; i < 500; i++) {
      ptrs[i] = mpalloc(pool,356);
        assert(ptrs[i] != NULL);
    }

    void *ptr_extra = mpalloc(pool,350);
    assert(ptr_extra != NULL); // Devrait  pas échouer

    for (int i = 0; i < 500; i++) {
        mpfree(pool, ptrs[i]);
    }

    /* verifier qu'il ne reste qu'un element */
    assert(mp_nb_blocks(pool) == 1);

    mpfree(pool,ptr_extra);

    assert(mp_nb_blocks(pool) == 1);

    mphead_delete(&pool);
    printf(" -> OK\n");
}


void test_500_allocations_liberations_reverse() {
    printf("Test: 500 Allocations reverse liberations\n");

    struct memptype *pool = mphead_create(10000); // Création d'un pool de 8Mo
    assert(pool != NULL);

    void *ptrs[5000];
    for (int i = 0; i < 500; i++) {
      ptrs[i] = mpalloc(pool,356);
        assert(ptrs[i] != NULL);
    }

    void *ptr_extra = mpalloc(pool,350);
    assert(ptr_extra != NULL); // Devrait  pas échouer

    for (int i = 499; i >= 0; i--) {
        mpfree(pool, ptrs[i]);
    }

    /* verifier qu'il ne reste qu'un element */
    assert(mp_nb_blocks(pool) == 1);

    mpfree(pool,ptr_extra);

    assert(mp_nb_blocks(pool) == 1);

    mphead_delete(&pool);
    printf(" -> OK\n");
}

void test_liberation_double() {
    printf("Test: Libération Double\n");

    struct memptype  *pool =  mphead_create(1024*1024*8); // Création d'un pool de 8Mo
    assert(pool != NULL);

    void *ptr = mpalloc(pool,350);
    assert(ptr != NULL);

    mpfree(pool, ptr);
    mpfree(pool, ptr); // Vérifier si cela provoque un crash

    mphead_delete(&pool);
    printf(" -> OK\n");
}

void test_fragmentation() {
    printf("Test: Fragmentation\n");

    struct memptype  *pool =  mphead_create(1284); // Création d'un pool de 8Mo
    assert(pool != NULL);

    void *ptr1 = mpalloc(pool,350);
    void *ptr2 = mpalloc(pool,350);
    void *ptr3 = mpalloc(pool,350);
    assert(ptr1 && ptr2 && ptr3);

    mpfree(pool, ptr2);

    void *ptr4 = mpalloc(pool,350);
    assert(ptr4 == ptr2); // Vérifier si l'espace libéré est bien réutilisé

    mphead_delete(&pool);
    printf(" -> OK\n");
}

void test_fragmentation2() {
    printf("Test: Fragmentation 2\n");

    struct memptype  *pool =  mphead_create(1284); // Création d'un pool de 8Mo
    assert(pool != NULL);

    void *ptr1 = mpalloc(pool,350);
    void *ptr2 = mpalloc(pool,350);
    void *ptr3 = mpalloc(pool,350);
    assert(ptr1 && ptr2 && ptr3);

    mpfree(pool, ptr2);

    void *ptr4 = mpalloc(pool,350);
    assert(ptr4 == ptr2); // Vérifier si l'espace libéré est bien réutilisé

    mpfree(pool, ptr1);

    ptr4 = mpalloc(pool,350);
    assert(ptr4 == ptr1); // Vérifier si l'espace libéré est bien réutilisé

    mpfree(pool, ptr3);

    ptr4 = mpalloc(pool,350);
    assert(ptr4 == ptr3); // Vérifier si l'espace libéré est bien réutilisé


    assert(mp_nb_blocks(pool) == 1);

    mphead_delete(&pool);
    printf(" -> OK\n");
}


void test_liberation1() {
    printf("Test: Liberation 1\n");

    struct memptype  *pool =  mphead_create(1028*1028*10); // Création d'un pool de 8Mo
    assert(pool != NULL);

    void *ptr1 = mpalloc(pool,1028*16);
    void *ptr2 = mpalloc(pool,1028*16);
    void *ptr3 = mpalloc(pool,550);
    void *ptr4 = mpalloc(pool,1028*16);
    void *ptr5 = mpalloc(pool,1028*16);

    assert(ptr1 && ptr2 && ptr3 && ptr4 && ptr5);

    mpfree(pool, ptr3);

    void *ptr6 = mpalloc(pool,1028);

    void *ptr7 = mpalloc(pool,1028*16);

    void *ptr8 = mpalloc(pool,500);

    assert(ptr6 && ptr7 && ptr8);
    mpfree(pool, ptr7);


    assert(mp_nb_blocks(pool) == 1);

    mphead_delete(&pool);
    printf(" -> OK\n");
}

void test_liberation2() {
    printf("Test: Liberation 2\n");

    struct memptype  *pool =  mphead_create(1028*1028*10); // Création d'un pool de 8Mo
    assert(pool != NULL);

    void *ptr1 = mpalloc(pool,1028*16);
    void *ptr2 = mpalloc(pool,1028*16);
    void *ptr3 = mpalloc(pool,150);
    void *ptr4 = mpalloc(pool,1028*16);
    void *ptr5 = mpalloc(pool,1028*16);

    assert(ptr1 && ptr2 && ptr3 && ptr4 && ptr5);

    mpfree(pool, ptr5);

    mpfree(pool, ptr1);

    void *ptr6 = mpalloc(pool,1028);
    assert(ptr6 == ptr1); // Vérifier si l'espace libéré est bien réutilisé

    mpfree(pool, ptr3);

    ptr6 = mpalloc(pool,1028*16);
    assert(ptr6 == ptr5); // Vérifier si l'espace libéré est bien réutilisé


    assert(mp_nb_blocks(pool) == 1);

    mphead_delete(&pool);
    printf(" -> OK\n");
}

void test_liberation3() {
    printf("Test: Liberation 3\n");

    struct memptype  *pool =  mphead_create(1028*1028*10); // Création d'un pool de 8Mo
    assert(pool != NULL);

    void *ptr1 = mpalloc(pool,1028);
    void *ptr2 = mpalloc(pool,1028);
    void *ptr3 = mpalloc(pool,150);
    void *ptr4 = mpalloc(pool,1028);
    void *ptr5 = mpalloc(pool,1028);

    assert(ptr1 && ptr2 && ptr3 && ptr4 && ptr5);

    mpfree(pool, ptr2);

    mpfree(pool, ptr4);

    mpfree(pool, ptr3);

    void *ptr6 = mpalloc(pool,1028);
    assert(ptr6 == ptr2); // Vérifier si l'espace libéré est bien réutilisé

    void *ptr7 = mpalloc(pool,150);
    assert(ptr7 == ptr3); // Vérifier si l'espace libéré est bien réutilisé


    void *ptr8 = mpalloc(pool,1028);
    assert(ptr8 == ptr4); // Vérifier si l'espace libéré est bien réutilisé


    assert(mp_nb_blocks(pool) == 1);

    mphead_delete(&pool);
    printf(" -> OK\n");
}


int main() {
    test_allocation_liberation();
    test_500_allocations();
    test_500_allocations_liberations();
    /* test_liberation_double(); */
    test_fragmentation();
    test_fragmentation2();
    test_liberation2();
    test_multiple_allocation_liberation();
    test_500_allocations_liberations_reverse();
    test_liberation1();
    test_liberation3();
    printf("Tous les tests ont réussi !\n");
    return 0;
}
