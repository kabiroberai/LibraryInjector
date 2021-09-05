//
//  testlib.c
//  TestLib
//
//  Created by Kabir Oberai on 05/09/21.
//

#include <stdio.h>

__attribute__((constructor)) static void init() {
    printf("testlib loaded!\n");
}
