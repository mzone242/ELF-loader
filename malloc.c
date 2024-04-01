#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

int
main() {
    printf("MALLOC\n");
    int *zero = malloc(sizeof(int));
    if (zero == NULL) {
        fprintf(stderr, "Malloc failed\n");
    }    

    return 0;
}