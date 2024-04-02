#include <stdio.h>

#define ARRAY_SIZE 40000000

int array[ARRAY_SIZE]; // Declaring a large array in the BSS segment

int main() {
    // Accessing each location in the array sequentially
    for (int i = 0; i < ARRAY_SIZE; ++i) {
        array[i] = i;
    }

    return 0;
}