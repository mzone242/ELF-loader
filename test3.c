#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define ARRAY_SIZE 40000000
#define WRITE_PERCENTAGE 10

int array[ARRAY_SIZE]; // Declaring a large array in the BSS segment

int main() {
    srand(time(NULL));

    int elements_to_write = (ARRAY_SIZE / 100) * WRITE_PERCENTAGE;

    // Write 1 to random locations in the array
    for (int i = 0; i < elements_to_write; ++i) {
        int random_index = rand() % ARRAY_SIZE;
        array[random_index] = 1;
    }

    return 0;
}