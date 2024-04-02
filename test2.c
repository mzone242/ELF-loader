#include <stdio.h>

#define ARRAY_SIZE 40000000

int array[ARRAY_SIZE]; // Declaring a large array in the BSS segment

int main() {
    // Accessing the first and last element of the array
    array[0] = 1;
    array[39999999] = 1;

    return 0;
}