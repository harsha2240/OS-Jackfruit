#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

int main() {
    size_t size = 1024 * 1024; // 1 MB

    while (1) {
        void *p = malloc(size);

        if (!p) {
            perror("malloc failed");
            break;
        }

        // Touch memory to ensure allocation is real (VERY IMPORTANT)
        memset(p, 0, size);

        printf("Allocated 1MB\n");
        usleep(100000); // 0.1 sec (fast growth)
    }

    return 0;
}
