// hello.c
#include <stdio.h>
#include <stdlib.h>
int main() {
  FILE *f = fopen("foo.txt","w");
  fprintf(f,"QEMU-user test\n");
  fclose(f);
  system("/bin/true");
  return 0;
}
