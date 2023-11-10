#include <stdio.h>

void hexdump(unsigned char *buf, int size) {
  unsigned char *p;
  int i;

  p = buf;

  while (p < buf + size) {

    for (i = 0; i < 16; i++) {
      if (p + i >= buf + size)
        printf("   ");
      else
        printf("%02x ", p[i]);
    }

    for (i = 0; i < 16; i++) {
      if (p + i >= buf + size) {
        printf(" ");
        continue;
      }

      if (p[i] > 31 && p[i] < 127)
        printf("%c", p[i]);
      else
        printf(".");
    }

    printf("\n");
    p += 16;
  }
}