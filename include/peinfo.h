/* SPDX-License-Identifier: MIT */

#include <stdio.h>

enum {
  FMT_NONE = 0,
  FMT_STR,
  FMT_DEC1,
  FMT_DEC2,
  FMT_DEC4,
  FMT_DEC8,
  FMT_HEX2,
  FMT_HEX4,
  FMT_HEX8
};

/* utils.c */
void print_kv(FILE *stream, const char *key, void *value, int format);
