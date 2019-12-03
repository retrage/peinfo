/* SPDX-License-Identifier: MIT */

#include "peinfo.h"

static char *format_str(char *buf, size_t size, void *value, int format)
{
  if (!buf)
    return NULL;

  switch (format) {
    case FMT_STR:
      snprintf(buf, size, "%s", (char *)value);
      break;
    case FMT_DEC1:
      snprintf(buf, size, "%d", *(char *)value);
      break;
    case FMT_DEC2:
      snprintf(buf, size, "%d", *(short *)value);
      break;
    case FMT_DEC4:
      snprintf(buf, size,  "%d", *(int *)value);
      break;
    case FMT_DEC8:
      snprintf(buf, size, "%lld", *(long long int *)value);
      break;
    case FMT_HEX2:
      snprintf(buf, size, "0x%04x", *(unsigned short *)value);
      break;
    case FMT_HEX4:
      snprintf(buf, size, "0x%08x", *(unsigned int *)value);
      break;
    case FMT_HEX8:
      snprintf(buf, size, "0x%016llx", *(unsigned long long *)value);
      break;
    default:
      fprintf(stderr, "unexpected format type\n");
      return NULL;
  }

  return buf;
}

void print_kv(FILE *stream, const char *key, void *value, int format)
{
  const size_t BUFSIZE = 1024;
  char *buf = malloc(sizeof(char) * BUFSIZE);
  if (!buf)
    return;
  buf = format_str(buf, BUFSIZE, value, format);
  if (!buf)
    goto free;

  fprintf(stream, "%s: %s\n", key, buf);

free:
  free(buf);
}
