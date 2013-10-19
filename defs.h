#ifndef CAREPO_DEFS_H_
#define CAREPO_DEFS_H_
#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <ndn/ndn.h>
#include <ndn/uri.h>

static inline void LOG(const char* format, ...) {
  va_list args;
  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);
}

static inline void LOG_name(const uint8_t* name, size_t namesz) {
  struct ndn_charbuf* uri = ndn_charbuf_create();
  ndn_uri_append(uri, name, namesz, 0);
  LOG("%s", uri->buf);
  ndn_charbuf_destroy(&uri);
}

#endif//CAREPO_DEFS_H_
