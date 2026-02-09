#ifndef DEMO_COMMON_H
#define DEMO_COMMON_H

#include <stdint.h>

typedef struct {
    uint32_t id;
    uint16_t flags;
    uint8_t mode;
    uint8_t reserved;
} common_header_t;

typedef struct {
    uint8_t a;
    uint32_t b;
} anon_wrap_t;

#endif
