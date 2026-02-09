#ifndef DEMO_STATUS_H
#define DEMO_STATUS_H

#include <stdint.h>

typedef struct {
    uint8_t state;
    uint32_t error_code;
    uint16_t temperature;
    uint8_t padding;
} device_status_t;

#endif
