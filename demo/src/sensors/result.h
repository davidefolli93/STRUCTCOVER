#ifndef DEMO_SENSORS_RESULT_H
#define DEMO_SENSORS_RESULT_H

#include <stdint.h>

typedef struct {
    int16_t value;
    uint32_t timestamp;
} sensor_reading_t;

typedef struct {
    sensor_reading_t readings[4];
    uint8_t count;
} sensor_result_t;

#endif
