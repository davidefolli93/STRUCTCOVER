#ifndef DEMO_NET_PACKET_H
#define DEMO_NET_PACKET_H

#include <stdint.h>
#include "../common.h"

typedef struct {
    uint16_t length;
    uint8_t type;
    uint8_t flags;
    uint8_t payload[12];
} net_packet_t;

typedef struct {
    common_header_t header;
    net_packet_t packet;
    uint32_t crc;
} net_frame_t;

#endif
