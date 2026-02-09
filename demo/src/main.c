#include "common.h"
#include "net/packet.h"
#include "sensors/result.h"
#include "status.h"

struct system_snapshot {
    device_status_t status;
    net_frame_t frame;
    sensor_result_t sensor;
    anon_wrap_t misc;
    uint8_t blob[20];
};

struct holey_struct {
    uint8_t small;
    uint32_t big;
    uint16_t mid;
};

int main(void) {
    struct system_snapshot snapshot = {0};
    struct holey_struct holey = {0};
    return (int)(snapshot.status.state + holey.small);
}
