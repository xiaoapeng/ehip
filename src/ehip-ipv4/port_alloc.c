#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <eh.h>
#include <eh_types.h>
#include <eh_swab.h>
#include <eh_platform.h>

#define TCP_PORT_ALLOC_START                (0xC000)
static uint16_t             last_bind_port = 0x0000;

uint16_be_t ehip_bind_port_alloc(void){
    uint32_t t = (uint32_t)eh_get_clock_monotonic_time();
    const uint32_t MAGIC1 = 1103515245u;
    const uint32_t MAGIC2 = 2654435761u;

    uint32_t mix = t ^ (last_bind_port * MAGIC1);
    mix ^= (mix >> 16);
    mix *= MAGIC2;
    mix ^= (mix >> 13);

    uint16_t rand_part = (uint16_t)(mix ^ (mix >> 8));

    last_bind_port += rand_part;
    last_bind_port |= TCP_PORT_ALLOC_START;
    return eh_hton16(last_bind_port);
}
