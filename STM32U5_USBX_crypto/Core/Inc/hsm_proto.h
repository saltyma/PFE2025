#ifndef HSM_PROTO_H
#define HSM_PROTO_H

#include <stdint.h>
#include "tx_api.h"

void hsm_proto_init(void);
void hsm_proto_on_cdc_ready(void);
void hsm_proto_on_cdc_disconnect(void);
void hsm_proto_receive_bytes(const uint8_t *data, UINT length);

#endif /* HSM_PROTO_H */
