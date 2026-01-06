#ifndef CMD_UTIL_H
#define CMD_UTIL_H

#include <stdbool.h>

#include "command.h"
#include "lownet.h"

#define MAX_TIME 100000

bool parse_cmd_signature(const uint8_t* payload, size_t len,
                         cmd_signature_t* sig);
bool parse_cmd_packet(const uint8_t* payload, size_t len,
                      cmd_packet_t* packet_out);

void compute_sha256(const uint8_t* data, size_t len,
                    uint8_t buf[CMD_HASH_SIZE]);
bool compare_fields(const lownet_frame_t* in_frame,
                    const lownet_frame_t* sig_frame);

bool check_time(const lownet_time_t* start_time);

void to_hex(const uint8_t* hash, char* out_str);

bool compare_hashes(const uint8_t* a, const uint8_t* b);

#endif
