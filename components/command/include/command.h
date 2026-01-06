#ifndef COMMAND_H
#define COMMAND_H

#include <lownet.h>
#include <stdint.h>

#define LOWNET_PROTOCOL_COMMAND 0x04

#define CMD_HASH_SIZE 32
#define CMD_BLOCK_SIZE 256
#define SIG_ZEROS_SIZE 220
#define SIG_ONES_SIZE 4
#define SIG_BLOCK_SIZE (SIG_ZEROS_SIZE + SIG_ONES_SIZE + CMD_HASH_SIZE)
#define FRAME_TYPE_MASK 0xc0
#define PROTOCOL_MASK 0x3F
#define CMD_PACKET_SIZE 192

#define ID_TIME 0x01
#define ID_TEST 0x02

typedef struct __attribute__((__packed__)) {
  uint64_t sequence;
  uint8_t type;
  uint8_t reserved[3];
  uint8_t contents[180];
} cmd_packet_t;

typedef struct __attribute__((__packed__)) {
  uint8_t hash_key[CMD_HASH_SIZE];
  uint8_t hash_msg[CMD_HASH_SIZE];
  uint8_t sig_part[CMD_BLOCK_SIZE / 2];
} cmd_signature_t;

void command_init();
void command_receive(const lownet_frame_t* frame);
#endif
