#include "command.h"

#include <string.h>

#include "cmd_util.h"
#include "esp_log.h"
#include "lownet.h"
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
// #include "mbedtls/sha256.h"
#include "ping.h"
#include "serial_io.h"
// #include "utility.h"

#define TAG "COMMAND"

enum l_state {
  LISTENING,
  LISTENING_SIG,
};

static struct {
  enum l_state listening_state;
  lownet_frame_t frame;
  uint8_t hash_k[CMD_HASH_SIZE];
  uint8_t hash_m[CMD_HASH_SIZE];
  cmd_signature_t sig1;
  cmd_signature_t sig2;
  bool sig1_received;
  bool sig2_received;
  lownet_time_t time_start;
  uint64_t last_seq;
} state;

static mbedtls_pk_context pk_ctx;
static bool pk_ready = false;
static bool state_initialized = false;

enum frame_type { FRAME_NORMAL = 0, FRAME_SIGNED, FRAME_SIG1, FRAME_SIG2 };

static void cmd_rsa_init() {
  const char* public_key = lownet_get_signing_key();
  mbedtls_pk_init(&pk_ctx);
  int pk_res = mbedtls_pk_parse_public_key(&pk_ctx, (const uint8_t*)public_key,
                                           strlen(public_key) + 1);
  if (pk_res == 0 && mbedtls_pk_can_do(&pk_ctx, MBEDTLS_PK_RSA)) {
    pk_ready = true;
  } else {
    ESP_LOGE(TAG, "pk_parse_public_key failed");
  }
}
static void perform_rsa_operation(const uint8_t* signature, uint8_t buf[256]) {
  if (!pk_ready) {
    memset(buf, 0, 256);
    return;
  }

  mbedtls_rsa_context* rsa_ctx = mbedtls_pk_rsa(pk_ctx);
  if (mbedtls_rsa_public(rsa_ctx, signature, buf)) {
    memset(buf, 0, 256);
  }
}

void reset_state() {
  uint64_t last_seq = state.last_seq;
  uint8_t hash_k[CMD_HASH_SIZE];
  memcpy(hash_k, state.hash_k, CMD_HASH_SIZE);

  memset(&state, 0, sizeof(state));

  state.last_seq = last_seq;
  memcpy(state.hash_k, hash_k, CMD_HASH_SIZE);
  state.listening_state = LISTENING;
  ESP_LOGI(TAG, "State has been reset");
}

void command_init() {
  // We want to compute the hash of the key which will be a constant so we do it
  // in the initializing function
  if (lownet_register_protocol(LOWNET_PROTOCOL_COMMAND, command_receive) != 0) {
    ESP_LOGE(TAG, "Error registering COMMAND protocol");
  }

  if (state_initialized) {
    ESP_LOGE(TAG, "Command already initialized");
    return;
  } else {
    state_initialized = true;
    memset(&state, 0, sizeof(state));
    state.listening_state = LISTENING;
    state.last_seq = 0;
  }

  const char* pem = lownet_get_signing_key();
  if (pem && *pem) {
    compute_sha256((const unsigned char*)pem, strlen(pem), state.hash_k);
  } else {
    ESP_LOGE(TAG, "Signing key not set");
  }

  cmd_rsa_init();
}

void cmd_time(const cmd_packet_t* command) {
  lownet_time_t time;
  memcpy(&time, command->contents, sizeof(time));
  lownet_set_time(&time);
}
void cmd_test(const uint8_t* payload, uint8_t length) {
  ping(state.frame.source, payload, length);
}

void handle_command() {
  cmd_packet_t command;
  if (!parse_cmd_packet(state.frame.payload, state.frame.length, &command)) {
    ESP_LOGW(TAG, "Command packet parsing failed");
    return;
  }

  // Check sequence number, strictly increasing

  if (command.sequence <= state.last_seq) {
    ESP_LOGW(TAG, "Command sequence must be strictly increasing");
    return;
  }

  uint8_t id = command.type;

  if (id == ID_TIME) {
    serial_write_line("Time command called");
    cmd_time(&command);
  } else if (id == ID_TEST) {
    serial_write_line("Test command called");
    uint8_t len = state.frame.length - offsetof(cmd_packet_t, contents);
    cmd_test(command.contents, len);
  }
}

void construct_signature_block(uint8_t buf[SIG_BLOCK_SIZE]) {
  memset(buf, 0x00, SIG_ZEROS_SIZE);
  memset(buf + SIG_ZEROS_SIZE, 0x01, SIG_ONES_SIZE);
  memcpy(buf + SIG_ZEROS_SIZE + SIG_ONES_SIZE, state.hash_m, CMD_HASH_SIZE);
}

bool verify_signature() {
  uint8_t sig[SIG_BLOCK_SIZE];
  memcpy(sig, state.sig1.sig_part, SIG_BLOCK_SIZE / 2);
  memcpy(sig + (SIG_BLOCK_SIZE / 2), state.sig2.sig_part, SIG_BLOCK_SIZE / 2);

  uint8_t sig_plain[SIG_BLOCK_SIZE];

  perform_rsa_operation(sig, sig_plain);

  uint8_t sig_expected[SIG_BLOCK_SIZE];
  construct_signature_block(sig_expected);

  if (memcmp(sig_plain, sig_expected, SIG_BLOCK_SIZE) != 0) {
    ESP_LOGW(TAG, "Signature does not match");
    return false;
  }
  return true;
}

void handle_signed_frame(const lownet_frame_t* frame) {
  compute_sha256((const uint8_t*)frame, LOWNET_FRAME_SIZE, state.hash_m);
  memcpy(&state.frame, frame, sizeof(*frame));

  state.time_start = lownet_get_time();
  state.listening_state = LISTENING_SIG;
  ESP_LOGI(TAG, "New signed frame received");
}

void handle_signature_frame(const lownet_frame_t* frame, enum frame_type type) {
  // Check if src, dest and protocol are the same
  if (!compare_fields(frame, &state.frame)) {
    ESP_LOGW(TAG,
             "One of source, destination or protocol fields of signature does "
             "not match signed frame.");
    return;
  }

  cmd_signature_t payload;
  memset(&payload, 0, sizeof(payload));
  if (!parse_cmd_signature(frame->payload, frame->length, &payload)) {
    ESP_LOGW(TAG, "Signature parsing failed");
    return;
  }
  char a[65], b[65];
  to_hex(state.hash_m, a);
  to_hex(payload.hash_msg, b);
  ESP_LOGW(TAG, "h_m(local)=%s", a);
  ESP_LOGW(TAG, "h_m(from sig)=%s", b);
  char c[65], d[65];
  to_hex(state.hash_k, c);
  to_hex(payload.hash_key, d);
  ESP_LOGW(TAG, "h_k(local)=%s", c);
  ESP_LOGW(TAG, "h_k(from sig)=%s", d);

  if (!compare_hashes(payload.hash_key, state.hash_k)) {
    ESP_LOGW(TAG, "Key hash does not match");
    reset_state();
    return;
  }
  // if (memcmp(payload.hash_key, state.hash_k, CMD_HASH_SIZE) != 0) {
  //   ESP_LOGW(TAG, "Key hash does not match");
  //   reset_state();
  //   return;
  // }

  ESP_LOGI(TAG, "Key hash matches");

  if (!compare_hashes(payload.hash_msg, state.hash_m)) {
    ESP_LOGW(TAG, "Message hash does not match");
    reset_state();
    return;
  }
  // if (memcmp(payload.hash_msg, state.hash_m, CMD_HASH_SIZE) != 0) {
  //   ESP_LOGW(TAG, "Message hash does not match");
  //   reset_state();
  //   return;
  // }

  ESP_LOGI(TAG, "Message hash matches");

  if (!check_time(&state.time_start)) {
    ESP_LOGW(TAG, "Time ran out");
    reset_state();
    return;
  }

  // Everything matches so we store the signature
  if (type == FRAME_SIG1 && !state.sig1_received) {
    memcpy(&state.sig1, &payload, sizeof(payload));
    state.listening_state = LISTENING_SIG;
    state.sig1_received = true;
  } else if (type == FRAME_SIG2 && !state.sig2_received) {
    memcpy(&state.sig2, &payload, sizeof(payload));
    state.listening_state = LISTENING_SIG;
    state.sig2_received = true;
  }

  if (state.sig1_received && state.sig2_received) {
    if (verify_signature()) {
      ESP_LOGI(TAG, "Signature has been verified");
      handle_command();
    } else {
      ESP_LOGW(TAG, "RSA signature verification failed");
    }
    reset_state();
  }
}

void command_receive(const lownet_frame_t* frame) {
  // Check for flags
  enum frame_type ft =
      (enum frame_type)(frame->protocol & FRAME_TYPE_MASK) >> 6;

  switch (ft) {
    case FRAME_NORMAL:
      ESP_LOGW(TAG, "The command protocol only handles signed frames");
      return;

    case FRAME_SIGNED:
      handle_signed_frame(frame);
      break;

    case FRAME_SIG1:
      ESP_LOGI(TAG, "Signature frame 1 received");
      handle_signature_frame(frame, FRAME_SIG1);
      break;

    case FRAME_SIG2:
      ESP_LOGI(TAG, "Signature frame 2 received");
      handle_signature_frame(frame, FRAME_SIG2);
      break;

    default:
      serial_write_line("Unknown frame type");
      break;
  }
}
