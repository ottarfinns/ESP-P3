#include "cmd_util.h"

#include <string.h>

#include "esp_log.h"
#include "mbedtls/sha256.h"
#include "utility.h"

#define TAG "CMD_UTIL"

bool parse_cmd_packet(const uint8_t* payload, size_t len,
                      cmd_packet_t* packet_out) {
  if (!payload || !packet_out) return false;

  size_t header_len = offsetof(cmd_packet_t, contents);
  size_t max_len = sizeof(cmd_packet_t);

  if (len > max_len || len < header_len) return false;

  memset(packet_out, 0, sizeof(*packet_out));
  memcpy(packet_out, payload, header_len);

  size_t contents_len = len - header_len;

  if (contents_len > sizeof(packet_out->contents)) return false;

  memcpy(packet_out->contents, payload + header_len, contents_len);
  return true;
}
bool parse_cmd_signature(const uint8_t* payload, size_t len,
                         cmd_signature_t* sig_out) {
  if (!payload || !sig_out) return false;
  if (len != sizeof(cmd_signature_t)) return false;
  memcpy(sig_out, payload, len);
  return true;
}

void compute_sha256(const uint8_t* data, size_t len,
                    uint8_t buf[CMD_HASH_SIZE]) {
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);
  mbedtls_sha256_update(&ctx, data, len);
  mbedtls_sha256_finish(&ctx, buf);
  mbedtls_sha256_free(&ctx);
}

// bool check_fields
bool compare_fields(const lownet_frame_t* a, const lownet_frame_t* b) {
  const uint8_t proto1 = a->protocol & PROTOCOL_MASK;
  const uint8_t proto2 = b->protocol & PROTOCOL_MASK;

  return a->source == b->source && a->destination == b->destination &&
         proto1 == proto2;
}

bool check_time(const lownet_time_t* start_time) {
  const lownet_time_t now = lownet_get_time();
  const lownet_time_t diff = time_diff(start_time, &now);
  const lownet_time_t max_time = {10, 0};
  bool res = compare_time(&diff, &max_time) > 0;

  return !res;
}

void to_hex(const uint8_t* hash, char* out_str) {
  for (int i = 0; i < CMD_HASH_SIZE; i++) {
    sprintf(out_str + (i * 2), "%02x", hash[i]);
  }
  out_str[CMD_HASH_SIZE * 2] = '\0';
}

bool compare_hashes(const uint8_t* a, const uint8_t* b) {
  bool mismatch = false;
  for (int i = 0; i < CMD_HASH_SIZE; i++) {
    if (a[i] == b[i]) {
      continue;
    } else {
      ESP_LOGW(TAG, "Character mismatch between buffers. a[%d]: %u, b[%d]: %u",
               i, a[i], i, b[i]);
      mismatch = true;
    }
  }
  return !mismatch;
}
