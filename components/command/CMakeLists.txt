idf_component_register(
  SRCS "command.c" "cmd_util.c"
  INCLUDE_DIRS "include"
  REQUIRES "lownet" "mbedtls" "ping"
)
