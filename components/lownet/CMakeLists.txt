idf_component_register(
	SRCS "lownet.c" "lownet_crypt.c"
	INCLUDE_DIRS "include"
	REQUIRES "device-table" "serial" "utility" "esp_wifi" "nvs_flash" "esp_timer" "mbedtls"
)
