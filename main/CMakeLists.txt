idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    PRIV_REQUIRES app_update esp_event esp_http_server esp_hw_support esp_netif esp_timer esp_wifi freertos led_strip log lwip mdns nvs_flash
)
