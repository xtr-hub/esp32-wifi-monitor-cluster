#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_event.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_ota_ops.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#if CONFIG_MONITOR_STATUS_LED_GPIO >= 0
#include "led_strip.h"
#endif
#include "mdns.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"

#define REPORT_PERIOD_MS 1000
#define STATUS_PERIOD_MS 5000
#define BUCKET_COUNT 256
#define CAPTURE_MAX_FRAME_LEN 2500
#define CAPTURE_QUEUE_DEPTH 32
#define CAPTURE_HEADER_LEN 10
#define CAPTURE_ENTRY_HEADER_LEN 4
#define CAPTURE_BATCH_LIMIT 1400
#define CAPTURE_DATAGRAM_SIZE (CAPTURE_HEADER_LEN + CAPTURE_ENTRY_HEADER_LEN + CAPTURE_MAX_FRAME_LEN)
#define CAPTURE_MAGIC "RWF1"

static const char *TAG = "wifi-monitor";
static QueueHandle_t g_packets;
static bool g_network_enabled;
static volatile bool g_connected;
static volatile bool g_has_ip;
static volatile uint32_t g_dropped;
static char g_ip[16] = "0.0.0.0";
static char g_bssid[18] = "00:00:00:00:00:00";
static uint8_t g_channel;
static uint8_t g_node_mac[6];
static volatile uint32_t g_pcap_dropped;
static volatile uint32_t g_wifi_join_started_ms;

#define CONFIG_NAMESPACE "monitor"
#define CONFIG_NAME_MAX 33
#define CONFIG_BODY_MAX 512

typedef struct {
    char collector_ip[16];
    uint16_t collector_port;
    char node_name[CONFIG_NAME_MAX];
    uint16_t max_kbps;
} runtime_config_t;

// Collector address and node name can be overridden at runtime through
// POST /config and survive reboots in NVS, so a DHCP change on the collector
// host no longer requires reflashing every board.
static runtime_config_t g_config;
static SemaphoreHandle_t g_config_mutex;
static struct sockaddr_in g_destination;
static char g_node_id[18];
static char g_mdns_hostname[24];

static void destination_from_config(void)
{
    g_destination.sin_family = AF_INET;
    g_destination.sin_port = htons(g_config.collector_port);
    g_destination.sin_addr.s_addr = inet_addr(g_config.collector_ip);
}

static void config_load(void)
{
    strlcpy(g_config.collector_ip, CONFIG_MONITOR_COLLECTOR_IP, sizeof(g_config.collector_ip));
    g_config.collector_port = CONFIG_MONITOR_COLLECTOR_PORT;
    strlcpy(g_config.node_name, CONFIG_MONITOR_NODE_NAME, sizeof(g_config.node_name));
    g_config.max_kbps = CONFIG_MONITOR_MAX_KBPS;

    nvs_handle_t handle;
    if (nvs_open(CONFIG_NAMESPACE, NVS_READONLY, &handle) != ESP_OK) {
        ESP_LOGI(TAG, "collector %s:%u name %s limit %u KB/s (build defaults)",
                 g_config.collector_ip, g_config.collector_port, g_config.node_name,
                 g_config.max_kbps);
        return;
    }

    char text[CONFIG_NAME_MAX];
    size_t length = sizeof(text);
    if (nvs_get_str(handle, "collector_ip", text, &length) == ESP_OK && text[0]) {
        // Validate the stored value the same way /config does. A corrupted or
        // legacy entry would otherwise reach inet_addr() and silently become
        // INADDR_NONE, i.e. 255.255.255.255, broadcasting telemetry to the LAN.
        struct in_addr parsed_address;
        if (inet_pton(AF_INET, text, &parsed_address) == 1) {
            strlcpy(g_config.collector_ip, text, sizeof(g_config.collector_ip));
        } else {
            ESP_LOGW(TAG, "ignoring invalid stored collector IP; using build default");
        }
    }
    uint16_t port = 0;
    if (nvs_get_u16(handle, "collector_port", &port) == ESP_OK && port != 0) {
        g_config.collector_port = port;
    }
    length = sizeof(text);
    if (nvs_get_str(handle, "node_name", text, &length) == ESP_OK && text[0]) {
        strlcpy(g_config.node_name, text, sizeof(g_config.node_name));
    }
    uint16_t max_kbps = 0;
    if (nvs_get_u16(handle, "max_kbps", &max_kbps) == ESP_OK) {
        g_config.max_kbps = max_kbps;
    }
    nvs_close(handle);
    ESP_LOGI(TAG, "collector %s:%u name %s limit %u KB/s (stored overrides)",
             g_config.collector_ip, g_config.collector_port, g_config.node_name,
             g_config.max_kbps);
}

static esp_err_t config_save(void)
{
    nvs_handle_t handle;
    esp_err_t error = nvs_open(CONFIG_NAMESPACE, NVS_READWRITE, &handle);
    if (error != ESP_OK) return error;
    error = nvs_set_str(handle, "collector_ip", g_config.collector_ip);
    if (error == ESP_OK) error = nvs_set_u16(handle, "collector_port", g_config.collector_port);
    if (error == ESP_OK) error = nvs_set_str(handle, "node_name", g_config.node_name);
    if (error == ESP_OK) error = nvs_set_u16(handle, "max_kbps", g_config.max_kbps);
    if (error == ESP_OK) error = nvs_commit(handle);
    nvs_close(handle);
    return error;
}

#if CONFIG_MONITOR_STATUS_LED_GPIO >= 0
static led_strip_handle_t g_status_led;
static bool g_status_led_ready;

static void set_status_led(uint8_t red, uint8_t green, uint8_t blue)
{
    if (!g_status_led_ready) return;

    esp_err_t error = led_strip_set_pixel(g_status_led, 0, red, green, blue);
    if (error == ESP_OK) error = led_strip_refresh(g_status_led);
    if (error != ESP_OK) {
        g_status_led_ready = false;
        ESP_LOGW(TAG, "status LED update failed; disabling LED indication: %s", esp_err_to_name(error));
    }
}

static void configure_status_led(void)
{
    const led_strip_config_t strip_config = {
        .strip_gpio_num = CONFIG_MONITOR_STATUS_LED_GPIO,
        .max_leds = 1,
        .led_model = LED_MODEL_WS2812,
        .color_component_format = LED_STRIP_COLOR_COMPONENT_FMT_GRB,
        .flags.invert_out = false,
    };
    const led_strip_rmt_config_t rmt_config = {
        .clk_src = RMT_CLK_SRC_DEFAULT,
        .resolution_hz = 10 * 1000 * 1000,
        .mem_block_symbols = 64,
        .flags.with_dma = false,
    };
    esp_err_t error = led_strip_new_rmt_device(&strip_config, &rmt_config, &g_status_led);
    if (error != ESP_OK) {
        ESP_LOGW(TAG, "status LED unavailable on GPIO%d: %s",
                 CONFIG_MONITOR_STATUS_LED_GPIO, esp_err_to_name(error));
        return;
    }
    g_status_led_ready = true;
    ESP_LOGI(TAG, "addressable status LED initialized on GPIO%d",
             CONFIG_MONITOR_STATUS_LED_GPIO);
    // A short, bright pulse makes it easy to distinguish the addressable RGB LED
    // from the board's hardwired power LED during a visual bring-up check.
    set_status_led(64, 64, 64);
    vTaskDelay(pdMS_TO_TICKS(250));
    set_status_led(0, 0, 0);
}

static void status_led_task(void *unused)
{
    enum { LED_WAITING, LED_CONNECTED, LED_TIMEOUT } last_state = LED_TIMEOUT + 1;
    bool blink_on = false;
    uint32_t next_blink_ms = 0;

    while (true) {
        const uint32_t now_ms = (uint32_t)(esp_timer_get_time() / 1000);
        const bool timed_out = now_ms - g_wifi_join_started_ms >=
                               (uint32_t)CONFIG_MONITOR_WIFI_JOIN_TIMEOUT_SECONDS * 1000U;
        const int state = g_has_ip ? LED_CONNECTED : (timed_out ? LED_TIMEOUT : LED_WAITING);

        if (state != last_state) {
            last_state = state;
            if (state == LED_CONNECTED) {
                set_status_led(0, 64, 0);       // green: DHCP completed
                ESP_LOGI(TAG, "status LED: connected");
            } else if (state == LED_TIMEOUT) {
                set_status_led(64, 28, 0);      // orange: offline, retries still active
                ESP_LOGI(TAG, "status LED: join timeout; reconnecting in background");
            } else {
                blink_on = true;
                set_status_led(0, 0, 64);        // blue blink: searching/joining
                ESP_LOGI(TAG, "status LED: waiting for Wi-Fi");
                next_blink_ms = now_ms + 500U;
            }
        } else if (state == LED_WAITING && (int32_t)(now_ms - next_blink_ms) >= 0) {
            blink_on = !blink_on;
            set_status_led(0, 0, blink_on ? 64 : 0);
            next_blink_ms = now_ms + 500U;
        }

        vTaskDelay(pdMS_TO_TICKS(100));
    }
}
#endif

enum { FRAME_MGMT, FRAME_CTRL, FRAME_DATA, FRAME_MISC, FRAME_KINDS };

typedef struct {
    uint8_t channel;
    uint8_t kind;
    int8_t rssi;
    uint16_t length;
    uint16_t capture_length;
    uint8_t frame[CAPTURE_MAX_FRAME_LEN];
} packet_sample_t;

typedef struct {
    uint32_t count;
    uint32_t kinds[FRAME_KINDS];
    int32_t rssi_sum;
    uint32_t bytes;
} frame_bucket_t;

static frame_bucket_t g_buckets[BUCKET_COUNT];
static packet_sample_t g_capture_scratch;
static uint8_t g_capture_datagram[CAPTURE_DATAGRAM_SIZE];

static bool is_cluster_transmitter(const uint8_t *frame, uint16_t length,
                                   wifi_promiscuous_pkt_type_t type)
{
    static const uint8_t cluster_macs[][6] = {
        {0xcc, 0x68, 0xc7, 0x2d, 0xa5, 0x14},
        {0xcc, 0x68, 0xc7, 0x2d, 0xa5, 0x7c},
    };
    if (type == WIFI_PKT_MISC || length < 16) return false;
    const uint8_t *transmitter = frame + 10; // Address 2 in management/data headers.
    if (memcmp(transmitter, g_node_mac, sizeof(g_node_mac)) == 0) return true;
    for (size_t i = 0; i < sizeof(cluster_macs) / sizeof(cluster_macs[0]); ++i) {
        if (memcmp(transmitter, cluster_macs[i], sizeof(g_node_mac)) == 0) return true;
    }
    return false;
}

static void promiscuous_callback(void *buffer, wifi_promiscuous_pkt_type_t type)
{
    const wifi_promiscuous_pkt_t *packet = (const wifi_promiscuous_pkt_t *)buffer;
    packet_sample_t *sample = &g_capture_scratch;
    sample->channel = packet->rx_ctrl.channel;
    sample->kind = type == WIFI_PKT_MGMT ? FRAME_MGMT :
                   type == WIFI_PKT_CTRL ? FRAME_CTRL :
                   type == WIFI_PKT_DATA ? FRAME_DATA : FRAME_MISC;
    sample->rssi = packet->rx_ctrl.rssi;
    sample->length = packet->rx_ctrl.sig_len;
    sample->capture_length = 0;
    if (type != WIFI_PKT_MISC && sample->length <= CAPTURE_MAX_FRAME_LEN &&
        !is_cluster_transmitter(packet->payload, sample->length, type)) {
        sample->capture_length = sample->length;
        memcpy(sample->frame, packet->payload, sample->capture_length);
    } else if (type != WIFI_PKT_MISC) {
        if (sample->length > CAPTURE_MAX_FRAME_LEN) g_pcap_dropped++;
    }
    if (g_packets) {
        if (xQueueSend(g_packets, sample, 0) != pdTRUE) g_dropped++;
    } else {
        g_dropped++;
    }
}

static void wifi_event_handler(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        ESP_ERROR_CHECK(esp_wifi_connect());
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        const bool was_online = g_has_ip;
        g_connected = false;
        g_has_ip = false;
        if (was_online) {
            g_wifi_join_started_ms = (uint32_t)(esp_timer_get_time() / 1000);
        }
        g_channel = 0;
        strlcpy(g_ip, "0.0.0.0", sizeof(g_ip));
        ESP_LOGW(TAG, "Wi-Fi disconnected; reconnecting");
        (void)esp_wifi_connect();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_CONNECTED) {
        const wifi_event_sta_connected_t *event = data;
        g_channel = event->channel;
        snprintf(g_bssid, sizeof(g_bssid), "%02x:%02x:%02x:%02x:%02x:%02x",
                 event->bssid[0], event->bssid[1], event->bssid[2],
                 event->bssid[3], event->bssid[4], event->bssid[5]);
        g_connected = true;
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        const ip_event_got_ip_t *event = data;
        snprintf(g_ip, sizeof(g_ip), IPSTR, IP2STR(&event->ip_info.ip));
        g_has_ip = true;
        ESP_LOGI(TAG, "connected ip=%s channel=%u", g_ip, g_channel);
    }
}

static bool parse_bssid(const char *text, uint8_t out[6])
{
    unsigned values[6];
    if (sscanf(text, "%x:%x:%x:%x:%x:%x", &values[0], &values[1], &values[2],
               &values[3], &values[4], &values[5]) != 6) {
        return false;
    }
    for (int index = 0; index < 6; index++) {
        if (values[index] > 0xff) return false;
        out[index] = (uint8_t)values[index];
    }
    return true;
}

static void configure_wifi(void)
{
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
    init.nvs_enable = false; // Wi-Fi settings are supplied by this app; PHY calibration still uses NVS.
    ESP_ERROR_CHECK(esp_wifi_init(&init));

    g_network_enabled = CONFIG_MONITOR_WIFI_SSID[0] != '\0';
    g_wifi_join_started_ms = (uint32_t)(esp_timer_get_time() / 1000);
    if (g_network_enabled) {
        esp_netif_create_default_wifi_sta();
        ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, wifi_event_handler, NULL));
        ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, wifi_event_handler, NULL));

        wifi_config_t config = {0};
        strlcpy((char *)config.sta.ssid, CONFIG_MONITOR_WIFI_SSID, sizeof(config.sta.ssid));
        strlcpy((char *)config.sta.password, CONFIG_MONITOR_WIFI_PASSWORD, sizeof(config.sta.password));
        config.sta.threshold.authmode = CONFIG_MONITOR_WIFI_PASSWORD[0] == '\0' ?
                                         WIFI_AUTH_OPEN : WIFI_AUTH_WPA2_PSK;
        config.sta.pmf_cfg.capable = true;
        config.sta.pmf_cfg.required = false;
        uint8_t bssid[6];
        if (CONFIG_MONITOR_WIFI_BSSID[0] && parse_bssid(CONFIG_MONITOR_WIFI_BSSID, bssid)) {
            memcpy(config.sta.bssid, bssid, sizeof(bssid));
            config.sta.bssid_set = true;
            ESP_LOGI(TAG, "pinned to BSSID %s", CONFIG_MONITOR_WIFI_BSSID);
        }

        ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
        ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &config));
        ESP_LOGI(TAG, "network reporting enabled; joining configured access point");
    } else {
        ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
        ESP_LOGI(TAG, "no SSID configured; starting standalone passive capture");
    }
    ESP_ERROR_CHECK(esp_wifi_start());

    if (!g_network_enabled) {
#if CONFIG_IDF_TARGET_ESP32C5
#if CONFIG_MONITOR_CAPTURE_5G
        ESP_ERROR_CHECK(esp_wifi_set_band_mode(WIFI_BAND_MODE_5G_ONLY));
#else
        ESP_ERROR_CHECK(esp_wifi_set_band_mode(WIFI_BAND_MODE_2G_ONLY));
#endif
#endif
        ESP_ERROR_CHECK(esp_wifi_set_channel(CONFIG_MONITOR_CAPTURE_CHANNEL, WIFI_SECOND_CHAN_NONE));
        ESP_LOGI(TAG, "listening on channel %u without joining Wi-Fi", CONFIG_MONITOR_CAPTURE_CHANNEL);
    }

    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_CTRL | WIFI_PROMIS_FILTER_MASK_DATA,
    };
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filter));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(promiscuous_callback));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
}

static void send_json(int sock, const struct sockaddr_in *destination,
                      const char *json, size_t length)
{
    if (sock >= 0) {
        (void)sendto(sock, json, length, 0,
                     (const struct sockaddr *)destination, sizeof(*destination));
    }
}

static void begin_capture_datagram(void)
{
    memcpy(g_capture_datagram, CAPTURE_MAGIC, 4);
    memcpy(g_capture_datagram + 4, g_node_mac, sizeof(g_node_mac));
}

static bool send_capture_datagram(int sock, const struct sockaddr_in *destination,
                                  size_t length)
{
    int result = sendto(sock, g_capture_datagram, length, 0,
                        (const struct sockaddr *)destination, sizeof(*destination));
    return result == (int)length;
}

static bool ota_token_ok(httpd_req_t *request)
{
    // An unset or placeholder token must authenticate nothing. Comparing two
    // empty strings would otherwise succeed, because a request carrying an empty
    // X-OTA-Token header yields an empty supplied value -- letting anyone on the
    // LAN push firmware or rewrite the collector address.
    if (CONFIG_MONITOR_OTA_TOKEN[0] == '\0' ||
        strcmp(CONFIG_MONITOR_OTA_TOKEN, "change-this-token") == 0) {
        return false;
    }
    char supplied_token[96] = {0};
    if (httpd_req_get_hdr_value_str(request, "X-OTA-Token", supplied_token,
                                    sizeof(supplied_token)) != ESP_OK) {
        return false;
    }
    if (supplied_token[0] == '\0') {
        return false;
    }
    return strcmp(supplied_token, CONFIG_MONITOR_OTA_TOKEN) == 0;
}

static esp_err_t ota_upload_handler(httpd_req_t *request)
{
    if (!ota_token_ok(request)) {
        httpd_resp_set_status(request, "403 Forbidden");
        httpd_resp_sendstr(request, "OTA token rejected\n");
        return ESP_OK;
    }

    const esp_partition_t *target = esp_ota_get_next_update_partition(NULL);
    if (!target) {
        httpd_resp_set_status(request, "500 Internal Server Error");
        httpd_resp_sendstr(request, "No OTA application slot\n");
        return ESP_OK;
    }
    if ((size_t)request->content_len > target->size) {
        httpd_resp_set_status(request, "413 Payload Too Large");
        httpd_resp_sendstr(request, "OTA image exceeds slot size\n");
        return ESP_OK;
    }

    esp_ota_handle_t handle;
    esp_err_t error = esp_ota_begin(target, OTA_WITH_SEQUENTIAL_WRITES, &handle);
    if (error != ESP_OK) {
        httpd_resp_set_status(request, "500 Internal Server Error");
        httpd_resp_sendstr(request, "OTA begin failed\n");
        return ESP_OK;
    }

    char buffer[4096];
    int remaining = request->content_len;
    while (remaining > 0) {
        int wanted = remaining < (int)sizeof(buffer) ? remaining : (int)sizeof(buffer);
        int received = httpd_req_recv(request, buffer, wanted);
        if (received == HTTPD_SOCK_ERR_TIMEOUT) {
            // A slow link is not a failed upload; retry instead of aborting.
            continue;
        }
        if (received <= 0) {
            esp_ota_abort(handle);
            httpd_resp_set_status(request, "400 Bad Request");
            httpd_resp_sendstr(request, "OTA upload interrupted\n");
            return ESP_OK;
        }
        error = esp_ota_write(handle, buffer, received);
        if (error != ESP_OK) {
            esp_ota_abort(handle);
            httpd_resp_set_status(request, "500 Internal Server Error");
            httpd_resp_sendstr(request, "OTA write failed\n");
            return ESP_OK;
        }
        remaining -= received;
    }

    error = esp_ota_end(handle);
    if (error == ESP_OK) error = esp_ota_set_boot_partition(target);
    if (error != ESP_OK) {
        httpd_resp_set_status(request, "400 Bad Request");
        httpd_resp_sendstr(request, "OTA image rejected\n");
        return ESP_OK;
    }

    httpd_resp_sendstr(request, "OTA accepted; rebooting\n");
    vTaskDelay(pdMS_TO_TICKS(500));
    esp_restart();
    return ESP_OK;
}

static esp_err_t status_handler(httpd_req_t *request)
{
    // Snapshot the mutable configuration under the lock so the JSON cannot mix
    // a half-written name or address with the rest of the response.
    char name[CONFIG_NAME_MAX];
    char collector_ip[16];
    uint16_t collector_port;
    uint16_t max_kbps;
    xSemaphoreTake(g_config_mutex, portMAX_DELAY);
    strlcpy(name, g_config.node_name, sizeof(name));
    strlcpy(collector_ip, g_config.collector_ip, sizeof(collector_ip));
    collector_port = g_config.collector_port;
    max_kbps = g_config.max_kbps;
    xSemaphoreGive(g_config_mutex);

    char json[420];
    int used = snprintf(json, sizeof(json),
        "{\"node\":\"%s\",\"name\":\"%s\",\"ip\":\"%s\",\"channel\":%u,\"bssid\":\"%s\","
        "\"collector_ip\":\"%s\",\"collector_port\":%u,\"max_kbps\":%u,\"hostname\":\"%s.local\"}",
        g_node_id, name, g_ip, g_channel, g_bssid,
        collector_ip, collector_port, max_kbps,
        g_mdns_hostname);
    if (used <= 0 || (size_t)used >= sizeof(json)) {
        return httpd_resp_send_500(request);
    }
    httpd_resp_set_type(request, "application/json");
    return httpd_resp_send(request, json, used);
}

static const char *json_value_start(const char *body, const char *key)
{
    // A quoted key must be preceded by '{' or ',' at the object level. Plain
    // strstr would also match a key name that appears inside a string value,
    // e.g. {"name":"\"collector_ip\":\"9.9.9.9\""}; requiring the separator
    // rejects that shape. Escapes are refused outright by the handler, so the
    // value scan below cannot be confused by them.
    char pattern[24];
    if (snprintf(pattern, sizeof(pattern), "\"%s\"", key) >= (int)sizeof(pattern)) return NULL;
    const char *found = body;
    while ((found = strstr(found, pattern)) != NULL) {
        const char *before = found;
        while (before > body && (before[-1] == ' ' || before[-1] == '\t')) before--;
        if (before == body || before[-1] == '{' || before[-1] == ',') break;
        found++;
    }
    if (!found) return NULL;
    found += strlen(pattern);
    while (*found == ' ' || *found == '\t') found++;
    if (*found != ':') return NULL;
    found++;
    while (*found == ' ' || *found == '\t') found++;
    return found;
}

static bool json_string_field(const char *body, const char *key, char *value, size_t capacity)
{
    const char *found = json_value_start(body, key);
    if (!found || *found != '"') return false;
    found++;
    const char *end = strchr(found, '"');
    if (!end || end == found || (size_t)(end - found) >= capacity) return false;
    memcpy(value, found, (size_t)(end - found));
    value[end - found] = '\0';
    return true;
}

static bool json_number_field(const char *body, const char *key, long *value)
{
    const char *found = json_value_start(body, key);
    if (!found || !(*found == '-' || (*found >= '0' && *found <= '9'))) return false;
    char *end = NULL;
    long parsed = strtol(found, &end, 10);
    if (end == found) return false;
    // Reject trailing garbage such as 8080abc so a malformed body cannot be
    // accepted as a valid number.
    while (*end == ' ' || *end == '\t') end++;
    if (*end != ',' && *end != '}' && *end != '\0') return false;
    *value = parsed;
    return true;
}

static esp_err_t config_handler(httpd_req_t *request)
{
    if (!ota_token_ok(request)) {
        httpd_resp_set_status(request, "403 Forbidden");
        httpd_resp_sendstr(request, "token rejected\n");
        return ESP_OK;
    }
    if (request->content_len <= 0 || request->content_len > CONFIG_BODY_MAX) {
        httpd_resp_set_status(request, "400 Bad Request");
        httpd_resp_sendstr(request, "config JSON body required\n");
        return ESP_OK;
    }

    char body[CONFIG_BODY_MAX + 1];
    // httpd_req_recv can return fewer bytes than requested, so read until the
    // whole declared body has arrived. A short read would otherwise parse a
    // truncated document and apply part of the change while answering 200.
    int received = 0;
    while (received < request->content_len) {
        int chunk = httpd_req_recv(request, body + received,
                                   request->content_len - received);
        if (chunk == HTTPD_SOCK_ERR_TIMEOUT) {
            continue;
        }
        if (chunk <= 0) {
            httpd_resp_set_status(request, "400 Bad Request");
            httpd_resp_sendstr(request, "config body not received\n");
            return ESP_OK;
        }
        received += chunk;
    }
    body[received] = '\0';

    // The flat parser does not unescape, so a backslash anywhere would make the
    // parsed value differ from what the client sent. Refuse it instead of
    // applying something else.
    if (strchr(body, '\\') != NULL) {
        httpd_resp_set_status(request, "400 Bad Request");
        httpd_resp_sendstr(request, "escaped characters are not supported\n");
        return ESP_OK;
    }

    // A flat JSON object is all this endpoint accepts; the fields are validated
    // first so a partially invalid body never changes the running config. Read
    // the current values under the lock to avoid a torn snapshot.
    char ip[16];
    char name[CONFIG_NAME_MAX];
    uint16_t port;
    uint16_t max_kbps;
    xSemaphoreTake(g_config_mutex, portMAX_DELAY);
    strlcpy(ip, g_config.collector_ip, sizeof(ip));
    strlcpy(name, g_config.node_name, sizeof(name));
    port = g_config.collector_port;
    max_kbps = g_config.max_kbps;
    xSemaphoreGive(g_config_mutex);
    bool valid = true;
    bool updated = false;

    if (strstr(body, "\"collector_ip\"")) {
        updated = true;
        // inet_pton, not inet_addr: inet_addr rejects 255.255.255.255, which is
        // exactly the broadcast collector address the capture transport relies
        // on, and it also accepts legacy shorthand such as "10.1".
        struct in_addr parsed_address;
        valid = json_string_field(body, "collector_ip", ip, sizeof(ip)) &&
                inet_pton(AF_INET, ip, &parsed_address) == 1;
    }
    long parsed_port = 0;
    if (valid && strstr(body, "\"collector_port\"")) {
        updated = true;
        valid = json_number_field(body, "collector_port", &parsed_port) &&
                parsed_port >= 1 && parsed_port <= 65535;
        if (valid) port = (uint16_t)parsed_port;
    }
    if (valid && strstr(body, "\"name\"")) {
        updated = true;
        valid = json_string_field(body, "name", name, sizeof(name));
    }
    long parsed_kbps = 0;
    if (valid && strstr(body, "\"max_kbps\"")) {
        updated = true;
        valid = json_number_field(body, "max_kbps", &parsed_kbps) &&
                parsed_kbps >= 0 && parsed_kbps <= 10000;
        if (valid) max_kbps = (uint16_t)parsed_kbps;
    }

    if (!valid || !updated) {
        httpd_resp_set_status(request, "400 Bad Request");
        httpd_resp_sendstr(request, valid ? "no known fields\n" :
                                            "invalid collector_ip, collector_port, name, or max_kbps\n");
        return ESP_OK;
    }

    xSemaphoreTake(g_config_mutex, portMAX_DELAY);
    strlcpy(g_config.collector_ip, ip, sizeof(g_config.collector_ip));
    g_config.collector_port = port;
    strlcpy(g_config.node_name, name, sizeof(g_config.node_name));
    g_config.max_kbps = max_kbps;
    destination_from_config();
    xSemaphoreGive(g_config_mutex);

    esp_err_t error = config_save();
    if (error != ESP_OK) {
        ESP_LOGW(TAG, "config kept in RAM only; NVS write failed: %s", esp_err_to_name(error));
    }
    (void)mdns_instance_name_set(name);
    ESP_LOGI(TAG, "config updated; collector %s:%u name %s limit %u KB/s",
             ip, port, name, max_kbps);
    return status_handler(request);
}

static void start_ota_server(void)
{
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.server_port = CONFIG_MONITOR_OTA_PORT;
    config.stack_size = 8192;
    httpd_handle_t server = NULL;
    if (httpd_start(&server, &config) != ESP_OK) {
        ESP_LOGE(TAG, "failed to start OTA server");
        return;
    }
    httpd_uri_t upload = {
        .uri = "/update",
        .method = HTTP_POST,
        .handler = ota_upload_handler,
        .user_ctx = NULL,
    };
    httpd_uri_t status = {
        .uri = "/status",
        .method = HTTP_GET,
        .handler = status_handler,
        .user_ctx = NULL,
    };
    httpd_uri_t settings = {
        .uri = "/config",
        .method = HTTP_POST,
        .handler = config_handler,
        .user_ctx = NULL,
    };
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &upload));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &status));
    ESP_ERROR_CHECK(httpd_register_uri_handler(server, &settings));
    ESP_LOGI(TAG, "HTTP endpoints ready on port %u: /update /status /config", CONFIG_MONITOR_OTA_PORT);
}

static void start_mdns(void)
{
    if (!g_network_enabled) return;
    esp_err_t error = mdns_init();
    if (error != ESP_OK) {
        ESP_LOGW(TAG, "mDNS unavailable: %s", esp_err_to_name(error));
        return;
    }
    mdns_hostname_set(g_mdns_hostname);
    mdns_instance_name_set(g_config.node_name);
    (void)mdns_service_add(NULL, "_http", "_tcp", CONFIG_MONITOR_OTA_PORT, NULL, 0);
    ESP_LOGI(TAG, "mDNS hosted as %s.local", g_mdns_hostname);
}

static void monitor_task(void *unused)
{
    int sock = g_network_enabled ? socket(AF_INET, SOCK_DGRAM, IPPROTO_IP) : -1;
    if (sock >= 0) {
        int send_buffer = 16384;
        (void)setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &send_buffer, sizeof(send_buffer));
        // Client isolation on the campus APs blocks unicast between wireless
        // clients but still floods broadcast, so a broadcast collector address
        // keeps telemetry flowing without putting the nodes on a second SSID.
        int broadcast = 1;
        (void)setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));
    }
    int64_t started = esp_timer_get_time();
    int64_t last_status = 0;
    int64_t last_report = esp_timer_get_time();
    int64_t tx_credit = 0;
    int64_t tx_credit_us = esp_timer_get_time();
    uint32_t rate_limited = 0;

    // The capture queue is allocated separately and may fail (it is one large
    // contiguous block). Draining a NULL queue would assert or crash, so the task
    // keeps running for telemetry but skips the drain entirely in that case.
    if (g_packets == NULL) {
        ESP_LOGW(TAG, "capture queue unavailable; monitor task will not drain frames");
    }

    while (true) {
        struct sockaddr_in destination;
        uint32_t limit_kbps;
        char node_name[CONFIG_NAME_MAX];
        xSemaphoreTake(g_config_mutex, portMAX_DELAY);
        destination = g_destination;
        limit_kbps = g_config.max_kbps;
        strlcpy(node_name, g_config.node_name, sizeof(node_name));
        xSemaphoreGive(g_config_mutex);
        begin_capture_datagram();
        size_t capture_used = CAPTURE_HEADER_LEN;
        uint32_t capture_records = 0;
        packet_sample_t sample;
        for (unsigned drained = 0;
             g_packets != NULL && drained < CAPTURE_QUEUE_DEPTH;
             ++drained) {
            if (xQueueReceive(g_packets, &sample, 0) != pdTRUE) break;
            if (sock >= 0 && sample.capture_length > 0) {
                size_t record_size = CAPTURE_ENTRY_HEADER_LEN + sample.capture_length;
                if (capture_used + record_size > CAPTURE_BATCH_LIMIT && capture_records > 0) {
                    if (!send_capture_datagram(sock, &destination, capture_used)) {
                        g_pcap_dropped += capture_records;
                    }
                    begin_capture_datagram();
                    capture_used = CAPTURE_HEADER_LEN;
                    capture_records = 0;
                }
                bool over_budget = false;
                if (limit_kbps > 0) {
                    int64_t now_us = esp_timer_get_time();
                    // Credit is bytes: KB/s * 1024 bytes per second.
                    int64_t refill = (now_us - tx_credit_us) * (int64_t)limit_kbps * 1024 / 1000000;
                    if (refill > 0) {
                        tx_credit += refill;
                        tx_credit_us = now_us;
                    }
                    // Allow at most 1/8 second of credit so a burst cannot
                    // stall the shared radio for the laptop's own traffic.
                    int64_t burst = (int64_t)limit_kbps * 1024 / 8;
                    if (tx_credit > burst) tx_credit = burst;
                    if (tx_credit >= (int64_t)record_size) {
                        tx_credit -= (int64_t)record_size;
                    } else {
                        over_budget = true;
                        rate_limited++;
                    }
                }
                if (!over_budget) {
                    g_capture_datagram[capture_used] = sample.channel;
                    g_capture_datagram[capture_used + 1] = (uint8_t)sample.rssi;
                    g_capture_datagram[capture_used + 2] = (uint8_t)(sample.capture_length & 0xff);
                    g_capture_datagram[capture_used + 3] = (uint8_t)(sample.capture_length >> 8);
                    memcpy(g_capture_datagram + capture_used + CAPTURE_ENTRY_HEADER_LEN,
                           sample.frame, sample.capture_length);
                    capture_used += record_size;
                    capture_records++;
                }
            }
            frame_bucket_t *bucket = &g_buckets[sample.channel];
            if (bucket->count == 0) bucket->rssi_sum = 0;
            bucket->count++;
            bucket->kinds[sample.kind < FRAME_KINDS ? sample.kind : FRAME_MISC]++;
            bucket->rssi_sum += sample.rssi;
            bucket->bytes += sample.length;
        }
        if (capture_records > 0 && !send_capture_datagram(sock, &destination, capture_used)) {
            g_pcap_dropped += capture_records;
        }

        int64_t now = esp_timer_get_time();
        if (now - last_report >= REPORT_PERIOD_MS * 1000LL) {
            char json[1900];
            int used = snprintf(json, sizeof(json),
                "{\"node\":\"%s\",\"name\":\"%s\",\"type\":\"frames\",\"uptime_ms\":%" PRId64 ",\"channels\":[",
                g_node_id, node_name, (now - started) / 1000);
            bool first = true;
            for (unsigned channel = 0; channel < BUCKET_COUNT && used > 0 && (size_t)used < sizeof(json); ++channel) {
                frame_bucket_t *bucket = &g_buckets[channel];
                if (bucket->count == 0) continue;
                used += snprintf(json + used, sizeof(json) - (size_t)used,
                    "%s{\"channel\":%u,\"frames\":%" PRIu32 ",\"avg_rssi\":%d,\"bytes\":%" PRIu32 ",\"classes\":{\"mgmt\":%" PRIu32 ",\"ctrl\":%" PRIu32 ",\"data\":%" PRIu32 ",\"misc\":%" PRIu32 "}}",
                    first ? "" : ",", channel, bucket->count,
                    (int)(bucket->rssi_sum / (int32_t)bucket->count), bucket->bytes,
                    bucket->kinds[FRAME_MGMT], bucket->kinds[FRAME_CTRL],
                    bucket->kinds[FRAME_DATA], bucket->kinds[FRAME_MISC]);
                first = false;
                memset(bucket, 0, sizeof(*bucket));
            }
            if (used > 0 && (size_t)used < sizeof(json)) {
                used += snprintf(json + used, sizeof(json) - (size_t)used,
                    "],\"dropped\":%" PRIu32 ",\"pcap_dropped\":%" PRIu32 ",\"rate_limited\":%" PRIu32 "}",
                    (uint32_t)g_dropped, (uint32_t)g_pcap_dropped, rate_limited);
                g_dropped = 0;
                g_pcap_dropped = 0;
                rate_limited = 0;
                if (used > 0 && (size_t)used < sizeof(json)) {
                    if (g_network_enabled) send_json(sock, &destination, json, (size_t)used);
                    else ESP_LOGI(TAG, "%s", json);
                }
            }
            last_report = now;
        }

        if (now - last_status >= STATUS_PERIOD_MS * 1000LL) {
            char json[384];
            int used = snprintf(json, sizeof(json),
                "{\"node\":\"%s\",\"name\":\"%s\",\"type\":\"status\",\"connected\":%s,\"ip\":\"%s\",\"ap_bssid\":\"%s\",\"channel\":%u,\"uptime_ms\":%" PRId64 "}",
                g_node_id, node_name, g_connected ? "true" : "false",
                g_ip, g_bssid, g_channel, (now - started) / 1000);
            if (used > 0 && (size_t)used < sizeof(json)) {
                if (g_network_enabled) send_json(sock, &destination, json, (size_t)used);
                else ESP_LOGI(TAG, "%s", json);
            }
            last_status = now;
        }
        vTaskDelay(1); // One FreeRTOS tick (10 ms here); pdMS_TO_TICKS(1) rounds to zero at 100 Hz.
    }
}

void app_main(void)
{
    esp_err_t nvs_result = nvs_flash_init();
    if (nvs_result == ESP_ERR_NVS_NO_FREE_PAGES || nvs_result == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        nvs_result = nvs_flash_init();
    }
    ESP_ERROR_CHECK(nvs_result);

    ESP_ERROR_CHECK(esp_read_mac(g_node_mac, ESP_MAC_WIFI_STA));
    snprintf(g_node_id, sizeof(g_node_id), "%02x:%02x:%02x:%02x:%02x:%02x",
             g_node_mac[0], g_node_mac[1], g_node_mac[2],
             g_node_mac[3], g_node_mac[4], g_node_mac[5]);
    // Unique per board and stable across reboots, so the mDNS name does not
    // depend on whichever address DHCP hands out.
    snprintf(g_mdns_hostname, sizeof(g_mdns_hostname), "esp-%02x%02x",
             g_node_mac[4], g_node_mac[5]);

    g_config_mutex = xSemaphoreCreateMutex();
    if (!g_config_mutex) {
        ESP_LOGE(TAG, "config mutex allocation failed");
        esp_restart();
    }
    config_load();
    destination_from_config();

    g_packets = xQueueCreate(CAPTURE_QUEUE_DEPTH, sizeof(packet_sample_t));
    if (!g_packets) ESP_LOGE(TAG, "packet queue allocation failed; frame capture disabled");
#if CONFIG_MONITOR_STATUS_LED_GPIO >= 0
    configure_status_led();
#endif
    configure_wifi();
#if CONFIG_MONITOR_STATUS_LED_GPIO >= 0
    if (g_network_enabled && g_status_led_ready &&
        xTaskCreate(status_led_task, "wifi-status-led", 3072, NULL, 1, NULL) != pdPASS) {
        ESP_LOGW(TAG, "status LED task unavailable; capture continues without LED indication");
    }
#endif
    xTaskCreate(monitor_task, "monitor", 8192, NULL, 4, NULL);
    if (g_network_enabled) {
        start_ota_server();
        start_mdns();
    }

    const esp_partition_t *running = esp_ota_get_running_partition();
    esp_ota_img_states_t image_state;
    if (esp_ota_get_state_partition(running, &image_state) == ESP_OK &&
        image_state == ESP_OTA_IMG_PENDING_VERIFY) {
        ESP_ERROR_CHECK(esp_ota_mark_app_valid_cancel_rollback());
        ESP_LOGI(TAG, "OTA image passed startup checks");
    }
}
