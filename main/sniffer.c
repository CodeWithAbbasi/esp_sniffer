#include <stdio.h>
#include <string.h>
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/uart.h"

#define MAX_APs 20
#define MAX_SSID_LEN 32
#define MAX_MACS 50
#define UART_PORT UART_NUM_0
#define BUF_SIZE 1024

static const char *TAG = "ESP_SNIFFER";

// ---------- Data Structures ----------
typedef struct {
    char ssid[MAX_SSID_LEN];
    int rssi;
    wifi_auth_mode_t authmode;
    uint8_t bssid[6];
    int primary_channel;
} wifi_ap_info_t;

wifi_ap_info_t ap_list[MAX_APs];
int ap_count = 0;

typedef struct {
    uint8_t mac[6];
    int packet_count;
} mac_entry_t;

mac_entry_t mac_dict[MAX_MACS];
int dict_size = 0;

// Target AP chosen by user
uint8_t target_bssid[6];
int target_channel = 1;

// ---------- UART Helper ----------
void uart_read_line(char *buffer, int max_len) {
    int len = 0;
    while (1) {
        uint8_t c;
        int read = uart_read_bytes(UART_PORT, &c, 1, 20 / portTICK_PERIOD_MS);
        if (read > 0) {
            if (c == '\n' || c == '\r') {
                buffer[len] = '\0';
                break;
            } else if (len < max_len - 1) {
                buffer[len++] = c;
            }
        }
        vTaskDelay(10 / portTICK_PERIOD_MS);
    }
}

// ---------- Wi-Fi Scan ----------
void scan_wifi() {
    wifi_scan_config_t scanConf = {
        .ssid = 0,
        .bssid = 0,
        .channel = 0,
        .show_hidden = true
    };

    ESP_ERROR_CHECK(esp_wifi_scan_start(&scanConf, true));

    uint16_t number = MAX_APs;
    wifi_ap_record_t records[MAX_APs];
    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&number, records));
    ap_count = number;

    printf("\nAvailable Wi-Fi Networks:\n");
    for (int i = 0; i < ap_count; i++) {
        strncpy(ap_list[i].ssid, (char *)records[i].ssid, MAX_SSID_LEN);
        ap_list[i].ssid[MAX_SSID_LEN - 1] = '\0';
        ap_list[i].rssi = records[i].rssi;
        ap_list[i].authmode = records[i].authmode;
        memcpy(ap_list[i].bssid, records[i].bssid, 6);
        ap_list[i].primary_channel = records[i].primary;

        printf("[%c] SSID: %s | RSSI: %d | Ch: %d | BSSID: %02x:%02x:%02x:%02x:%02x:%02x\n",
               'A' + i,
               ap_list[i].ssid,
               ap_list[i].rssi,
               ap_list[i].primary_channel,
               ap_list[i].bssid[0], ap_list[i].bssid[1], ap_list[i].bssid[2],
               ap_list[i].bssid[3], ap_list[i].bssid[4], ap_list[i].bssid[5]);
    }
}

// ---------- User Select WiFi ----------
void select_wifi() {
    char input[8];
    printf("\nEnter the letter of the Wi-Fi to sniff:\n");

    uart_read_line(input, sizeof(input));
    char c = input[0];
    if (c >= 'a' && c <= 'z') c -= 32; // uppercase
    int index = c - 'A';

    if (index >= 0 && index < ap_count) {
        printf("\nYou selected: %s\n", ap_list[index].ssid);
        memcpy(target_bssid, ap_list[index].bssid, 6);
        target_channel = ap_list[index].primary_channel;
    } else {
        printf("Invalid selection!\n");
        select_wifi();
    }
}

// ---------- MAC Dictionary Update ----------
void update_mac_dict(const uint8_t *mac) {
    for (int i = 0; i < dict_size; i++) {
        if (memcmp(mac_dict[i].mac, mac, 6) == 0) {
            mac_dict[i].packet_count++;
            return;
        }
    }
    if (dict_size < MAX_MACS) {
        memcpy(mac_dict[dict_size].mac, mac, 6);
        mac_dict[dict_size].packet_count = 1;
        dict_size++;
    }
}

// ---------- Sniffer Packet Handler ----------
static void sniffer_packet_handler(void *buf, wifi_promiscuous_pkt_type_t type) {
    const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *frame = ppkt->payload;

    const uint8_t *bssid = frame + 16;
    if (memcmp(bssid, target_bssid, 6) != 0) {
        return; 
    }

    const uint8_t *src_mac = frame + 10; 
    update_mac_dict(src_mac);

    int rssi = ppkt->rx_ctrl.rssi;
    int channel = ppkt->rx_ctrl.channel;

    ESP_LOGI(TAG, "SRC: %02x:%02x:%02x:%02x:%02x:%02x | RSSI: %d | Ch: %d | MACs: %d",
             src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5],
             rssi, channel, dict_size);
}

// ---------- Start Sniffer ----------
void wifi_sniffer_init() {
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_ERROR_CHECK(esp_wifi_set_channel(target_channel, WIFI_SECOND_CHAN_NONE));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
    esp_wifi_set_promiscuous_rx_cb(&sniffer_packet_handler);
}

// ---------- Main ----------
void app_main(void) {
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());

    // UART setup
    uart_config_t uart_config = {
        .baud_rate = 115200,
        .data_bits = UART_DATA_8_BITS,
        .parity    = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE
    };
    uart_param_config(UART_PORT, &uart_config);
    uart_driver_install(UART_PORT, BUF_SIZE, 0, 0, NULL, 0);

    // Init WiFi
    esp_netif_create_default_wifi_sta();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());

    // Scan & Select
    scan_wifi();
    select_wifi();

    // Switch to sniffer mode
    ESP_ERROR_CHECK(esp_wifi_stop());
    wifi_sniffer_init();

    ESP_LOGI(TAG, "Sniffer started on %02x:%02x:%02x:%02x:%02x:%02x (Ch %d)",
             target_bssid[0], target_bssid[1], target_bssid[2],
             target_bssid[3], target_bssid[4], target_bssid[5], target_channel);
}
