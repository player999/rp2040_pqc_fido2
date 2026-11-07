#include "tusb.h"
#include "pico/unique_id.h"
#include "user_presence.h"

#define USBD_VID 0x2E8A
#define USBD_PID 0x1050

//--------------------------------------------------------------------+
// Device Descriptor
//--------------------------------------------------------------------+
tusb_desc_device_t const desc_device = {
    .bLength            = sizeof(tusb_desc_device_t),
    .bDescriptorType    = TUSB_DESC_DEVICE,
    .bcdUSB             = 0x0200,
    .bDeviceClass       = 0xEF, // Miscellaneous (IAD composite)
    .bDeviceSubClass    = 0x02, // Common Class
    .bDeviceProtocol    = 0x01, // Interface Association Descriptor
    .bMaxPacketSize0    = CFG_TUD_ENDPOINT0_SIZE,

    .idVendor           = USBD_VID,
    .idProduct          = USBD_PID,
    .bcdDevice          = 0x0100,

    .iManufacturer      = 0x01,
    .iProduct           = 0x02,
    .iSerialNumber      = 0x03,

    .bNumConfigurations = 0x01
};

uint8_t const * tud_descriptor_device_cb(void) {
    return (uint8_t const *) &desc_device;
}

//--------------------------------------------------------------------+
// HID Report Descriptor (FIDO2 / CTAPHID 64-byte IN/OUT)
//--------------------------------------------------------------------+
uint8_t const desc_hid_report[] = {
    0x06, 0xD0, 0xF1, // USAGE_PAGE (FIDO Alliance: 0xF1D0)
    0x09, 0x01,       // USAGE (U2F / CTAPHID: 0x01)
    0xA1, 0x01,       // COLLECTION (Application)
    0x09, 0x20,       //   USAGE (Data In)
    0x15, 0x00,       //   LOGICAL_MINIMUM (0)
    0x26, 0xFF, 0x00, //   LOGICAL_MAXIMUM (255)
    0x75, 0x08,       //   REPORT_SIZE (8)
    0x95, 0x40,       //   REPORT_COUNT (64)
    0x81, 0x02,       //   INPUT (Data,Var,Abs)
    0x09, 0x21,       //   USAGE (Data Out)
    0x15, 0x00,       //   LOGICAL_MINIMUM (0)
    0x26, 0xFF, 0x00, //   LOGICAL_MAXIMUM (255)
    0x75, 0x08,       //   REPORT_SIZE (8)
    0x95, 0x40,       //   REPORT_COUNT (64)
    0x91, 0x02,       //   OUTPUT (Data,Var,Abs)
    0xC0              // END_COLLECTION
};

uint8_t const * tud_hid_descriptor_report_cb(uint8_t itf) {
    (void) itf;
    return desc_hid_report;
}

//--------------------------------------------------------------------+
// Configuration Descriptor (HID + CDC)
//--------------------------------------------------------------------+
enum {
    ITF_NUM_HID = 0,
    ITF_NUM_CDC,
    ITF_NUM_CDC_DATA,
    ITF_NUM_TOTAL
};

#define EPNUM_HID       0x01
#define EPNUM_CDC_NOTIF 0x02
#define EPNUM_CDC_DATA  0x03

#define CONFIG_TOTAL_LEN (TUD_CONFIG_DESC_LEN + TUD_HID_INOUT_DESC_LEN + TUD_CDC_DESC_LEN)

uint8_t const desc_configuration[] = {
    // Config number, interface count, string index, total length, attribute, power in mA
    TUD_CONFIG_DESCRIPTOR(1, ITF_NUM_TOTAL, 0, CONFIG_TOTAL_LEN, 0x00, 200),

    // Interface 0: HID (FIDO2)
    TUD_HID_INOUT_DESCRIPTOR(ITF_NUM_HID, 4, HID_ITF_PROTOCOL_NONE, sizeof(desc_hid_report),
                             EPNUM_HID, 0x80 | EPNUM_HID, 64, 5),

    // Interface 1 & 2: CDC Serial
    TUD_CDC_DESCRIPTOR(ITF_NUM_CDC, 5, EPNUM_CDC_NOTIF, 8, EPNUM_CDC_DATA, 0x80 | EPNUM_CDC_DATA, 64)
};

uint8_t const * tud_descriptor_configuration_cb(uint8_t index) {
    (void) index;
    return desc_configuration;
}

//--------------------------------------------------------------------+
// String Descriptors
//--------------------------------------------------------------------+
static char serial_str[33] = "000000000000";

char const* string_desc_arr[] = {
    (const char[]) { 0x09, 0x04 },         // 0: Supported language (0x0409 English)
    "Raspberry Pi",                        // 1: Manufacturer
    "RP2040 PQC FIDO2 Authenticator",     // 2: Product
    serial_str,                            // 3: Serial
    "FIDO2 CTAPHID",                       // 4: HID Interface
    "RP2040 PQC Debug Console",           // 5: CDC Interface
};

static uint16_t _desc_str[64];

uint16_t const* tud_descriptor_string_cb(uint8_t index, uint16_t langid) {
    (void) langid;
    uint8_t chr_count;

    if (index == 0) {
        memcpy(&_desc_str[1], string_desc_arr[0], 2);
        chr_count = 1;
    } else {
        if (index == 3) {
            // Generate serial from unique board ID
            pico_unique_board_id_t id;
            pico_get_unique_board_id(&id);
            for (int i = 0; i < 8; ++i) {
                snprintf(serial_str + (i * 2), 3, "%02X", id.id[i]);
            }
        }

        if (index >= sizeof(string_desc_arr) / sizeof(string_desc_arr[0])) return NULL;

        const char* str = string_desc_arr[index];
        chr_count = (uint8_t)strlen(str);
        if (chr_count > 63) chr_count = 63;

        for (uint8_t i = 0; i < chr_count; i++) {
            _desc_str[1 + i] = str[i];
        }
    }

    _desc_str[0] = (uint16_t)((TUSB_DESC_STRING << 8) | (2 * chr_count + 2));
    return _desc_str;
}

// Support 1200 baud touch to reboot into BOOTSEL mode
void tud_cdc_line_coding_cb(uint8_t itf, cdc_line_coding_t const* p_line_coding) {
    (void) itf;
    if (p_line_coding->bit_rate == 1200) {
        user_presence_reboot_to_bootloader();
    }
}
