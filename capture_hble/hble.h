#include "../config.h"

#ifndef __HBLE_H__
#define __HBLE_H__

#define HBLE_USB_VENDOR         0x046f
#define HBLE_USB_PRODUCT        0x37b3

#define HBLE_SET_MODE           0x07
#define HBLE_SET_CHANNEL        0x08
#define HBLE_OPEN_STREAM        0x09
#define HBLE_CLOSE_STREAM       0x0A

#define HBLE_CMD_MODE_AC        0x00
#define HBLE_CMD_MODE_NONE      0x04

#define HBLE_CMD_EP             0x02
#define HBLE_REP_EP             0x81
#define HBLE_PKT_EP             0x83

#define HBLE_TIMEOUT            1000

#define HBLE_POWER_RETRIES 10


#endif