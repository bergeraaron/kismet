
#include "../config.h"

#include "hble.h"

#include <libusb-1.0/libusb.h>

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <math.h>

#include "../capture_framework.h"

/* Unique instance data passed around by capframework */
typedef struct {
    libusb_context *libusb_ctx;
    libusb_device_handle *hble_handle;

    unsigned int devno, busno;

    pthread_mutex_t usb_mutex;

    /* we don't want to do a channel query every data response, we just want to 
     * remember the last channel used */
    unsigned int channel;

    /* keep track of our errors so we can reset if needed */
    unsigned int error_ctr;

    /* flag to let use know when we are ready to capture */
    bool ready;

    kis_capture_handler_t *caph;
} local_hble_t;

/* Most basic of channel definitions */
typedef struct {
    unsigned int channel;
} local_channel_t;

unsigned char key[44] = { 0xB2, 0xF9, 0x33, 0xD5, 0xD4, 0xB0, 0x66, 0xD7, 0x11, 0x70,
                            0x56, 0x54, 0xB1, 0x14, 0xD6, 0xBE, 0x65, 0xE3, 0x8A, 0x29,
                            0xD6, 0x14, 0xAE, 0xBA, 0x51, 0x94, 0x11, 0xE7, 0xB1, 0x14,
                            0xB2, 0xF9, 0x33, 0xD5, 0xFE, 0x66, 0x77, 0xFF, 0x62, 0x58,
                            0x8A, 0x12, 0x45, 0x50};

int hble_set_channel(kis_capture_handler_t *caph, uint8_t channel) {
    
    int ret = 0;
/**
    local_hble_t *localhble = (local_hble_t *) caph->userdata;

    uint8_t data;
    // two step channel process
    data = channel & 0xFF;
    pthread_mutex_lock(&(localhble->usb_mutex));
    ret = libusb_control_transfer(localhble->hble_handle, hble_DIR_OUT, hble_SET_CHAN, 0x00, 0x00, &data, 1, hble_TIMEOUT);
    pthread_mutex_unlock(&(localhble->usb_mutex));

    if (ret < 0)
        return ret;

    data = (channel >> 8) & 0xFF;
    pthread_mutex_lock(&(localhble->usb_mutex));
    ret = libusb_control_transfer(localhble->hble_handle, hble_DIR_OUT, hble_SET_CHAN, 0x00, 0x01, &data, 1, hble_TIMEOUT);
    pthread_mutex_unlock(&(localhble->usb_mutex));
    if (ret < 0)
        printf("setting channel (LSB) failed!\n");
**/
    return ret;
}

int hble_set_power(kis_capture_handler_t *caph,uint8_t power, int retries) {
    int ret = 0;
/**
    local_hble_t *localhble = (local_hble_t *) caph->userdata;
    int i;

    pthread_mutex_lock(&(localhble->usb_mutex));
    // set power

    ret = libusb_control_transfer(localhble->hble_handle, hble_DIR_OUT, hble_SET_POWER, 0x00, power, NULL, 0, hble_TIMEOUT);

    // get power until it is the same as configured in set_power 
    for (i = 0; i < retries; i++) {
        uint8_t data;
        ret = libusb_control_transfer(localhble->hble_handle, 0xC0, hble_GET_POWER, 0x00, 0x00, &data, 1, hble_TIMEOUT);
        if (ret < 0) {
            pthread_mutex_unlock(&(localhble->usb_mutex));
            return ret;
        }
        if (data == power) {
            pthread_mutex_unlock(&(localhble->usb_mutex));
            return 0;
        }
    }
    pthread_mutex_unlock(&(localhble->usb_mutex));
**/
    return ret;
}

int hble_enter_promisc_mode(kis_capture_handler_t *caph) {
    int ret = 0;
/**
    local_hble_t *localhble = (local_hble_t *) caph->userdata;

    pthread_mutex_lock(&(localhble->usb_mutex));
    ret = libusb_control_transfer(localhble->hble_handle, hble_DIR_OUT, hble_SET_START, 0x00, 0x00, NULL, 0, hble_TIMEOUT);
    pthread_mutex_unlock(&(localhble->usb_mutex));
**/
    return ret;
}

int hble_exit_promisc_mode(kis_capture_handler_t *caph) {
    int ret = 0;
/**
    local_hble_t *localhble = (local_hble_t *) caph->userdata;

    pthread_mutex_lock(&(localhble->usb_mutex));
    ret = libusb_control_transfer(localhble->hble_handle, hble_DIR_OUT, hble_SET_END, 0x00, 0x00, NULL, 0, hble_TIMEOUT);
    pthread_mutex_unlock(&(localhble->usb_mutex));
**/
    return ret;
}

int hble_receive_payload(kis_capture_handler_t *caph, uint8_t *rx_buf, size_t rx_max) {
//printf("hble hble_receive_payload\n");
    local_hble_t *localhble = (local_hble_t *) caph->userdata;
    int actual_len, r;
    
    pthread_mutex_lock(&(localhble->usb_mutex));
    r = libusb_bulk_transfer(localhble->hble_handle, HBLE_PKT_EP, rx_buf, rx_max, &actual_len, HBLE_TIMEOUT);
    pthread_mutex_unlock(&(localhble->usb_mutex));

    //printf("hble_receive_payload r:%d\n",r);

    if (r < 0) {
        localhble->error_ctr++;
        if (localhble->error_ctr >= 10000) {
            return r;
        } else {
            /*continue on for now*/
            return 1;
        }
    }

    localhble->error_ctr = 0; /*we got something valid so reset*/

    //convert
    //printf("hble_receive_payload actual_len:%d\n",actual_len);
    if(actual_len > 0)
    {
        for (int i = 0; i < actual_len; i++)
        {
            if(i >= 10)
            {
                if(i == 18)
                rx_buf[i] = rx_buf[i] ^ rx_buf[4] ^ key[i-10];
                else if(i == 19)
                rx_buf[i] = rx_buf[i] ^ rx_buf[5] ^ key[i-10];
                else if(i == 20)
                rx_buf[i] = rx_buf[i] ^ rx_buf[6] ^ key[i-10];
                else if(i == 21)
                rx_buf[i] = rx_buf[i] ^ rx_buf[7] ^ key[i-10];
                else if(i == 22)
                rx_buf[i] = rx_buf[i] ^ rx_buf[8] ^ key[i-10];
                else if(i == 23)
                rx_buf[i] = rx_buf[i] ^ rx_buf[9] ^ key[i-10];
                else
                rx_buf[i] = rx_buf[i] ^ key[i-10];
            }
        }
    }
    else
        actual_len = 1;
    //printf("hble_receive_payload actual_len:%d\n",actual_len);
    return actual_len;
}

int probe_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, char **uuid, KismetExternal__Command *frame,
        cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {
 
//printf("hble probe_callback\n");

    char *placeholder = NULL;
    int placeholder_len;
    char *interface;
    char errstr[STATUS_MAX];

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    int x;
    int busno = -1, devno = -1;

    libusb_device **libusb_devs = NULL;
    ssize_t libusb_devices_cnt = 0;
    int r;

    int matched_device = 0;

    local_hble_t *localhble = (local_hble_t *) caph->userdata;

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition"); 
        return 0;
    }

    interface = strndup(placeholder, placeholder_len);

    /* Look for the interface type */
    if (strstr(interface, "hble") != interface) {
        free(interface);
        return 0;
    }

    /* Look for interface-bus-dev */
    x = sscanf(interface, "hble-%d-%d", &busno, &devno);
    free(interface);

    /* If we don't have a valid busno/devno or malformed interface name */
    if (x != -1 && x != 2) {
        return 0;
    }
    pthread_mutex_lock(&(localhble->usb_mutex));
    libusb_devices_cnt = libusb_get_device_list(localhble->libusb_ctx, &libusb_devs);

    if (libusb_devices_cnt < 0) {
        return 0;
    }

    for (ssize_t i = 0; i < libusb_devices_cnt; i++) {
        struct libusb_device_descriptor dev;

        r = libusb_get_device_descriptor(libusb_devs[i], &dev);

        if (r < 0) {
            continue;
        }

        if (dev.idVendor == HBLE_USB_VENDOR && dev.idProduct == HBLE_USB_PRODUCT) {
            if (busno >= 0) {
                if (busno == libusb_get_bus_number(libusb_devs[i]) &&
                        devno == libusb_get_device_address(libusb_devs[i])) {
                    matched_device = 1;
                    break;
                }
            } else {
                matched_device = 1;
                busno = libusb_get_bus_number(libusb_devs[i]);
                devno = libusb_get_device_address(libusb_devs[i]);
                break;
            }
        }
    }
    libusb_free_device_list(libusb_devs, 1);
    pthread_mutex_unlock(&(localhble->usb_mutex));

    /* Make a spoofed, but consistent, UUID based on the adler32 of the interface name 
     * and the location in the bus */
    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%06X%06X",
                adler32_csum((unsigned char *) "kismet_cap_hble", 
                    strlen("kismet_cap_hble")) & 0xFFFFFFFF,
                busno, devno);
        *uuid = strdup(errstr);
    }

    /* HBLE supports 37-39 */
    (*ret_interface)->channels = (char **) malloc(sizeof(char *) * 3);
    for (int i = 37; i < 40; i++) {
        char chstr[4];
        snprintf(chstr, 4, "%d", i);
        (*ret_interface)->channels[i - 37] = strdup(chstr);
    }

    (*ret_interface)->channels_len = 3;
    return 1;
}

int list_callback(kis_capture_handler_t *caph, uint32_t seqno, char *msg,
                  cf_params_list_interface_t ***interfaces) {
    /* Basic list of devices */
    typedef struct hble_list {
        char *device;
        struct hble_list *next;
    } hble_list_t;

//printf("hble list_callback\n");

    hble_list_t *devs = NULL;
    size_t num_devs = 0;
    libusb_device **libusb_devs = NULL;
    ssize_t libusb_devices_cnt = 0;
    int r;
    char devname[32];
    unsigned int i;

    local_hble_t *localhble = (local_hble_t *) caph->userdata;
    pthread_mutex_lock(&(localhble->usb_mutex));
    libusb_devices_cnt = libusb_get_device_list(localhble->libusb_ctx, &libusb_devs);
    pthread_mutex_unlock(&(localhble->usb_mutex));

    if (libusb_devices_cnt < 0) {
        return 0;
    }

    pthread_mutex_lock(&(localhble->usb_mutex));
    for (ssize_t i = 0; i < libusb_devices_cnt; i++) {
        struct libusb_device_descriptor dev;

        r = libusb_get_device_descriptor(libusb_devs[i], &dev);

        if (r < 0) {
            continue;
        }

        if (dev.idVendor == HBLE_USB_VENDOR && dev.idProduct == HBLE_USB_PRODUCT) {
            snprintf(devname, 32, "hble-%u-%u", libusb_get_bus_number(libusb_devs[i]),
                     libusb_get_device_address(libusb_devs[i]));

            hble_list_t *d = (hble_list_t *) malloc(sizeof(hble_list_t));
            num_devs++;
            d->device = strdup(devname);
            d->next = devs;
            devs = d;
        }
    }

    libusb_free_device_list(libusb_devs, 1);
    pthread_mutex_unlock(&(localhble->usb_mutex));

    if (num_devs == 0) {
        *interfaces = NULL;
        return 0;
    }

    *interfaces =
        (cf_params_list_interface_t **) malloc(sizeof(cf_params_list_interface_t *) * num_devs);

    i = 0;

    while (devs != NULL) {
        hble_list_t *td = devs->next;
        (*interfaces)[i] =
            (cf_params_list_interface_t *) malloc(sizeof(cf_params_list_interface_t));
        memset((*interfaces)[i], 0, sizeof(cf_params_list_interface_t));

        (*interfaces)[i]->interface = devs->device;
        (*interfaces)[i]->flags = NULL;
        (*interfaces)[i]->hardware = strdup("hble");

        free(devs);
        devs = td;

        i++;
    }

    return num_devs;
}

void *chantranslate_callback(kis_capture_handler_t *caph, char *chanstr) {
    local_channel_t *ret_localchan;
    unsigned int parsechan;
    char errstr[STATUS_MAX];
//printf("hble chantranslate_callback\n");
    if (sscanf(chanstr, "%u", &parsechan) != 1) {
        snprintf(errstr, STATUS_MAX, "1 unable to parse requested channel '%s'; hble channels "
                "are from 37 to 39", chanstr);
        cf_send_message(caph, errstr, MSGFLAG_INFO);
        return NULL;
    }

    if (parsechan > 39 || parsechan < 37) {
        snprintf(errstr, STATUS_MAX, "2 unable to parse requested channel '%u'; hble channels "
                "are from 37 to 39", parsechan);
        cf_send_message(caph, errstr, MSGFLAG_INFO);
        return NULL;
    }

    ret_localchan = (local_channel_t *) malloc(sizeof(local_channel_t));
    ret_localchan->channel = parsechan;
    return ret_localchan;
}

int open_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, uint32_t *dlt, char **uuid, KismetExternal__Command *frame,
        cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {


//printf("hble open_callback\n");

    char *placeholder = NULL;
    int placeholder_len;
    char *interface;
    char errstr[STATUS_MAX];

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    int x;
    int busno = -1, devno = -1;

    libusb_device **libusb_devs = NULL;
    libusb_device *matched_dev = NULL;
    ssize_t libusb_devices_cnt = 0;
    int r;

    int matched_device = 0;
    char cap_if[32];
    
    ssize_t i;

    char *localchanstr = NULL;
    unsigned int *localchan = NULL;

    local_hble_t *localhble = (local_hble_t *) caph->userdata;

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition"); 
        return 0;
    }

    interface = strndup(placeholder, placeholder_len);

    /* Look for the interface type */
    if (strstr(interface, "hble") != interface) {
        snprintf(msg, STATUS_MAX, "Unable to find hble interface"); 
        free(interface);
        return -1;
    }

    /* Look for interface-bus-dev */
    x = sscanf(interface, "hble-%d-%d", &busno, &devno);

    free(interface);

    /* If we don't have a valid busno/devno or malformed interface name */
    if (x != -1 && x != 2) {
        snprintf(msg, STATUS_MAX, "Malformed hble interface, expected 'hble' or "
                "'hble-bus#-dev#'"); 
        return -1;
    }

    pthread_mutex_lock(&(localhble->usb_mutex));
    libusb_devices_cnt = libusb_get_device_list(localhble->libusb_ctx, &libusb_devs);
    pthread_mutex_unlock(&(localhble->usb_mutex));

    if (libusb_devices_cnt < 0) {
        snprintf(msg, STATUS_MAX, "Unable to iterate USB devices"); 
        return -1;
    }
    
    pthread_mutex_lock(&(localhble->usb_mutex));
    for (i = 0; i < libusb_devices_cnt; i++) {
        struct libusb_device_descriptor dev;

        r = libusb_get_device_descriptor(libusb_devs[i], &dev);

        if (r < 0) {
            continue;
        }

        if (dev.idVendor == HBLE_USB_VENDOR && dev.idProduct == HBLE_USB_PRODUCT) {
            if (busno >= 0) {
                if (busno == libusb_get_bus_number(libusb_devs[i]) &&
                        devno == libusb_get_device_address(libusb_devs[i])) {
                    matched_device = 1;
                    matched_dev = libusb_devs[i];
                    break;
                }
            } else {
                matched_device = 1;
                busno = libusb_get_bus_number(libusb_devs[i]);
                devno = libusb_get_device_address(libusb_devs[i]);
                matched_dev = libusb_devs[i];
                break;
            }
        }
    }

    if (!matched_device) {
        snprintf(msg, STATUS_MAX, "Unable to find hble USB device");
        return -1;
    }

    libusb_free_device_list(libusb_devs, 1);
    pthread_mutex_unlock(&(localhble->usb_mutex));

    snprintf(cap_if, 32, "hble-%u-%u", busno, devno);

    /* try pulling the channel */
    if ((placeholder_len = cf_find_flag(&placeholder, "channel", definition)) > 0) {
        localchanstr = strndup(placeholder, placeholder_len);
        localchan = (unsigned int *) malloc(sizeof(unsigned int));
        *localchan = atoi(localchanstr);
        free(localchanstr);

        if (localchan == NULL) {
            snprintf(msg, STATUS_MAX,
                     "hble could not parse channel= option provided in source "
                     "definition");
            return -1;
        }
    } else {
        localchan = (unsigned int *) malloc(sizeof(unsigned int));
        *localchan = 37;
    }

    localhble->devno = devno;
    localhble->busno = busno;

    /* Make a spoofed, but consistent, UUID based on the adler32 of the interface name 
     * and the location in the bus */
    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%06X%06X",
                adler32_csum((unsigned char *) "kismet_cap_hble", 
                    strlen("kismet_cap_hble")) & 0xFFFFFFFF,
                busno, devno);
        *uuid = strdup(errstr);
    }

    (*ret_interface)->capif = strdup(cap_if);
    (*ret_interface)->hardware = strdup("hble");

    /* BTLE supports 37-39 */
    (*ret_interface)->channels = (char **) malloc(sizeof(char *) * 3);
    for (int i = 37; i < 40; i++) {
        char chstr[4];
        snprintf(chstr, 4, "%d", i);
        (*ret_interface)->channels[i - 37] = strdup(chstr);
    }

    (*ret_interface)->channels_len = 3;

    pthread_mutex_lock(&(localhble->usb_mutex));

    /* Try to open it */
    //printf("hble libusb_open\n");
    r = libusb_open(matched_dev, &localhble->hble_handle);

    if (r < 0) {
        snprintf(errstr, STATUS_MAX, "Unable to open hble USB interface: %s", 
                libusb_strerror((enum libusb_error) r));
        pthread_mutex_unlock(&(localhble->usb_mutex));
        return -1;
    }
//printf("hble libusb_kernel_driver_active\n");
    if (libusb_kernel_driver_active(localhble->hble_handle, 0)) {
        r = libusb_detach_kernel_driver(localhble->hble_handle, 0); 

        if (r < 0) {
            snprintf(errstr, STATUS_MAX, "Unable to open hble USB interface, "
                    "could not disconnect kernel drivers: %s",
                    libusb_strerror((enum libusb_error) r));
            pthread_mutex_unlock(&(localhble->usb_mutex));
            return -1;
        }
    }
//printf("hble libusb_set_configuration\n");
    r = libusb_set_configuration(localhble->hble_handle, 1);
    if (r < 0) {
        snprintf(errstr, STATUS_MAX,
                 "Unable to open hble USB interface; could not set USB configuration.  Has "
                 "your device been flashed with the sniffer firmware?");
        pthread_mutex_unlock(&(localhble->usb_mutex));
        return -1;
    }
//printf("hble libusb_claim_interface\n");
    /* Try to claim it */
    r = libusb_claim_interface(localhble->hble_handle, 0);
    if (r < 0) {
        if (r == LIBUSB_ERROR_BUSY) {
            /* Try to detach the kernel driver */
            r = libusb_detach_kernel_driver(localhble->hble_handle, 0);
            if (r < 0) {
                snprintf(errstr, STATUS_MAX, "Unable to open hble USB interface, and unable "
                        "to disconnect existing driver: %s", 
                        libusb_strerror((enum libusb_error) r));
                pthread_mutex_unlock(&(localhble->usb_mutex));
                return -1;
            }
        } else {
            snprintf(errstr, STATUS_MAX, "Unable to open hble USB interface: %s",
                    libusb_strerror((enum libusb_error) r));
            pthread_mutex_unlock(&(localhble->usb_mutex));
            return -1;
        }
    }
   
    pthread_mutex_unlock(&(localhble->usb_mutex));
//printf("hble hble_set_power\n");
    hble_set_power(caph, 0x04, HBLE_POWER_RETRIES);
//printf("hble hble_set_channel\n");
    hble_set_channel(caph, *localchan);
    
    localhble->channel = *localchan;
//printf("hble hble_enter_promisc_mode\n");
    hble_enter_promisc_mode(caph);

    localhble->ready = true;

    return 1;
}

int chancontrol_callback(kis_capture_handler_t *caph, uint32_t seqno, void *privchan, char *msg) {
//printf("hble chancontrol_callback\n");
    local_hble_t *localhble = (local_hble_t *) caph->userdata;
    local_channel_t *channel = (local_channel_t *) privchan;
    int r;

    if (privchan == NULL) {
        return 0;
    }

    localhble->ready = false;

    hble_exit_promisc_mode(caph);

    r = hble_set_channel(caph, channel->channel);

    if (r < 0)
        return -1;

    localhble->channel = channel->channel;

    hble_enter_promisc_mode(caph);

    localhble->ready = true;
   
    return 1;
}

/* Run a standard glib mainloop inside the capture thread */
void capture_thread(kis_capture_handler_t *caph) {
//printf("hble capture_thread\n");
    local_hble_t *localhble = (local_hble_t *) caph->userdata;
    char errstr[STATUS_MAX];

    uint8_t usb_buf[256];

    int buf_rx_len, r;

    while (1) {
        if (caph->spindown) {
            /* close usb */
            if (localhble->hble_handle) {
                libusb_close(localhble->hble_handle);
                localhble->hble_handle = NULL;
            }

            break;
        }

        if (localhble->ready) {
            buf_rx_len = hble_receive_payload(caph, usb_buf, 256);
            if (buf_rx_len < 0) {
                snprintf(errstr, STATUS_MAX, "HBLE interface 'hble-%u-%u' closed "
                        "unexpectedly", localhble->busno, localhble->devno);
                cf_send_error(caph, 0, errstr);
                cf_handler_spindown(caph);
                break;
            }

            /* Skip runt packets caused by timeouts */
            if (buf_rx_len == 1)
                continue;

            /* the devices look to report a 4 byte counter/heartbeat, skip it */
            if (buf_rx_len <= 7)
                continue;

            while (1) {
                struct timeval tv;

                gettimeofday(&tv, NULL);

                if ((r = cf_send_data(caph,
                                NULL, NULL, NULL,
                                tv,
                                0,
                                buf_rx_len, usb_buf)) < 0) {
                    cf_send_error(caph, 0, "unable to send DATA frame");
                    cf_handler_spindown(caph);
                } else if (r == 0) {
                    cf_handler_wait_ringbuffer(caph);
                    continue;
                } else {
                    break;
                }
            }
        }
    }

    cf_handler_spindown(caph);
}


int main(int argc, char *argv[]) {
    local_hble_t localhble = {
        .libusb_ctx = NULL,
        .hble_handle = NULL,
        .caph = NULL,
        .error_ctr = 0,
    };

    pthread_mutex_init(&(localhble.usb_mutex), NULL);

    kis_capture_handler_t *caph = cf_handler_init("hble");
    int r;

    if (caph == NULL) {
        fprintf(stderr, "FATAL: Could not allocate basic handler data, your system "
                "is very low on RAM or something is wrong.\n");
        return -1;
    }

    r = libusb_init(&localhble.libusb_ctx);
    if (r < 0) {
        return -1;
    }

    localhble.caph = caph;

    /* Set the local data ptr */
    cf_handler_set_userdata(caph, &localhble);

    /* Set the callback for opening  */
    cf_handler_set_open_cb(caph, open_callback);

    /* Set the callback for probing an interface */
    cf_handler_set_probe_cb(caph, probe_callback);

    /* Set the list callback */
    cf_handler_set_listdevices_cb(caph, list_callback);

    /* Channel callbacks */
    cf_handler_set_chantranslate_cb(caph, chantranslate_callback);
    cf_handler_set_chancontrol_cb(caph, chancontrol_callback);

    /* Set the capture thread */
    cf_handler_set_capture_cb(caph, capture_thread);

    if (cf_handler_parse_opts(caph, argc, argv) < 1) {
        cf_print_help(caph, argv[0]);
        return -1;
    }

    /* Support remote capture by launching the remote loop */
    cf_handler_remote_capture(caph);

    /* Jail our ns */
    cf_jail_filesystem(caph);

    /* Strip our privs */
    cf_drop_most_caps(caph);

    cf_handler_loop(caph);
    libusb_exit(localhble.libusb_ctx);
    
    return 0;
}

