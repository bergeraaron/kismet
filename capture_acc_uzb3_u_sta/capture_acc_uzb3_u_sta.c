#define _GNU_SOURCE

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <termios.h>
#include <fcntl.h>

#include "../config.h"

#include "acc_uzb3_u_sta.h"

#include "../capture_framework.h"

#define MODEMDEVICE "/dev/ttyUSB0"

#ifndef CRTSCTS
#define CRTSCTS  020000000000 /*should be defined but isn't with the C99*/
#endif

#define CHECK_BIT(var,pos) ((var) & (1<<(pos)))

/* Unique instance data passed around by capframework */
typedef struct {
    pthread_mutex_t serial_mutex;

    struct termios oldtio, newtio;

    int fd;

    char *name;
    char *interface;

    speed_t baudrate;

    //we will keep a counter of empty length packets
    unsigned int error_ctr;
    unsigned int ping_ctr;

    kis_capture_handler_t *caph;
} local_acc_uzb3_u_sta_t;

int get_baud(int baud)
{
    switch (baud) {
    case 9600:
        return B9600;
    case 19200:
        return B19200;
    case 38400:
        return B38400;
    case 57600:
        return B57600;
    case 115200:
        return B115200;
    case 230400:
        return B230400;
    case 460800:
        return B460800;
    case 500000:
        return B500000;
    case 576000:
        return B576000;
    case 921600:
        return B921600;
    case 1000000:
        return B1000000;
    case 1152000:
        return B1152000;
    case 1500000:
        return B1500000;
    case 2000000:
        return B2000000;
    case 2500000:
        return B2500000;
    case 3000000:
        return B3000000;
    case 3500000:
        return B3500000;
    case 4000000:
        return B4000000;
    default: 
        return -1;
    }
}

bool ping_check(kis_capture_handler_t *caph) {
    local_acc_uzb3_u_sta_t *localacc_uzb3_u_sta = (local_acc_uzb3_u_sta_t *) caph->userdata;
/**
PING_REQ = 0x0D
PING_RESP = 0x0E
**/
    uint8_t buf[255];
    buf[0] = 0x0D;
    uint16_t ctr = 0;
    int8_t res = 0;
    int8_t resp_len = 1;
    bool found = false;
    pthread_mutex_lock(&(localacc_uzb3_u_sta->serial_mutex));

    /* lets flush the buffer */
    tcflush(localacc_uzb3_u_sta->fd, TCIOFLUSH);
    /* we are transmitting something */
    res = write(localacc_uzb3_u_sta->fd, buf, 1);
    if (res < 0) {
        found = false;
    }
    if (resp_len > 0) {
        /* looking for a response */
        while (ctr < 5000) {
            usleep(25);
            memset(buf,0x00,255);
            found = false;
            res = read(localacc_uzb3_u_sta->fd, buf, 255);
            /* currently if we get something back that is fine and continue */
            if (res > 0) {
                found = true;
                break;
            }
            ctr++;
        }
    }
    pthread_mutex_unlock(&(localacc_uzb3_u_sta->serial_mutex));
    return found;
}

int acc_uzb3_u_sta_receive_payload(kis_capture_handler_t *caph, uint8_t *rx_buf, size_t rx_max) {
    local_acc_uzb3_u_sta_t *localacc_uzb3_u_sta = (local_acc_uzb3_u_sta_t *) caph->userdata;

    int actual_len = 0;
    
    pthread_mutex_lock(&(localacc_uzb3_u_sta->serial_mutex));
    actual_len = read(localacc_uzb3_u_sta->fd,rx_buf,rx_max);
    pthread_mutex_unlock(&(localacc_uzb3_u_sta->serial_mutex));

    if(actual_len == 0) {
        localacc_uzb3_u_sta->error_ctr++;
        if(localacc_uzb3_u_sta->error_ctr > 1000000) {
            //try to send a ping packet to verify we are actually talking to the correct device
            if(ping_check(caph)) {
                localacc_uzb3_u_sta->error_ctr = 0;
                localacc_uzb3_u_sta->ping_ctr = 0;
            }
            else {
                //we have an error, or possibly the incorrect serial port
                localacc_uzb3_u_sta->ping_ctr++;
                if(localacc_uzb3_u_sta->ping_ctr > 1000000) {
                    return -1;
                }
            }
        }
    }
    else {
        localacc_uzb3_u_sta->error_ctr = 0;
        localacc_uzb3_u_sta->ping_ctr = 0;
    }

    return actual_len;
}

int probe_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, char **uuid, KismetExternal__Command *frame,
        cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {
 
    char *placeholder = NULL;
    int placeholder_len;
    char *interface;
    char errstr[STATUS_MAX];
    char *device = NULL;

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition"); 
        return 0;
    }

    interface = strndup(placeholder, placeholder_len);

    /* Look for the interface type */
    if (strstr(interface, "acc_uzb3_u_sta51822") != interface) {
        free(interface);
        return 0;
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "device", definition)) > 0) {
        device = strndup(placeholder, placeholder_len);
    } else {
        snprintf(msg, STATUS_MAX, "Expected device= path to serial device in definition");
        return 0;
    }

    /* Make a spoofed, but consistent, UUID based on the adler32 of the interface name 
     * and the serial device */
    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%012X",
                adler32_csum((unsigned char *) "kismet_cap_acc_uzb3_u_sta", 
                    strlen("kismet_cap_acc_uzb3_u_sta")) & 0xFFFFFFFF,
                adler32_csum((unsigned char *) device,
                    strlen(device)));
        *uuid = strdup(errstr);
    }

    /* TI CC 2540 supports 37-39 */
    (*ret_interface)->channels = (char **) malloc(sizeof(char *) * 3);
    for (int i = 37; i < 40; i++) {
        char chstr[4];
        snprintf(chstr, 4, "%d", i);
        (*ret_interface)->channels[i - 37] = strdup(chstr);
    }

    (*ret_interface)->channels_len = 3;

    return 1;
}

int open_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, uint32_t *dlt, char **uuid, KismetExternal__Command *frame,
        cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {

    char *placeholder;
    int placeholder_len;
    char *device = NULL;
    char errstr[STATUS_MAX];

    char *localbaudratestr = NULL;
    unsigned int *localbaudrate = NULL;


    local_acc_uzb3_u_sta_t *localacc_uzb3_u_sta = (local_acc_uzb3_u_sta_t *) caph->userdata;

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition"); 
        return -1;
    }

    localacc_uzb3_u_sta->interface = strndup(placeholder, placeholder_len);

    if ((placeholder_len = cf_find_flag(&placeholder, "name", definition)) > 0) {
        localacc_uzb3_u_sta->name = strndup(placeholder, placeholder_len);
    } else {
        localacc_uzb3_u_sta->name = strdup(localacc_uzb3_u_sta->interface);
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "device", definition)) > 0) {
        device = strndup(placeholder, placeholder_len);
    } else {
        snprintf(msg, STATUS_MAX, "%s expected device= path to serial device in definition",
                localacc_uzb3_u_sta->name);
        return -1;
    }

    //try and find the baudrate
    if ((placeholder_len = cf_find_flag(&placeholder, "baudrate", definition)) > 0) {
        localbaudratestr = strndup(placeholder, placeholder_len);
        localbaudrate = (unsigned int *) malloc(sizeof(unsigned int));
        *localbaudrate = atoi(localbaudratestr); 
        free(localbaudratestr);

        if (localbaudrate == NULL) {
            snprintf(msg, STATUS_MAX,
                    "acc_uzb3_u_sta51822 could not parse baudrate= option provided in source "
                    "definition");
            return -1;
        }
        //better way of doing this?
        localacc_uzb3_u_sta->baudrate = get_baud(*localbaudrate);
    } else {
        localacc_uzb3_u_sta->baudrate = D_BAUDRATE;
    }

    /* Make a spoofed, but consistent, UUID based on the adler32 of the interface name 
     * and the serial device */

    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%012X",
                adler32_csum((unsigned char *) "kismet_cap_acc_uzb3_u_sta", 
                    strlen("kismet_cap_acc_uzb3_u_sta")) & 0xFFFFFFFF,
                adler32_csum((unsigned char *) device,
                    strlen(device)));
        *uuid = strdup(errstr);
    }

    /* open for r/w but no tty */
    localacc_uzb3_u_sta->fd = open(device, O_RDWR | O_NOCTTY );

    if (localacc_uzb3_u_sta->fd < 0) {
        snprintf(msg, STATUS_MAX, "%s failed to open serial device - %s",
                localacc_uzb3_u_sta->name, strerror(errno));
        return -1;
    }

    tcgetattr(localacc_uzb3_u_sta->fd,&localacc_uzb3_u_sta->oldtio); /* save current serial port settings */
    bzero(&localacc_uzb3_u_sta->newtio, sizeof(localacc_uzb3_u_sta->newtio)); /* clear struct for new port settings */

    /* set the baud rate and flags */
    localacc_uzb3_u_sta->newtio.c_cflag = localacc_uzb3_u_sta->baudrate | CRTSCTS | CS8 | CLOCAL | CREAD;

    /* ignore parity errors */
    localacc_uzb3_u_sta->newtio.c_iflag = IGNPAR;

    /* raw output */
    localacc_uzb3_u_sta->newtio.c_oflag = 0;

    /* newtio.c_lflag = ICANON; */

    /* flush and set up */
    tcflush(localacc_uzb3_u_sta->fd, TCIFLUSH);
    tcsetattr(localacc_uzb3_u_sta->fd, TCSANOW, &localacc_uzb3_u_sta->newtio);

    return 1;
}

/* Run a standard glib mainloop inside the capture thread */
void capture_thread(kis_capture_handler_t *caph) {

    local_acc_uzb3_u_sta_t *localacc_uzb3_u_sta = (local_acc_uzb3_u_sta_t *) caph->userdata;

    char errstr[STATUS_MAX];
    uint8_t buf[256];
    int buf_rx_len = 0;
    unsigned char pkt[255];memset(pkt,0x00,255);

    int pkt_start = 0;
    int hdr_len = 0;
    int pkt_len = 0;
    /* int pld_ctr = 0; */
    int pkt_ctr = 0;
    bool valid_pkt = false;

    int r = 0;

    while(1) {
                if (caph->spindown) {
                    /* set the port back to normal */
                    tcsetattr(localacc_uzb3_u_sta->fd,TCSANOW,&localacc_uzb3_u_sta->oldtio);
                    break;
                }

                valid_pkt = false;
                buf_rx_len = acc_uzb3_u_sta_receive_payload(caph, buf, 256);

                if (buf_rx_len < 0) {
                    cf_send_error(caph, 0, errstr);
                    cf_handler_spindown(caph);
                    break;
                }

                /* send the packet along */
                if (pkt_ctr > 0 && valid_pkt) {
                    while (1) {
                        struct timeval tv;

                        gettimeofday(&tv, NULL);

                        if ((r = cf_send_data(caph,
                                        NULL, NULL, NULL,
                                        tv,
                                        0,
                                        pkt_ctr, pkt)) < 0) {
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
        }
    }
    cf_handler_spindown(caph);
}

int main(int argc, char *argv[]) {
    local_acc_uzb3_u_sta_t localacc_uzb3_u_sta = {
        .caph = NULL,
        .name = NULL,
        .interface = NULL,
        .fd = -1,
    };

    kis_capture_handler_t *caph = cf_handler_init("acc_uzb3_u_sta51822");

    if (caph == NULL) {
        fprintf(stderr, "FATAL: Could not allocate basic handler data, your system "
                "is very low on RAM or something is wrong.\n");
        return -1;
    }

    localacc_uzb3_u_sta.caph = caph;

    /* Set the local data ptr */
    cf_handler_set_userdata(caph, &localacc_uzb3_u_sta);

    /* Set the callback for opening  */
    cf_handler_set_open_cb(caph, open_callback);

    /* Set the callback for probing an interface */
    /**/ cf_handler_set_probe_cb(caph, probe_callback); /**/

    /* Set the list callback */
    /* cf_handler_set_listdevices_cb(caph, list_callback); */

    /* Channel callbacks */
    /* cf_handler_set_chantranslate_cb(caph, chantranslate_callback); */
    /* cf_handler_set_chancontrol_cb(caph, chancontrol_callback); */

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

    return 0;
}
