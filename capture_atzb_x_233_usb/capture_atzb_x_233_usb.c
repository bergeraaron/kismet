/*
    This file is part of Kismet

    Kismet is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    Kismet is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Kismet; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#define _GNU_SOURCE

#include "../config.h"

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <termios.h>
#include <fcntl.h>

#include "atzb_x_233_usb.h"

#include "../capture_framework.h"

#ifndef CRTSCTS
#define CRTSCTS 020000000000 /*should be defined but isn't with the C99*/
#endif


int atzb_receive_payload(kis_capture_handler_t *caph, uint8_t *rx_buf, size_t rx_max);

/* Unique instance data passed around by capframework */
typedef struct {
    pthread_mutex_t serial_mutex;

    struct termios oldtio, newtio;

    int fd;

    unsigned int channel;
    unsigned int prevchannel;
    char *name;
    char *interface;
    
    bool ready;

    kis_capture_handler_t *caph;
} local_atzb_t;

/* Most basic of channel definitions */
typedef struct {
    unsigned int channel;
} local_channel_t;

int atzb_write_cmd(kis_capture_handler_t *caph, uint8_t *tx_buf, size_t tx_len, uint8_t *resp,
                  size_t resp_len, uint8_t *rx_buf, size_t rx_max) {

    uint8_t buf[255];
    uint16_t ctr = 0;
    uint16_t try_ctr = 0;
    int8_t res = 0;
    bool found = false;
    local_atzb_t *localatzb = (local_atzb_t *) caph->userdata;
    pthread_mutex_lock(&(localatzb->serial_mutex));

    if (tx_len > 0) {
        // lets flush the buffer
        printf("flush the buffer\n");
        tcflush(localatzb->fd, TCIOFLUSH);
        // we are transmitting something
printf("write(%ld):",tx_len);
for(int i=0;i<tx_len;i++)
printf("%02X",tx_buf[i]);
printf("\n");
	    res = write(localatzb->fd, tx_buf, tx_len);
            if (res < 0) {
                printf("error write:%d\n",res);
                return res;
            }
        if (resp_len > 0) {
            // looking for a response
            while (ctr < 5000) {
                usleep(25);
                memset(buf,0x00,255);
		found = false;
		res = read(localatzb->fd, buf, 255);
if(res > 0)
{
printf("read(%d):",res);
for(int i=0;i<res;i++)
printf("%02X",buf[i]);
printf("\n");
}
		// currently if we get something back that is fine and continue
                if (res > 0 && memcmp(buf, resp, resp_len) == 0) {
                    found = true;
		    printf("found\n");
                    break;
                } else if (res > 0) {
                        //we got something from the device
//			ctr = 0;
//                        try_ctr++;
//                        if (try_ctr >= 10) {
                            res = -1;  // we fell through
                            printf("too many wrong answers\n");
			    printf("flush the buffer\n");
			    tcflush(localatzb->fd,TCIOFLUSH);
                            break;
//                        }
		}

                ctr++;
            }//looking loop
            if (!found) {
                res = -1;  // we fell through
                printf("not found\n");
	    }
        } else
            res = 1;  // no response requested
    } else if (rx_max > 0) {
        res = read(localatzb->fd, rx_buf, rx_max);
	if (res < 0) {
            printf("Read Error %s\n", strerror(errno));
            usleep(25);
            res = 0;
	}
    }

    pthread_mutex_unlock(&(localatzb->serial_mutex));

    return res;
}

int atzb_receive_payload(kis_capture_handler_t *caph, uint8_t *rx_buf, size_t rx_max) {
    return atzb_write_cmd(caph, NULL, 0, NULL, 0, rx_buf, rx_max);
}

int atzb_reset(kis_capture_handler_t *caph) {
    printf("not really reset\n");

    return 1;
}

int atzb_enter_promisc_mode(kis_capture_handler_t *caph, uint8_t chan) {
    /* first byte is header, last byte is checksum
     * checksum is basic xor of other bits
     * for these we can just used precomputed packets
     */
    int res = 0;
        
    uint8_t cmd_1[5] = {0x01, 0x02, 0x02, 0x04, 0x04};
    uint8_t rep_1[6] = {0x01, 0x03, 0x02, 0x04, 0x38, 0x04};
    res = atzb_write_cmd(caph, cmd_1, 5, rep_1, 6, NULL, 0);
    if (res < 0)
        return res;

    uint8_t cmd_2[5] = {0x01, 0x02, 0x02, 0x0B, 0x04};
    uint8_t rep_2[6] = {0x01, 0x03, 0x02, 0x0B, 0x0B, 0x04};
    res = atzb_write_cmd(caph, cmd_2, 5, rep_2, 6, NULL, 0);
    if (res < 0)
        return res;

    uint8_t cmd_3[5] = {0x01, 0x02, 0x02, 0x03, 0x04};
    uint8_t rep_3[9] = {0x01, 0x06, 0x02, 0x03, 0xC8, 0x00, 0x00, 0x00, 0x04};
    res = atzb_write_cmd(caph, cmd_3, 5, rep_3, 9, NULL, 0);
    if (res < 0)
        return res;

    uint8_t cmd_4[6] = {0x01, 0x03, 0x02, 0x01, 0x0B, 0x04};
    cmd_4[4] = chan;//set the chan
    uint8_t rep_4[6] = {0x01, 0x03, 0x02, 0x01, 0x01, 0x04};
    res = atzb_write_cmd(caph, cmd_4, 6, rep_4, 6, NULL, 0);
    if (res < 0)
        return res;

    uint8_t cmd_5[6] = {0x01, 0x03, 0x02, 0x02, 0x00, 0x04};
    uint8_t rep_5[6] = {0x01, 0x03, 0x02, 0x02, 0x01, 0x04};
    res = atzb_write_cmd(caph, cmd_5, 6, rep_5, 6, NULL, 0);
    if (res < 0)
        return res;

    uint8_t cmd_6[5] = {0x01, 0x02, 0x02, 0x05, 0x04};
    uint8_t rep_6[6] = {0x01, 0x03, 0x02, 0x05, 0x01, 0x04};
    res = atzb_write_cmd(caph, cmd_6, 5, rep_6, 6, NULL, 0);
    if (res < 0)
        return res;

    return res;
}

int atzb_write_cmd_retry(kis_capture_handler_t *caph, uint8_t *tx_buf, size_t tx_len,
                        uint8_t *resp, size_t resp_len, uint8_t *rx_buf, size_t rx_max) {
    int ret = 0;
    int retries = 3;
    int reset = 0;
    while (retries > 0) {
        ret = atzb_write_cmd(caph,tx_buf,tx_len,resp,resp_len,rx_buf,rx_max);
        if (ret >= 0) {
            usleep(50);
            break;
        }
        usleep(100);
        retries--;
        if (retries == 0 && reset == 0) {
            retries = 3;
            reset = 1;
            atzb_reset(caph);
            usleep(200);
        }
    }
    return ret;
}

int atzb_exit_promisc_mode(kis_capture_handler_t *caph) {
    uint8_t cmd[5] = {0x01, 0x02, 0x02, 0x08, 0x04};
    //uint8_t rep[7] = {0x02, 0x4E, 0x80, 0x01, 0x00, 0x00, 0xCF};
    int res = 0;

    res = atzb_write_cmd_retry(caph, cmd, 5, NULL, 0, NULL, 0);

    return res;
}

int atzb_set_channel(kis_capture_handler_t *caph, uint8_t channel) {
    int res = 0;

    res = atzb_exit_promisc_mode(caph);

    if (res < 0) 
        return res;

    res = atzb_enter_promisc_mode(caph, channel);

    return res;
}

int probe_callback(kis_capture_handler_t *caph, uint32_t seqno,
                   char *definition, char *msg, char **uuid,
                   KismetExternal__Command *frame,
                   cf_params_interface_t **ret_interface,
                   cf_params_spectrum_t **ret_spectrum) {
    char *placeholder = NULL;
    int placeholder_len;
    char *interface;
    char errstr[STATUS_MAX];
    char *device = NULL;

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    char cap_if[32];

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition");
        return 0;
    }

    interface = strndup(placeholder, placeholder_len);

    /* Look for the interface type */
    if (strstr(interface, "atzb_x_233_usb") != interface) {
        free(interface);
        return 0;
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "device", definition)) > 0) {
        device = strndup(placeholder, placeholder_len);
    } else {
        snprintf(msg, STATUS_MAX, "Expected device= path to serial device in definition");
        return 0;
    }

    snprintf(cap_if, 32, "atzb_x_233_usb-%012X", adler32_csum((unsigned char *) device, strlen(device)));

    /* Make a spoofed, but consistent, UUID based on the adler32 of the
     * interface name and the serial device */
    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%012X",
                adler32_csum((unsigned char *) "kismet_cap_atzb_x_233_usb",
                    strlen("kismet_cap_atzb_x_233_usb")) & 0xFFFFFFFF,
                adler32_csum((unsigned char *) device, strlen(device)));
        *uuid = strdup(errstr);
    }

    (*ret_interface)->capif = strdup(cap_if);
    (*ret_interface)->hardware = strdup("atzb_x_233_usb");

    /* atzb_x_233_usb supports 11-26 for zigbee */
    char chstr[4];
    int ctr = 0;

    (*ret_interface)->channels = (char **) malloc(sizeof(char *) * 16);

    for (int i = 11; i < 27; i++) {
        snprintf(chstr, 4, "%d", i);
        (*ret_interface)->channels[ctr] = strdup(chstr);
        ctr++;
    }

    (*ret_interface)->channels_len = 16;

    return 1;
}

int open_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, uint32_t *dlt, char **uuid, KismetExternal__Command *frame,
        cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {

printf("open_callback\n");

    char *placeholder;
    int placeholder_len;
    char *device = NULL;
    char errstr[STATUS_MAX];
    int res = 0;

    local_atzb_t *localatzb = (local_atzb_t *) caph->userdata;

    *ret_interface = cf_params_interface_new();

    char cap_if[32];

    char *localchanstr = NULL;
    unsigned int *localchan = NULL;

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition"); 
        return -1;
    }

    localatzb->interface = strndup(placeholder, placeholder_len);

    if ((placeholder_len = cf_find_flag(&placeholder, "name", definition)) > 0) {
        localatzb->name = strndup(placeholder, placeholder_len);
    } else {
        localatzb->name = strdup(localatzb->interface);
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "device", definition)) > 0) {
        device = strndup(placeholder, placeholder_len);
    } else {
        snprintf(msg, STATUS_MAX, "%s expected device= path to serial device in definition",
                localatzb->name);
        return -1;
    }

    // try pulling the channel
    if ((placeholder_len = cf_find_flag(&placeholder, "channel", definition)) > 0) {
        localchanstr = strndup(placeholder, placeholder_len);
        localchan = (unsigned int *) malloc(sizeof(unsigned int));
        *localchan = atoi(localchanstr); 
        free(localchanstr);

        if (localchan == NULL) {
            snprintf(msg, STATUS_MAX,
                    "atzb x 233 usb could not parse channel= option provided in source "
                    "definition");
            return -1;
        }
    } else {
        localchan = (unsigned int *) malloc(sizeof(unsigned int));
        *localchan = 11;
    }
    
    snprintf(cap_if, 32, "atzb_x_233_usb-%012X",adler32_csum((unsigned char *) device, strlen(device)));

    /* Make a spoofed, but consistent, UUID based on the adler32 of the interface name 
     * and the serial device */
    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%012X",
                adler32_csum((unsigned char *) "kismet_cap_atzb_x_233_usb", 
                    strlen("kismet_cap_atzb_x_233_usb")) & 0xFFFFFFFF,
                adler32_csum((unsigned char *) device,
                    strlen(device)));
        *uuid = strdup(errstr);
    }

    (*ret_interface)->capif = strdup(cap_if);
    (*ret_interface)->hardware = strdup("atzb_x_233_usb");

    /* atzb_x_233_usb supports 11-26 for zigbee */
    char chstr[4];
    int ctr = 0;

    (*ret_interface)->channels = (char **) malloc(sizeof(char *) * 16);

    for (int i = 11; i < 27; i++) {
        snprintf(chstr, 4, "%d", i);
        (*ret_interface)->channels[ctr] = strdup(chstr);
        ctr++;
    }

    (*ret_interface)->channels_len = 16;
    if (*localchan > 26) {
        *localchan = 11;
    }

printf("opendevice\n");

    pthread_mutex_lock(&(localatzb->serial_mutex));
    /* open for r/w but no tty */
    localatzb->fd = open(device, O_RDWR | O_NOCTTY);

    if (localatzb->fd < 0) {
        snprintf(msg, STATUS_MAX, "%s failed to open serial device - %s",
                localatzb->name, strerror(errno));
        return -1;
    }

    tcgetattr(localatzb->fd,&localatzb->oldtio); /* save current serial port settings */
    bzero(&localatzb->newtio, sizeof(localatzb->newtio)); /* clear struct for new port settings */

    /* set the baud rate and flags */
    localatzb->newtio.c_cflag = BAUDRATE | CRTSCTS | CS8 | CLOCAL | CREAD;

    /* ignore parity errors */
    localatzb->newtio.c_iflag = IGNPAR;

    /* raw output */
    localatzb->newtio.c_oflag = 0;

    /* newtio.c_lflag = ICANON; */

    /* flush and set up */
    tcflush(localatzb->fd, TCIFLUSH);
    tcsetattr(localatzb->fd, TCSANOW, &localatzb->newtio);

    pthread_mutex_unlock(&(localatzb->serial_mutex));
   
    localatzb->ready = false;
 
    /* atzb_reset(caph); */
/**
    printf("atzb_exit_promisc_mode\n");

    res = atzb_exit_promisc_mode(caph);
    if (res < 0) 
        return -1;
**/

printf("atzb_enter_promisc_mode\n");

    res = atzb_enter_promisc_mode(caph, *localchan);
    if (res < 0) 
        return -1;

    localatzb->channel = *localchan;

    localatzb->ready = true;

    return 1;
}

void *chantranslate_callback(kis_capture_handler_t *caph, char *chanstr) {
    local_channel_t *ret_localchan;
    unsigned int parsechan;
    char errstr[STATUS_MAX];

    if (sscanf(chanstr, "%u", &parsechan) != 1) {
        snprintf(errstr, STATUS_MAX, "1 unable to parse requested channel '%s'; atzb_x_233_usb channels "
                "are from 11 to 26", chanstr);
        cf_send_message(caph, errstr, MSGFLAG_INFO);
        return NULL;
    }

    if (parsechan > 26 || parsechan < 11) {
        snprintf(errstr, STATUS_MAX, "2 unable to parse requested channel '%u'; atzb_x_233_usb channels "
                "are from 11 to 26", parsechan);
        cf_send_message(caph, errstr, MSGFLAG_INFO);
        return NULL;
    }

    ret_localchan = (local_channel_t *) malloc(sizeof(local_channel_t));
    ret_localchan->channel = parsechan;
    return ret_localchan;
}

int chancontrol_callback(kis_capture_handler_t *caph, uint32_t seqno, void *privchan, char *msg) {
    local_atzb_t *localatzb = (local_atzb_t *) caph->userdata;
    local_channel_t *channel = (local_channel_t *) privchan;
    int r;

printf("chancontrol_callback\n");

    if (privchan == NULL) {
        return 0;
    }

    if (localatzb->ready == true) {
        localatzb->ready = false;
        r = atzb_set_channel(caph, channel->channel);
        if (r <= 0) {
            localatzb->ready = false;
            atzb_reset(caph);
            // clear the buffer
            tcflush(localatzb->fd, TCIOFLUSH);
            usleep(350);
            tcflush(localatzb->fd, TCIOFLUSH);
            r = 1;
            localatzb->ready = true;
        } else {
            tcflush(localatzb->fd, TCIOFLUSH);
            localatzb->ready = true;
            localatzb->prevchannel = channel->channel;
        }
    } else {
	    r = 0;
    }
    
    return r;
}

/* Run a standard glib mainloop inside the capture thread */
void capture_thread(kis_capture_handler_t *caph) {
    local_atzb_t *localatzb = (local_atzb_t *) caph->userdata;

    char errstr[STATUS_MAX];
    uint8_t buf[256];
    int buf_rx_len = 0;
    int r = 0;

    while (1) {
        if (caph->spindown) {
            atzb_exit_promisc_mode(caph);
            /* set the port back to normal */
            pthread_mutex_lock(&(localatzb->serial_mutex));
            tcsetattr(localatzb->fd, TCSANOW, &localatzb->oldtio);
            pthread_mutex_unlock(&(localatzb->serial_mutex));
            break;
        }
        buf_rx_len = 0;
        if (localatzb->ready) {
            memset(buf,0x00,256);
            buf_rx_len = atzb_receive_payload(caph, buf, 256);
            if (buf_rx_len < 0) {
                cf_send_error(caph, 0, errstr);
                cf_handler_spindown(caph);
                break;
            }
        }
        if (buf_rx_len > 0) {
            while (1) {
                struct timeval tv;

                gettimeofday(&tv, NULL);

                if ((r = cf_send_data(caph, NULL, NULL, NULL, tv, 0, buf_rx_len,
                                      buf)) < 0) {
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
    local_atzb_t localatzb = {
        .caph = NULL,
        .name = NULL,
        .interface = NULL,
        .fd = -1,
        .ready = false,
        .prevchannel = 0,
    };

    pthread_mutex_init(&(localatzb.serial_mutex), NULL);

    kis_capture_handler_t *caph = cf_handler_init("atzb_x_233_usb");

    if (caph == NULL) {
        fprintf(stderr, "FATAL: Could not allocate basic handler data, your system "
                "is very low on RAM or something is wrong.\n");
        return -1;
    }

    localatzb.caph = caph;

    /* Set the local data ptr */
    cf_handler_set_userdata(caph, &localatzb);

    /* Set the callback for opening  */
    cf_handler_set_open_cb(caph, open_callback);

    /* Set the callback for probing an interface */
    cf_handler_set_probe_cb(caph, probe_callback);

    /* Set the list callback */
    /* cf_handler_set_listdevices_cb(caph, list_callback); */

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

    return 0;
}

