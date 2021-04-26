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

#include "ti_cc26x2r1lp.h"

#include "../capture_framework.h"

#ifndef CRTSCTS
#define CRTSCTS 020000000000 /*should be defined but isn't with the C99*/
#endif


int ti_cc26x2r1lp_receive_payload(kis_capture_handler_t *caph, uint8_t *rx_buf, size_t rx_max);

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
} local_ti_cc26x2r1lp_t;

/* Most basic of channel definitions */
typedef struct {
    unsigned int channel;
} local_channel_t;

int ti_cc26x2r1lp_write_cmd(kis_capture_handler_t *caph, uint8_t *tx_buf, size_t tx_len, uint8_t *resp,
                  size_t resp_len, uint8_t *rx_buf, size_t rx_max) {
if(tx_len > 0)
{
    printf("ti_cc26x2r1lp_write_cmd\n");
    printf("tx_buf:");
    for(int re=0;re<tx_len;re++)
        printf("%02X",tx_buf[re]);
    printf("\n");
    printf("resp:");
    for(int re=0;re<resp_len;re++)
        printf("%02X",resp[re]);
    printf("\n");
}

    unsigned char buf[256];memset(buf,0x00,256);
    unsigned char pkt[256];memset(pkt,0x00,256);
    int actual_len = 0;
    bool endofpkt=false;
    int pkt_ctr = 0;
    unsigned int loop_ctr = 0;
    uint16_t ctr = 0;
    int8_t res = 0;
    bool found = false;
    local_ti_cc26x2r1lp_t *localti_cc26x2r1lp = (local_ti_cc26x2r1lp_t *) caph->userdata;
    pthread_mutex_lock(&(localti_cc26x2r1lp->serial_mutex));

    if (tx_len > 0) {
        /* lets flush the buffer */
        tcflush(localti_cc26x2r1lp->fd, TCIOFLUSH);
        /* we are transmitting something */
	    res = write(localti_cc26x2r1lp->fd, tx_buf, tx_len);
        if (res < 0) {
            return res;
        }
        if (resp_len > 0) {
            /* looking for a response */
            while (ctr < 10) {
                usleep(25);
                memset(buf,0x00,255);
                found = false;
                res = read(localti_cc26x2r1lp->fd, buf, 255);
                /* currently if we get something back that is fine and continue */
                if (res > 0 && memcmp(buf, resp, resp_len) == 0) {
                    printf("found response\n");
                    found = true;
                    break;
                } else if (res > 0) {
                    printf("got a different response\n");
printf("resp:");
for(int re=0;re<res;re++)
    printf("%02X",buf[re]);
printf("\n");
                }
                ctr++;
            }
            if (!found) {
                res = -1;  // we fell through
            }
        } else {
            res = 1;  // no response requested
        }
    } else if (rx_max > 0) {
        while(1) {
            res = read(localti_cc26x2r1lp->fd, buf, 256);
            if(res > 0)
            {
                loop_ctr = 0;
                //printf("payload-- %s:%d\n", buf, res);
                for(int xp = 0;xp < res;xp++)
                {
                    if(buf[xp] == 0x40 && buf[xp+1] == 0x53) {
                            memset(pkt,0x00,256);
                            pkt_ctr = 0;//start over
                            //printf("start over\n");
                    }

                    pkt[pkt_ctr] = buf[xp];

                    //printf("pkt[%d]:%02X buf[%d]:%02X\n",pkt_ctr,pkt[pkt_ctr],xp,buf[xp]);

                    pkt_ctr++;
                    if(pkt_ctr > 254)
                            break;
                    if(buf[xp-1] == 0x40 && buf[xp] == 0x45)
                    {
                        //printf("end of packet\n");
                        endofpkt = true;
                        break;
                    }
                }
                if(pkt_ctr > 0 && endofpkt)
                {
                    //printf("end of packet and copy\n");
                    memcpy(rx_buf,pkt,pkt_ctr);
                    rx_max = pkt_ctr;
                    res = rx_max;
                    break;
                }
            }
            else
            {
                // to keep us from looking for a packet when we only got a partial
                loop_ctr++;
                if(loop_ctr > 1)
                {
                    //printf("stop looking\n");
                    break;
                }
                    
            }
        }
    }

    pthread_mutex_unlock(&(localti_cc26x2r1lp->serial_mutex));

    return res;
}

int ti_cc26x2r1lp_receive_payload(kis_capture_handler_t *caph, uint8_t *rx_buf, size_t rx_max) {
//printf("ti_cc26x2r1lp_receive_payload\n");
    return ti_cc26x2r1lp_write_cmd(caph, NULL, 0, NULL, 0, rx_buf, rx_max);
}

int ti_cc26x2r1lp_reset(kis_capture_handler_t *caph) {
//printf("ti_cc26x2r1lp_reset\n");
/**
    uint8_t cmd_1[6] = {0x02, 0xA3, 0x08, 0x00, 0x00, 0xAB};
    uint8_t buf[256];

    ti_cc26x2r1lp_write_cmd(caph, cmd_1, 6, NULL, 0, NULL, 0);
    usleep(100);
    // lets do some reads, to maybe clear the buffer
    for (int i = 0; i < 100; i++) 
        ti_cc26x2r1lp_receive_payload(caph, buf, 256);
/**/
    return 1;
}

int ti_cc26x2r1lp_enter_promisc_mode(kis_capture_handler_t *caph, uint8_t chan) {
printf("ti_cc26x2r1lp_enter_promisc_mode\n");
    int res = 0;
    //chan = 11;
    if (chan < 30) {
        /* zigbee */

        // set the phy
        cfg_phy[3] = 1;
        //usleep(100);
        res = ti_cc26x2r1lp_write_cmd(caph, cfg_phy, 9, cmd_resp, 9, NULL, 0);
        if(res < 0)
            return res;
        //usleep(100);
        cfg_freq[5] = 0x65 + ((chan - 11) * 0x05);
        cfg_freq[9] = 0xB7 + ((chan - 11) * 0x05);
        // set the channel
        res = ti_cc26x2r1lp_write_cmd(caph, cfg_freq, 12, cmd_resp, 9, NULL, 0);
        if(res < 0)
            return res;
    } else {
        /* bluetooth */

        // set the phy
        //cfg_phy[3] = 0;
        res = ti_cc26x2r1lp_write_cmd(caph, cfg_phy, 9, cmd_resp, 9, NULL, 0);
        if(res < 0)
            return res;
        // set the channel
        res = ti_cc26x2r1lp_write_cmd(caph, cfg_freq, 12, cmd_resp, 9, NULL, 0);
        if(res < 0)
            return res;
    }
    //usleep(100);
    res = ti_cc26x2r1lp_write_cmd(caph, cmd_start, 8, cmd_resp, 9, NULL, 0);
    return res;
}

int ti_cc26x2r1lp_write_cmd_retry(kis_capture_handler_t *caph, uint8_t *tx_buf, size_t tx_len,
                        uint8_t *resp, size_t resp_len, uint8_t *rx_buf, size_t rx_max) {
printf("ti_cc26x2r1lp_write_cmd_retry\n");
    int ret = 0;
    int retries = 3;
    int reset = 0;

    while (retries > 0) {
        ret = ti_cc26x2r1lp_write_cmd(caph,tx_buf,tx_len,resp,resp_len,rx_buf,rx_max);

        if (ret >= 0) {
            usleep(50);
            break;
        }

        usleep(100);
        retries--;

        if (retries == 0 && reset == 0) {
            retries = 3;
            reset = 1;
            ti_cc26x2r1lp_reset(caph);
            usleep(200);
        }
    }

    return ret;
}

int ti_cc26x2r1lp_exit_promisc_mode(kis_capture_handler_t *caph) {
    int res = 0;

    res = ti_cc26x2r1lp_write_cmd_retry(caph, cmd_stop, 8, cmd_resp, 9, NULL, 0);

    return res;
}

int ti_cc26x2r1lp_set_channel(kis_capture_handler_t *caph, uint8_t channel) {

    printf("ti_cc26x2r1lp_set_channel:%d\n",channel);
    int res = 0;
    res = ti_cc26x2r1lp_exit_promisc_mode(caph);

    printf("ti_cc26x2r1lp_exit_promisc_mode res:%d \n",res);

    if (res < 0) 
        return res;

    res = ti_cc26x2r1lp_enter_promisc_mode(caph, channel);

    printf("ti_cc26x2r1lp_enter_promisc_mode:%d res:%d \n",channel,res);

    res = 1;
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
    if (strstr(interface, "ti_cc26x2r1lp") != interface) {
        free(interface);
        return 0;
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "device", definition)) > 0) {
        device = strndup(placeholder, placeholder_len);
    } else {
        snprintf(msg, STATUS_MAX, "Expected device= path to serial device in definition");
        return 0;
    }

    snprintf(cap_if, 32, "ti_cc26x2r1lp-%012X", adler32_csum((unsigned char *) device, strlen(device)));

    /* Make a spoofed, but consistent, UUID based on the adler32 of the
     * interface name and the serial device */
    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%012X",
                adler32_csum((unsigned char *) "kismet_cap_ti_cc26x2r1lp",
                    strlen("kismet_cap_ti_cc26x2r1lp")) & 0xFFFFFFFF,
                adler32_csum((unsigned char *) device, strlen(device)));
        *uuid = strdup(errstr);
    }

    (*ret_interface)->capif = strdup(cap_if);
    (*ret_interface)->hardware = strdup("ti_cc26x2r1lp");

    /* ti_cc26x2r1lp supports 11-26 for zigbee and 37-39 for ble */
    char chstr[4];
    int ctr = 0;
/**
    (*ret_interface)->channels = (char **) malloc(sizeof(char *) * 3);
    for (int i = 37; i < 40; i++) {
        snprintf(chstr, 4, "%d", i);
        (*ret_interface)->channels[ctr] = strdup(chstr);
        ctr++;
    }

    (*ret_interface)->channels_len = 3;// 19
**/
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

    char *placeholder;
    int placeholder_len;
    char *device = NULL;
    char *phy = NULL;
    char errstr[STATUS_MAX];
    int res = 0;

    local_ti_cc26x2r1lp_t *localti_cc26x2r1lp = (local_ti_cc26x2r1lp_t *) caph->userdata;

    *ret_interface = cf_params_interface_new();

    char cap_if[32];

    char *localchanstr = NULL;
    unsigned int *localchan = NULL;

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition"); 
        return -1;
    }

    localti_cc26x2r1lp->interface = strndup(placeholder, placeholder_len);

    if ((placeholder_len = cf_find_flag(&placeholder, "name", definition)) > 0) {
        localti_cc26x2r1lp->name = strndup(placeholder, placeholder_len);
    } else {
        localti_cc26x2r1lp->name = strdup(localti_cc26x2r1lp->interface);
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "device", definition)) > 0) {
        device = strndup(placeholder, placeholder_len);
    } else {
        snprintf(msg, STATUS_MAX, "%s expected device= path to serial device in definition",
                localti_cc26x2r1lp->name);
        return -1;
    }

    // try to pull the phy
    if ((placeholder_len = cf_find_flag(&placeholder, "phy", definition)) > 0) {
        phy = strndup(placeholder, placeholder_len);
    } else {
        phy = strdup("any");
    }

    // try pulling the channel
    if ((placeholder_len = cf_find_flag(&placeholder, "channel", definition)) > 0) {
        localchanstr = strndup(placeholder, placeholder_len);
        localchan = (unsigned int *) malloc(sizeof(unsigned int));
        *localchan = atoi(localchanstr); 
        free(localchanstr);

        if (localchan == NULL) {
            snprintf(msg, STATUS_MAX,
                    "ti_cc26x2r1lp could not parse channel= option provided in source "
                    "definition");
            return -1;
        }
    } else {
        localchan = (unsigned int *) malloc(sizeof(unsigned int));
        *localchan = 11;
    }
    
    snprintf(cap_if, 32, "ti_cc26x2r1lp-%012X",adler32_csum((unsigned char *) device, strlen(device)));

    /* Make a spoofed, but consistent, UUID based on the adler32 of the interface name 
     * and the serial device */
    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%012X",
                adler32_csum((unsigned char *) "kismet_cap_ti_cc26x2r1lp", 
                    strlen("kismet_cap_ti_cc26x2r1lp")) & 0xFFFFFFFF,
                adler32_csum((unsigned char *) device,
                    strlen(device)));
        *uuid = strdup(errstr);
    }

    (*ret_interface)->capif = strdup(cap_if);
    (*ret_interface)->hardware = strdup("ti_cc26x2r1lp");

    /* ti_cc26x2r1lp supports 11-26 for zigbee and 37-39 for ble */
    char chstr[4];
    int ctr = 0;
/**
    if (strcmp(phy, "btle") == 0) {
        (*ret_interface)->channels = (char **) malloc(sizeof(char *) * 3);

        for (int i = 37; i < 40; i++) {
            snprintf(chstr, 4, "%d", i);
            (*ret_interface)->channels[ctr] = strdup(chstr);
            ctr++;
        }

        (*ret_interface)->channels_len = 3;
        if (*localchan < 37) {
            *localchan = 37;
        }
    }
    else if (strcmp(phy, "zigbee") == 0) {
/**/
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
/**
    } else {
        (*ret_interface)->channels = (char **) malloc(sizeof(char *) * 19);

        for (int i = 11; i < 27; i++) {
            snprintf(chstr, 4, "%d", i);
            (*ret_interface)->channels[ctr] = strdup(chstr);
            ctr++;
        }

        for (int i = 37; i < 40; i++) {
            snprintf(chstr, 4, "%d", i);
            (*ret_interface)->channels[ctr] = strdup(chstr);
            ctr++;
        }

        (*ret_interface)->channels_len = 19;
    }
/**/
    pthread_mutex_lock(&(localti_cc26x2r1lp->serial_mutex));
    /* open for r/w but no tty */
    localti_cc26x2r1lp->fd = open(device, O_RDWR | O_NOCTTY);

    if (localti_cc26x2r1lp->fd < 0) {
        snprintf(msg, STATUS_MAX, "%s failed to open serial device - %s",
                localti_cc26x2r1lp->name, strerror(errno));
        return -1;
    }

    tcgetattr(localti_cc26x2r1lp->fd,&localti_cc26x2r1lp->oldtio); /* save current serial port settings */
    bzero(&localti_cc26x2r1lp->newtio, sizeof(localti_cc26x2r1lp->newtio)); /* clear struct for new port settings */

    /* set the baud rate and flags */
    localti_cc26x2r1lp->newtio.c_cflag = BAUDRATE | CRTSCTS | CS8 | CLOCAL | CREAD;

    /* ignore parity errors */
    localti_cc26x2r1lp->newtio.c_iflag = IGNPAR;

    /* raw output */
    localti_cc26x2r1lp->newtio.c_oflag = 0;

    /* newtio.c_lflag = ICANON; */

    localti_cc26x2r1lp->newtio.c_lflag &= ~ICANON; /* Set non-canonical mode */
    localti_cc26x2r1lp->newtio.c_cc[VTIME] = 1; /* Set timeout in deciseconds */

    /* flush and set up */
    tcflush(localti_cc26x2r1lp->fd, TCIFLUSH);
    tcsetattr(localti_cc26x2r1lp->fd, TCSANOW, &localti_cc26x2r1lp->newtio);

    pthread_mutex_unlock(&(localti_cc26x2r1lp->serial_mutex));
   
    localti_cc26x2r1lp->ready = false;
 
    /* ti_cc26x2r1lp_reset(caph); */
    printf("ti_cc26x2r1lp_exit_promisc_mode\n");
    res = ti_cc26x2r1lp_exit_promisc_mode(caph);
    printf("ti_cc26x2r1lp_exit_promisc_mode res:%d\n",res);

    if (res < 0) {
        snprintf(msg, STATUS_MAX, "%s failed to send ti_cc26x2r1lp exit_promisc command (%d)\n", localti_cc26x2r1lp->name, res);
        return -1;
    }

    res = ti_cc26x2r1lp_enter_promisc_mode(caph, *localchan);
    if (res < 0) {
        snprintf(msg, STATUS_MAX, "%s failed to send ti_cc26x2r1lp enter_promisc command (%d)\n", localti_cc26x2r1lp->name, res);
        return -1;
    }

    localti_cc26x2r1lp->channel = *localchan;

    localti_cc26x2r1lp->ready = true;

    return 1;
}

void *chantranslate_callback(kis_capture_handler_t *caph, char *chanstr) {

    local_channel_t *ret_localchan;
    unsigned int parsechan;
    char errstr[STATUS_MAX];

    if (sscanf(chanstr, "%u", &parsechan) != 1) {
        snprintf(errstr, STATUS_MAX, "1 unable to parse requested channel '%s'; ti_cc26x2r1lp channels "
                "are from 11 to 26 and 37 to 39", chanstr);
        cf_send_message(caph, errstr, MSGFLAG_INFO);
        return NULL;
    }

    /* if (parsechan > 39 || parsechan < 37) { */
    if (parsechan > 39 || parsechan < 11) {
        snprintf(errstr, STATUS_MAX, "2 unable to parse requested channel '%u'; ti_cc26x2r1lp channels "
                "are from 11 to 26 and 37 to 39", parsechan);
        cf_send_message(caph, errstr, MSGFLAG_INFO);
        return NULL;
    }

    ret_localchan = (local_channel_t *) malloc(sizeof(local_channel_t));
    ret_localchan->channel = parsechan;
    return ret_localchan;
}

int chancontrol_callback(kis_capture_handler_t *caph, uint32_t seqno, void *privchan, char *msg) {
    local_ti_cc26x2r1lp_t *localti_cc26x2r1lp = (local_ti_cc26x2r1lp_t *) caph->userdata;
    local_channel_t *channel = (local_channel_t *) privchan;
    int r = 1;

    if (privchan == NULL) {
        return 0;
    }
    /* crossing the phy layer */
/**/
    if ( (localti_cc26x2r1lp->prevchannel >= 37 && localti_cc26x2r1lp->prevchannel <= 39) &&
       (channel->channel >= 11 && channel->channel <= 26) ) {
        ti_cc26x2r1lp_reset(caph);
        // clear the buffer
        tcflush(localti_cc26x2r1lp->fd, TCIOFLUSH);
        usleep(350);
        tcflush(localti_cc26x2r1lp->fd, TCIOFLUSH);
    }

    if (localti_cc26x2r1lp->ready == true) {
        localti_cc26x2r1lp->ready = false;
        r = ti_cc26x2r1lp_set_channel(caph, channel->channel);
        if (r <= 0) {
            localti_cc26x2r1lp->ready = false;
            ti_cc26x2r1lp_reset(caph);
            // clear the buffer
            tcflush(localti_cc26x2r1lp->fd, TCIOFLUSH);
            usleep(350);
            tcflush(localti_cc26x2r1lp->fd, TCIOFLUSH);
            r = 1;
            localti_cc26x2r1lp->ready = true;
        } else {
            tcflush(localti_cc26x2r1lp->fd, TCIOFLUSH);
            localti_cc26x2r1lp->ready = true;
            localti_cc26x2r1lp->prevchannel = channel->channel;
        }
    } else {
	    r = 0;
    }
/**/
    return r;
}

/* Run a standard glib mainloop inside the capture thread */
void capture_thread(kis_capture_handler_t *caph) {
    local_ti_cc26x2r1lp_t *localti_cc26x2r1lp = (local_ti_cc26x2r1lp_t *) caph->userdata;

    char errstr[STATUS_MAX];
    uint8_t buf[256];
    int buf_rx_len = 0;
    int r = 0;

    while (1) {
        if (caph->spindown) {
            ti_cc26x2r1lp_exit_promisc_mode(caph);
            /* set the port back to normal */
            pthread_mutex_lock(&(localti_cc26x2r1lp->serial_mutex));
            tcsetattr(localti_cc26x2r1lp->fd, TCSANOW, &localti_cc26x2r1lp->oldtio);
            pthread_mutex_unlock(&(localti_cc26x2r1lp->serial_mutex));
            break;
        }
        buf_rx_len = 0;
        if (localti_cc26x2r1lp->ready) {
            memset(buf,0x00,256);
            buf_rx_len = ti_cc26x2r1lp_receive_payload(caph, buf, 256);
            if (buf_rx_len < 0) {
                cf_send_error(caph, 0, errstr);
                cf_handler_spindown(caph);
                break;
            }
        }

        if (buf_rx_len > 0) {
/**
printf("buf_rx_len:%d\n",buf_rx_len);
for(int re=0;re<buf_rx_len;re++)
printf("%02X",buf[re]);
printf("\n");
**/
            //printf("channel:%d prevchannel:%d\n",(uint8_t)localti_cc26x2r1lp->channel,(uint8_t)localti_cc26x2r1lp->prevchannel);
            /* btle channel is part of the packet, zigbee is not*/
            if((uint8_t)localti_cc26x2r1lp->prevchannel == 0){
                if((uint8_t)localti_cc26x2r1lp->channel >= 11 && (uint8_t)localti_cc26x2r1lp->channel <= 26) {
                    buf[4] = (uint8_t)localti_cc26x2r1lp->channel;
                }
            }
            else {
                if((uint8_t)localti_cc26x2r1lp->prevchannel >= 11 && (uint8_t)localti_cc26x2r1lp->prevchannel <= 26) {
                    buf[4] = (uint8_t)localti_cc26x2r1lp->prevchannel;
                }
            }

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
    local_ti_cc26x2r1lp_t localti_cc26x2r1lp = {
        .caph = NULL,
        .name = NULL,
        .interface = NULL,
        .fd = -1,
        .ready = false,
        .prevchannel = 0,
    };

    pthread_mutex_init(&(localti_cc26x2r1lp.serial_mutex), NULL);

    kis_capture_handler_t *caph = cf_handler_init("ti_cc26x2r1lp");

    if (caph == NULL) {
        fprintf(stderr, "FATAL: Could not allocate basic handler data, your system "
                "is very low on RAM or something is wrong.\n");
        return -1;
    }

    localti_cc26x2r1lp.caph = caph;

    /* Set the local data ptr */
    cf_handler_set_userdata(caph, &localti_cc26x2r1lp);

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

