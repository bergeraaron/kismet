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

#ifndef __ZIGBEE_H__
#define __ZIGBEE_H__ 

#include "config.h"

#include <stdio.h>
#include <time.h>
#include <list>
#include <map>
#include <vector>
#include <algorithm>
#include <string>
#include <memory>

struct _fcf_802_15_4{
    unsigned char type : 3;
    unsigned char security : 1;
    unsigned char pending : 1;
    unsigned char ack_req : 1;
    unsigned char pan_id_comp : 1;
    unsigned char reserved : 1;
    unsigned char sns : 1;
    unsigned char iep : 1;
    unsigned char dest_addr_mode : 2;
    unsigned char frame_ver : 2;
    unsigned char src_addr_mode : 2;
};

class header_802_15_4
{
private:
    /* data */
    uint16_t pkt_ctr = 0;
public:
    _fcf_802_15_4 * fcf_h; //frame control field 802.15.4

    unsigned char seq = 0x00;
    unsigned short dest = 0x0000;
    unsigned short dest_pan = 0x0000;
    unsigned short src = 0x0000;

    header_802_15_4(uint8_t * data,uint16_t pkt_start);
    ~header_802_15_4();
};

header_802_15_4::header_802_15_4(uint8_t * data,uint16_t pkt_start)
{
    this->pkt_ctr = pkt_start;
    unsigned short fcf = (((short)data[this->pkt_ctr+1]) << 8) | (0x00ff & data[this->pkt_ctr]);
    this->pkt_ctr += 2;
    this->fcf_h = (_fcf_802_15_4* )&fcf;

    this->seq = data[this->pkt_ctr];this->pkt_ctr++;

    if(this->fcf_h->dest_addr_mode == 0x02)
    {
        this->dest = (((short)data[this->pkt_ctr+1]) << 8) | (0x00ff & data[this->pkt_ctr]);
        this->pkt_ctr+=2;
        this->dest_pan = (((short)data[this->pkt_ctr+1]) << 8) | (0x00ff & data[this->pkt_ctr]);
    }

    if(this->fcf_h->src_addr_mode == 0x02)
    {
        this->src = (((short)data[this->pkt_ctr+1]) << 8) | (0x00ff & data[this->pkt_ctr]);
        this->pkt_ctr+=2;
    }
}

header_802_15_4::~header_802_15_4()
{
}

struct _fcf_zb{
    unsigned char type : 2;
    unsigned char proto_ver : 4;
    unsigned char disc_rt : 2;
    unsigned char multicast : 1;
    unsigned char sec : 1;
    unsigned char src_rt : 1;
    unsigned char dest : 1;
    unsigned char ext_src : 1;
    unsigned char edi : 1;
};

class header_zigbee
{
private:
    /* data */
    uint16_t pkt_ctr = 0;
public:
    _fcf_zb * fcf_zh; //frame control field zigbee

    unsigned char seq = 0x00;
    unsigned short dest = 0x0000;
    unsigned short dest_pan = 0x0000;
    unsigned short src = 0x0000;
    unsigned char radius = 0;
    unsigned char ext_source[8];
    bool have_ext_source = false;

    header_zigbee(uint8_t * data,uint16_t pkt_start);
    ~header_zigbee();
};

header_zigbee::header_zigbee(uint8_t * data,uint16_t pkt_start)
{
    this->pkt_ctr = pkt_start;
    unsigned short fcf_zh = (((short)data[this->pkt_ctr+1]) << 8) | (0x00ff & data[this->pkt_ctr]);
    this->pkt_ctr +=2;
    printf("short fcf_zh :%04X\n",fcf_zh);

    this->fcf_zh = (_fcf_zb* )&fcf_zh;

    if(this->fcf_zh->type == 0x01)//cmd
    {
        this->dest = (((short)data[this->pkt_ctr+1]) << 8) | (0x00ff & data[this->pkt_ctr]);
        this->pkt_ctr +=2;
        this->src = (((short)data[this->pkt_ctr+1]) << 8) | (0x00ff & data[this->pkt_ctr]);
        this->pkt_ctr +=2;
        this->radius = data[this->pkt_ctr];this->pkt_ctr++;
        this->seq = data[this->pkt_ctr];this->pkt_ctr++;

        if(this->fcf_zh->ext_src == 1)
        {
            //extended source which is what were are looking for
            this->ext_source[7] = data[this->pkt_ctr];this->pkt_ctr++;
            this->ext_source[6] = data[this->pkt_ctr];this->pkt_ctr++;
            this->ext_source[5] = data[this->pkt_ctr];this->pkt_ctr++;
            this->ext_source[4] = data[this->pkt_ctr];this->pkt_ctr++;
            this->ext_source[3] = data[this->pkt_ctr];this->pkt_ctr++;
            this->ext_source[2] = data[this->pkt_ctr];this->pkt_ctr++;
            this->ext_source[1] = data[this->pkt_ctr];this->pkt_ctr++;
            this->ext_source[0] = data[this->pkt_ctr];this->pkt_ctr++;
            this->have_ext_source = true;
        }
    }
}

header_zigbee::~header_zigbee()
{
}

#endif /* ifndef ZIGBEE_H */
