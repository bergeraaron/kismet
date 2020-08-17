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

#include "config.h"

#include <stdio.h>
#include <time.h>
#include <list>
#include <map>
#include <vector>
#include <algorithm>
#include <string>
#include <memory>

#include "globalregistry.h"
#include "packetchain.h"
#include "timetracker.h"
#include "kis_httpd_registry.h"
#include "devicetracker.h"
#include "dlttracker.h"
#include "manuf.h"

#include "phy_zigbee.h"
//802.15.4 header
struct _802_15_4_fcf{
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
_802_15_4_fcf * hdr_802_15_4_fcf;

//zigbee specific header
struct fcf_z{
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
fcf_z * fcf_zzh;

uint8_t dest[2] = {0x00,0x00};
uint8_t dest_pan[2] = {0x00,0x00};
uint8_t src[2] = {0x00,0x00};
uint8_t src_pan[2] = {0x00,0x00};

uint8_t ext_dest[8];
uint8_t ext_source[8];

kis_zigbee_phy::kis_zigbee_phy(global_registry *in_globalreg, int in_phyid) :
    kis_phy_handler(in_globalreg, in_phyid) {

    set_phy_name("zigbee");

    packetchain = 
        Globalreg::fetch_mandatory_global_as<packet_chain>();
    entrytracker = 
        Globalreg::fetch_mandatory_global_as<entry_tracker>();
    devicetracker =
        Globalreg::fetch_mandatory_global_as<device_tracker>();

    zigbee_device_entry_id =
        entrytracker->register_field("zigbee.device",
                tracker_element_factory<zigbee_tracked_device>(),
                "zigbee device");

    pack_comp_common = packetchain->register_packet_component("COMMON");
	pack_comp_linkframe = packetchain->register_packet_component("LINKFRAME");

    // Extract the dynamic DLT
    auto dltt = 
        Globalreg::fetch_mandatory_global_as<dlt_tracker>("DLTTRACKER");
    dlt = KDLT_IEEE802_15_4_NOFCS;

    /*
    auto httpregistry = 
        Globalreg::fetch_mandatory_global_as<kis_httpd_registry>("WEBREGISTRY");
        */

    packetchain->register_handler(&dissectorzigbee, this, CHAINPOS_LLCDISSECT, -100);
    packetchain->register_handler(&commonclassifierzigbee, this, CHAINPOS_CLASSIFIER, -100);
}

kis_zigbee_phy::~kis_zigbee_phy() {
    packetchain->remove_handler(&commonclassifierzigbee, CHAINPOS_CLASSIFIER);
}

int kis_zigbee_phy::dissectorzigbee(CHAINCALL_PARMS) {
    auto mphy = static_cast<kis_zigbee_phy *>(auxdata);

    auto packdata = in_pack->fetch<kis_datachunk>(mphy->pack_comp_linkframe);

    if (packdata == NULL)
        return 0;

    // Is it a packet we care about?
    if (packdata == NULL || (packdata != NULL && packdata->dlt != KDLT_IEEE802_15_4_NOFCS))
        return 0;

    // Do we have enough data for an OUI?
    if (packdata->length < 6)
        return 0;

    // Did something already classify this?
    auto common = in_pack->fetch<kis_common_info>(mphy->pack_comp_common);

    if (common != NULL)
        return 0;


    //process the packet
    //printf("process a packet from within the phy_zigbee\n");
    //hurray we make it here

    uint8_t pkt_ctr = 0;
    if(packdata->dlt == KDLT_IEEE802_15_4_NOFCS)
    {
        //printf("parse a zigbee packet of dlt KDLT_IEEE802_15_4_NOFCS\n");
        //printf("print the packet that we got\n");
        //for(int xp=0;xp<(int)packdata->length;xp++)
        //{
            //printf("%02X",packdata->data[xp]);
        //}
        //printf("\n");
        //get the fcf first

        unsigned short fcf = (((short)packdata->data[pkt_ctr+1]) << 8) | (0x00ff & packdata->data[pkt_ctr]);
        pkt_ctr+=2;
        //we need to take a look at what flags are set
        hdr_802_15_4_fcf = (_802_15_4_fcf* )&fcf;

        //printf("struct\n");
//        printf("type:%02X\n",hdr_802_15_4_fcf->type);
//        printf("security:%02X\n",hdr_802_15_4_fcf->security);
        //printf("pending:%02X\n",hdr_802_15_4_fcf->pending);
        //printf("ack_req:%02X\n",hdr_802_15_4_fcf->ack_req);
        //printf("pan_id_comp:%02X\n",hdr_802_15_4_fcf->pan_id_comp);
        //printf("reserved:%02X\n",hdr_802_15_4_fcf->reserved);
        //printf("sns:%02X\n",hdr_802_15_4_fcf->sns);
        //printf("iep:%02X\n",hdr_802_15_4_fcf->iep);
//        printf("dest_addr_mode:%02X\n",hdr_802_15_4_fcf->dest_addr_mode);
//        printf("frame_ver:%02X\n",hdr_802_15_4_fcf->frame_ver);
//        printf("src_addr_mode:%02X\n",hdr_802_15_4_fcf->src_addr_mode);

        //we should be able to handle whichever correctly
        //0x01 - data,  0x03 - cmd, 0x04 - reserved
        //hdr_802_15_4_fcf->type == 0x01 || hdr_802_15_4_fcf->type == 0x03 || hdr_802_15_4_fcf->type == 0x04
        if(hdr_802_15_4_fcf->type == 0x05)
        {
            printf("type %02X currently not supported\n",hdr_802_15_4_fcf->type);
            return 0;
        }
        uint8_t seq;
        if(!hdr_802_15_4_fcf->sns)
        {
            seq = packdata->data[pkt_ctr];pkt_ctr++;
        }

        if(hdr_802_15_4_fcf->dest_addr_mode == 0x01)
        {
            if(hdr_802_15_4_fcf->frame_ver == 0)//this address mode is not valid under this spec
            {
                printf("this address mode is not valid under this spec\n");
                return 0;
            }

            dest[1] = packdata->data[pkt_ctr];
            pkt_ctr++;
        }
        else if(hdr_802_15_4_fcf->dest_addr_mode == 0x02)
        {
            dest[1] = packdata->data[pkt_ctr];pkt_ctr++;
            dest[0] = packdata->data[pkt_ctr];pkt_ctr++;

            dest_pan[1] = packdata->data[pkt_ctr];pkt_ctr++;
            dest_pan[0] = packdata->data[pkt_ctr];pkt_ctr++;
        }
        else if(hdr_802_15_4_fcf->dest_addr_mode == 0x03)
        {
            //length means we actually have an extended dest
            dest[1] = packdata->data[pkt_ctr];pkt_ctr++;
            dest[0] = packdata->data[pkt_ctr];pkt_ctr++;
            //extended dest which is what were are looking for
            ext_dest[7] = packdata->data[pkt_ctr];pkt_ctr++;
            ext_dest[6] = packdata->data[pkt_ctr];pkt_ctr++;
            ext_dest[5] = packdata->data[pkt_ctr];pkt_ctr++;
            ext_dest[4] = packdata->data[pkt_ctr];pkt_ctr++;
            ext_dest[3] = packdata->data[pkt_ctr];pkt_ctr++;
            ext_dest[2] = packdata->data[pkt_ctr];pkt_ctr++;
            ext_dest[1] = packdata->data[pkt_ctr];pkt_ctr++;
            ext_dest[0] = packdata->data[pkt_ctr];pkt_ctr++;
        }

        if(hdr_802_15_4_fcf->src_addr_mode == 0x01)
        {
            if(hdr_802_15_4_fcf->frame_ver == 0)//this address mode is not valid under this spec
            {
                printf("this address mode is not valid under this spec\n");
                return 0;
            }
            src[1] = packdata->data[pkt_ctr];pkt_ctr++;
        }
        else if(hdr_802_15_4_fcf->src_addr_mode == 0x02)
        {
            if(!hdr_802_15_4_fcf->pan_id_comp)
            {
                //src pan
                src_pan[1] = packdata->data[pkt_ctr];pkt_ctr++;
                src_pan[0] = packdata->data[pkt_ctr];pkt_ctr++;
            }
            src[1] = packdata->data[pkt_ctr];pkt_ctr++;
            src[0] = packdata->data[pkt_ctr];pkt_ctr++;
        }
        else if(hdr_802_15_4_fcf->src_addr_mode == 0x03)
        {
            //srcpan
            //extended source
            if(!hdr_802_15_4_fcf->pan_id_comp)
            {
                src_pan[1] = packdata->data[pkt_ctr];pkt_ctr++;
                src_pan[0] = packdata->data[pkt_ctr];pkt_ctr++;
            }
            //extended source which is what were are looking for
            ext_source[7] = packdata->data[pkt_ctr];pkt_ctr++;
            ext_source[6] = packdata->data[pkt_ctr];pkt_ctr++;
            ext_source[5] = packdata->data[pkt_ctr];pkt_ctr++;
            ext_source[4] = packdata->data[pkt_ctr];pkt_ctr++;
            ext_source[3] = packdata->data[pkt_ctr];pkt_ctr++;
            ext_source[2] = packdata->data[pkt_ctr];pkt_ctr++;
            ext_source[1] = packdata->data[pkt_ctr];pkt_ctr++;
            ext_source[0] = packdata->data[pkt_ctr];pkt_ctr++;
        }
    
/**
        if(hdr_802_15_4_fcf->frame_ver == 0x00)
        {
            //assume zigbee?
            unsigned short fcf_zh = (((short)packdata->data[pkt_ctr+1]) << 8) | (0x00ff & packdata->data[pkt_ctr]);
            pkt_ctr+=2;

            fcf_zzh = (fcf_z* )&fcf_zh;

            printf("struct\n");
            printf("type:%02X\n",fcf_zzh->type);
            printf("proto_ver:%02X\n",fcf_zzh->proto_ver);
            printf("disc_rt:%02X\n",fcf_zzh->disc_rt);
            printf("multicast:%02X\n",fcf_zzh->multicast);
            printf("sec:%02X\n",fcf_zzh->sec);
            printf("src_rt:%02X\n",fcf_zzh->src_rt);
            printf("dest:%02X\n",fcf_zzh->dest);
            printf("ext_src:%02X\n",fcf_zzh->ext_src);
            printf("edi:%02X\n",fcf_zzh->edi);

            if(fcf_zzh->type == 0x01)//cmd
            {
                printf("cmd pkt\n");
                unsigned short zzh_dest = (((short)packdata->data[pkt_ctr+1]) << 8) | (0x00ff & packdata->data[pkt_ctr]);
                pkt_ctr+=2;
                unsigned short zzh_src = (((short)packdata->data[pkt_ctr+1]) << 8) | (0x00ff & packdata->data[pkt_ctr]);
                pkt_ctr+=2;
                unsigned char zzh_radius = packdata->data[pkt_ctr];pkt_ctr++;
                unsigned char zzh_seq = packdata->data[pkt_ctr];pkt_ctr++;

                if(fcf_zzh->ext_src == 1)
                {
                    //extended source which is what were are looking for
                    ext_source[7] = packdata->data[pkt_ctr];pkt_ctr++;
                    ext_source[6] = packdata->data[pkt_ctr];pkt_ctr++;
                    ext_source[5] = packdata->data[pkt_ctr];pkt_ctr++;
                    ext_source[4] = packdata->data[pkt_ctr];pkt_ctr++;
                    ext_source[3] = packdata->data[pkt_ctr];pkt_ctr++;
                    ext_source[2] = packdata->data[pkt_ctr];pkt_ctr++;
                    ext_source[1] = packdata->data[pkt_ctr];pkt_ctr++;
                    ext_source[0] = packdata->data[pkt_ctr];pkt_ctr++;
                }

                printf("zzh_dest:%04X\n",zzh_dest);
                printf("zzh_src:%04X\n",zzh_src);
                printf("zzh_radius:%02X\n",zzh_radius);
                printf("zzh_seq:%02X\n",zzh_seq);
                printf("ext_source ");
                for(int xps=0;xps<8;xps++)
                    printf("%02X ",ext_source[xps]);
                printf("\n");
            }
            else if(fcf_zzh->type == 0x00)//data
            {
                printf("data packet\n");
            }
        }
        else if(hdr_802_15_4_fcf->frame_ver == 0x01)
        {
            //assume 6LowPAN

        }
**/
    }

    if(hdr_802_15_4_fcf->src_addr_mode >= 0x02 || hdr_802_15_4_fcf->dest_addr_mode >= 0x02)// || fcf_zzh->ext_src == 1
    {
        if(hdr_802_15_4_fcf->src_addr_mode == 0x03)
        {
            for(int xps=0;xps<8;xps++)
                printf("%02X ",ext_source[xps]);
            printf("\n");
        }
        if(hdr_802_15_4_fcf->src_addr_mode == 0x02)
        {
            for(int xps=0;xps<2;xps++)
                printf("%02X ",src[xps]);
            printf("\n");
            for(int xps=0;xps<2;xps++)
                printf("%02X ",src_pan[xps]);
            printf("\n");
        }

        if(hdr_802_15_4_fcf->dest_addr_mode == 0x03)
        {
            for(int xps=0;xps<8;xps++)
                printf("%02X ",ext_dest[xps]);
            printf("\n");
        }
        if(hdr_802_15_4_fcf->dest_addr_mode == 0x02)
        {
            for(int xps=0;xps<2;xps++)
                printf("%02X ",dest[xps]);
            printf("\n");
            for(int xps=0;xps<2;xps++)
                printf("%02X ",dest_pan[xps]);
            printf("\n");
        }


        common = new kis_common_info;
        common->phyid = mphy->fetch_phy_id();
        //error
        //datasize
        //channel
        //freq_khz
        common->basic_crypt_set = crypt_none;
        common->type = packet_basic_data;
        //direction
        if(hdr_802_15_4_fcf->src_addr_mode == 0x03)
            common->source = mac_addr(ext_source, 8);
        else if(hdr_802_15_4_fcf->src_addr_mode == 0x02 && !hdr_802_15_4_fcf->pan_id_comp)
            common->source = mac_addr(src_pan, 2);
        else if(hdr_802_15_4_fcf->src_addr_mode == 0x02 && hdr_802_15_4_fcf->pan_id_comp)
            common->source = mac_addr(src, 2);
/**
        if(fcf_zzh->ext_src == 1)
            common->source = mac_addr(ext_source, 8);
**/
        if(hdr_802_15_4_fcf->dest_addr_mode == 0x03)
            common->dest = mac_addr(ext_dest, 8);
        else if(hdr_802_15_4_fcf->dest_addr_mode == 0x02)
            common->dest = mac_addr(dest_pan, 2);
        //network
        //transmitter
        printf("insert\n");
        in_pack->insert(mphy->pack_comp_common, common);

    }

    return 1;
}

int kis_zigbee_phy::commonclassifierzigbee(CHAINCALL_PARMS) {
    auto mphy = static_cast<kis_zigbee_phy *>(auxdata);

    auto packdata = in_pack->fetch<kis_datachunk>(mphy->pack_comp_linkframe);

    printf("in commonclassifierzigbee\n");
    if (packdata == nullptr)
        return 0;

    // Is it a packet we care about?
    printf("commonclassifierzigbee packdata->dlt:%d mphy->dlt:%d\n",packdata->dlt,mphy->dlt);
    if (packdata->dlt != mphy->dlt)
        return 0;

    // Did we classify this?
    auto common = in_pack->fetch<kis_common_info>(mphy->pack_comp_common);

    if (common == NULL)
        return 0;

    printf("auto device\n");

    // Update with all the options in case we can add signal and frequency
    // in the future
    auto device = 
        mphy->devicetracker->update_common_device(common,
                common->source, mphy, in_pack,
                (UCD_UPDATE_SIGNAL | UCD_UPDATE_FREQUENCIES |
                 UCD_UPDATE_PACKETS | UCD_UPDATE_LOCATION |
                 UCD_UPDATE_SEENBY | UCD_UPDATE_ENCRYPTION),
                "zigbee");

    auto zigbee =
        device->get_sub_as<zigbee_tracked_device>(mphy->zigbee_device_entry_id);

    if (zigbee == NULL) {
        _MSG_INFO("Detected new zigbee device {}",
                common->source.mac_to_string());
        zigbee = std::make_shared<zigbee_tracked_device>(mphy->zigbee_device_entry_id);
        device->insert(zigbee);
    }

    return 1;
}

void kis_zigbee_phy::load_phy_storage(shared_tracker_element in_storage,
        shared_tracker_element in_device) {
    if (in_storage == nullptr || in_device == nullptr)
        return;

    auto storage = std::static_pointer_cast<tracker_element_map>(in_storage);

    auto zigbeedevi = storage->find(zigbee_device_entry_id);
    
    if (zigbeedevi != storage->end()) {
        auto zigbeedev =
            std::make_shared<zigbee_tracked_device>(zigbee_device_entry_id,
                    std::static_pointer_cast<tracker_element_map>(zigbeedevi->second));
        std::static_pointer_cast<tracker_element_map>(in_device)->insert(zigbeedev);
    }
    
}

