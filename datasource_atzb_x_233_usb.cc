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

#include "endian_magic.h"

#include "datasource_atzb_x_233_usb.h"


void kis_datasource_atzbx233usb::handle_rx_packet(kis_packet *packet) {


    auto atzb_chunk = packet->fetch<kis_datachunk>(pack_comp_linkframe);

    // If we can't validate the basics of the packet at the phy capture level,
    // throw it out. We don't get rid of invalid btle contents, but we do get
    // rid of invalid USB frames that we can't decipher - we can't even log them
    // sanely!

    if (atzb_chunk->length < 10) {
        // fmt::print(stderr, "debug - atzb kw41z too short ({} < 10)\n",
        // atzb_chunk->length);
        delete (packet);
        return;
    }

    printf("received zigbee packet\n");

    for(int i=0;i<atzb_chunk->length;i++)
    {
        printf("%02X",atzb_chunk->data[i]);
    }
    printf("\n");
    if(atzb_chunk->data[4] > 0)
    {
        int rz_payload_len = atzb_chunk->data[4];

        int rssi = 22;//atzb_chunk->data[6];
        uint8_t channel = 11;//atzb_chunk->data[5];
	// We can make a valid payload from this much
        auto conv_buf_len = sizeof(_802_15_4_tap) + rz_payload_len;
        _802_15_4_tap *conv_header = reinterpret_cast<_802_15_4_tap *>(new uint8_t[conv_buf_len]);
        memset(conv_header, 0, conv_buf_len);

        // Copy the actual packet payload into the header
        memcpy(conv_header->payload, &atzb_chunk->data[5], rz_payload_len);

        conv_header->version = 0;//currently only one version
        conv_header->reserved = 0;//must be set to 0

        //fcs setting
        conv_header->tlv[0].type = 0;
        conv_header->tlv[0].length = 1;
        conv_header->tlv[0].value = 0;

        //rssi
        conv_header->tlv[1].type = 10;
        conv_header->tlv[1].length = 1;
        conv_header->tlv[1].value = rssi;

        //channel
        conv_header->tlv[2].type = 3;
        conv_header->tlv[2].length = 3;
        conv_header->tlv[2].value = channel;

        //size
        conv_header->length = sizeof(conv_header)+sizeof(conv_header->tlv)-4;//remove 4 bytes for the length in the header
        atzb_chunk->set_data((uint8_t *)conv_header, conv_buf_len, false);
        atzb_chunk->dlt = KDLT_IEEE802_15_4_TAP; 	

        auto radioheader = new kis_layer1_packinfo();
        radioheader->signal_type = kis_l1_signal_type_dbm;
        radioheader->signal_dbm = rssi;
        radioheader->freq_khz = (2405 + ((channel - 11) * 5)) * 1000;
        radioheader->channel = fmt::format("{}", (channel));
        packet->insert(pack_comp_radiodata, radioheader);

	    // Pass the packet on
        kis_datasource::handle_rx_packet(packet);
    }
    else
    {
        delete(packet);
        return;
    }
}