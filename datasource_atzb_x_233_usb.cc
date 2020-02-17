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

    if (atzb_chunk->data[0] != 0x02 && atzb_chunk->data[1] != 0x4E &&
        atzb_chunk->data[2] != 0x7F) {
        // not a packet we are interested in
        delete (packet);
        return;
    }

    if (!checksum(atzb_chunk->data, atzb_chunk->length)) {
        delete (packet);
        return;
    }

    // check what type of packet we are
    if (atzb_chunk->data[0] == 0x02 && atzb_chunk->data[1] == 0x86 &&
        atzb_chunk->data[2] == 0x03) {
        printf("received zigbee packet\n");
    
        typedef struct {
            uint16_t type;    // type identifier
            uint16_t length;  // number of octets for type in value field (not
                              // including padding
            uint32_t value;   // data for type
        } tap_tlv;

        typedef struct {
            uint8_t version;   // currently zero
            uint8_t reserved;  // must be zero
            uint16_t length;   // total length of header and tlvs in octets, min
                               // 4 and must be multiple of 4
            tap_tlv tlv[2];    // tap tlvs
            uint8_t payload[0];
            ////payload + fcs per fcs type
        } zigbee_tap;

        uint32_t rssi = atzb_chunk->data[5];
        uint16_t atzb_payload_len = atzb_chunk->data[10];
        // We can make a valid payload from this much
        auto conv_buf_len = sizeof(zigbee_tap) + atzb_payload_len;
        zigbee_tap *conv_header =
            reinterpret_cast<zigbee_tap *>(new uint8_t[conv_buf_len]);
        memset(conv_header, 0, conv_buf_len);

        // Copy the actual packet payload into the header
        memcpy(conv_header->payload, &atzb_chunk->data[11], atzb_payload_len);

        conv_header->version = 0;   // currently only one version
        conv_header->reserved = 0;  // must be set to 0

        // fcs setting
        conv_header->tlv[0].type = 0;
        conv_header->tlv[0].length = 1;
        conv_header->tlv[0].value = 0;

        // rssi
        conv_header->tlv[1].type = 10;
        conv_header->tlv[1].length = 1;
        conv_header->tlv[1].value = rssi;
/*
        // channel
        conv_header->tlv[2].type = 3;
        conv_header->tlv[2].length = 3;
        conv_header->tlv[2].value = 11;  // need to try to pull from some where
*/
        // size
        conv_header->length =
            sizeof(conv_header) + sizeof(conv_header->tlv) - 4;
        atzb_chunk->set_data((uint8_t *) conv_header, conv_buf_len, false);
        atzb_chunk->dlt = KDLT_IEEE802_15_4_TAP;

        // Pass the packet on
        packetchain->process_packet(packet);

    } else {
        delete (packet);
        return;
    }
}
