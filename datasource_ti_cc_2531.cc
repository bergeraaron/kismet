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

#include "datasource_ti_cc_2531.h"


void kis_datasource_ticc2531::handle_rx_packet(kis_packet *packet) {

    auto cc_chunk = packet->fetch<kis_datachunk>(pack_comp_linkframe);

    // If we can't validate the basics of the packet at the phy capture level, throw it out.
    // We don't get rid of invalid btle contents, but we do get rid of invalid USB frames that
    // we can't decipher - we can't even log them sanely!
    
    if (cc_chunk->length < 8) {
        // fmt::print(stderr, "debug - cc2531 too short ({} < 8)\n", cc_chunk->length);
        delete(packet);
        return;
    }

    unsigned int cc_len = cc_chunk->data[1];
    if (cc_len != cc_chunk->length - 3) {
        // fmt::print(stderr, "debug - cc2531 invalid packet length ({} != {})\n", cc_len, cc_chunk->length - 3);
        delete(packet);
        return;
    }

    unsigned int cc_payload_len = cc_chunk->data[7] - 0x02;
    if (cc_payload_len + 8 != cc_chunk->length - 2) {
        // fmt::print(stderr, "debug - cc2531 invalid payload length ({} != {})\n", cc_payload_len + 8, cc_chunk->length - 2);
        delete(packet);
        return;
    }

    // uint8_t fcs1 = cc_chunk->data[cc_chunk->length - 2];
    uint8_t fcs2 = cc_chunk->data[cc_chunk->length - 1];

    unsigned char crc_ok = fcs2 & (1 << 7);

    // unsigned char corr = fcs2 & 0x7f;

    if (crc_ok > 0) {

//        int rssi = (fcs1 + (int) pow(2, 7)) % (int) pow(2, 8) - (int) pow(2, 7) - 73;

        uint8_t payload[256];
        memset(payload, 0x00, 256);
        memcpy(payload, &cc_chunk->data[8], cc_payload_len);
        // Replace the existing packet data with this and update the DLT
        cc_chunk->set_data(payload, cc_payload_len, false);
        cc_chunk->dlt = KDLT_IEEE802_15_4_NOFCS;

        // Pass the packet on
        packetchain->process_packet(packet);

    } else {
        delete (packet);
        return;
    }
}

