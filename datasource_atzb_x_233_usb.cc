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

    delete (packet);
    return;
}
