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
    //auto dltt = 
    //    Globalreg::fetch_mandatory_global_as<dlt_tracker>("DLTTRACKER");
    //dlt = dltt->register_linktype("zigbee");

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
    if (packdata == NULL || ((packdata != NULL && packdata->dlt != KDLT_IEEE802_15_4_NOFCS) && (packdata != NULL && packdata->dlt != KDLT_IEEE802_15_4_TAP)))
        return 0;

    // Do we have enough data for an OUI?
    if (packdata->length < 6)
        return 0;

    // Did something already classify this?
    auto common = in_pack->fetch<kis_common_info>(mphy->pack_comp_common);

    if (common != NULL)
        return 0;


    //process the packet
    printf("process a packet from within the phy_zigbee\n");
    //hurray we make it here

    if(packdata->dlt == KDLT_IEEE802_15_4_NOFCS)
    {
        printf("parse a zigbee packet of dlt KDLT_IEEE802_15_4_NOFCS\n");
        printf("print the packet that we got\n");
        for(int xp=0;xp<packdata->length;xp++)
        {
            printf("%02X",packdata->data[xp]);
        }
        printf("\n");
        //get the fcf first
        //maybe reverse?
        short fcf = (((short)packdata->data[0]) << 8) | (0x00ff & packdata->data[1]);
        printf("short fcf :%04X\n",fcf);
        //we need to take a look at what flags are set

    }
    else if(packdata->dlt == KDLT_IEEE802_15_4_TAP)
    {
        printf("parse a zigbee packet of dlt KDLT_IEEE802_15_4_TAP\n");
        printf("print the packet that we got\n");
        for(int xp=0;xp<packdata->length;xp++)
        {
            printf("%02X",packdata->data[xp]);
        }
        printf("\n");

    }

/**
    common = new kis_common_info;

    common->phyid = mphy->fetch_phy_id();
    common->basic_crypt_set = crypt_none;
    common->type = packet_basic_data;
    common->source = mac_addr(packdata->data, 6);

    in_pack->insert(mphy->pack_comp_common, common);
**/
    return 1;
}

int kis_zigbee_phy::commonclassifierzigbee(CHAINCALL_PARMS) {
    auto mphy = static_cast<kis_zigbee_phy *>(auxdata);

    auto packdata = in_pack->fetch<kis_datachunk>(mphy->pack_comp_linkframe);

    if (packdata == nullptr)
        return 0;

    // Is it a packet we care about?
    if (packdata->dlt != mphy->dlt)
        return 0;

    // Did we classify this?
    auto common = in_pack->fetch<kis_common_info>(mphy->pack_comp_common);

    if (common == NULL)
        return 0;

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

