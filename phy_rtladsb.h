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

#ifndef __PHY_RTLADSB_H__
#define __PHY_RTLADSB_H__

#include "config.h"


#include "adsb_icao.h"
#include "devicetracker_component.h"
#include "globalregistry.h"
#include "kis_net_microhttpd.h"
#include "phyhandler.h"
#include "trackedelement.h"

// Thermometer type rtl data, derived from the rtl device.  This adds new
// fields for adsb but uses the same base IDs
class rtladsb_tracked_adsb : public tracker_component {
public:
    rtladsb_tracked_adsb() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);

        lat = lon = alt = heading = speed = 0;
        update_location = false;
    }

    rtladsb_tracked_adsb(int in_id) :
       tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);

        lat = lon = alt = heading = speed = 0;
        update_location = false;
        }

    rtladsb_tracked_adsb(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);

        lat = lon = alt = heading = speed = 0;
        update_location = false;
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("rtladsb_tracked_adsb");
    }

    virtual std::unique_ptr<tracker_element> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<tracker_element> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
    }

    __Proxy(icao, std::string, std::string, std::string, icao);
    __ProxyTrackable(icao_record, tracked_adsb_icao, icao_record);
    __Proxy(callsign, std::string, std::string, std::string, callsign);
    __Proxy(gsas, std::string, std::string, std::string, gsas);

    __Proxy(odd_raw_lat, double, double, double, odd_raw_lat);
    __Proxy(odd_raw_lon, double, double, double, odd_raw_lon);
    __Proxy(odd_ts, uint64_t, time_t, time_t, odd_ts);
    __Proxy(even_raw_lat, double, double, double, even_raw_lat);
    __Proxy(even_raw_lon, double, double, double, even_raw_lon);
    __Proxy(even_ts, uint64_t, time_t, time_t, even_ts);

protected:
    virtual void register_fields() override {
        register_field("rtladsb.device.icao", "ICAO", &icao);
        register_field("rtladsb.device.icao_record", "ICAO record", &icao_record);
        register_field("rtladsb.device.gsas", "GSAS", &gsas);
        register_field("rtladsb.device.callsign", "Callsign", &callsign);
        register_field("rtladsb.device.odd_raw_lat", "Odd-packet raw latitude", &odd_raw_lat);
        register_field("rtladsb.device.odd_raw_lon", "Odd-packet raw longitude", &odd_raw_lon);
        register_field("rtladsb.device.odd_ts", "Timestamp of last odd-packet", &odd_ts);
        register_field("rtladsb.device.even_raw_lat", "even-packet raw latitude", &even_raw_lat);
        register_field("rtladsb.device.even_raw_lon", "even-packet raw longitude", &even_raw_lon);
        register_field("rtladsb.device.even_ts", "Timestamp of last even-packet", &even_ts);
    }

    std::shared_ptr<tracker_element_string> icao;
    std::shared_ptr<tracked_adsb_icao> icao_record;
    std::shared_ptr<tracker_element_string> callsign;
    std::shared_ptr<tracker_element_string> gsas;


    // Aggregate location records from multiple packets to derive the actual
    // location.  These are raw adsb locations.
    std::shared_ptr<tracker_element_double> odd_raw_lat;
    std::shared_ptr<tracker_element_double> odd_raw_lon;
    std::shared_ptr<tracker_element_uint64> odd_ts;
    std::shared_ptr<tracker_element_double> even_raw_lat;
    std::shared_ptr<tracker_element_double> even_raw_lon;
    std::shared_ptr<tracker_element_uint64> even_ts;

    // Aggregated location turned into a packet location later
    double lat, lon, alt, heading, speed;
    bool update_location;

    friend class kis_rtladsb_phy;
};

class kis_rtladsb_phy : public kis_phy_handler {
public:
    virtual ~kis_rtladsb_phy();

    kis_rtladsb_phy(global_registry *in_globalreg) :
        kis_phy_handler(in_globalreg) { };

	// Build a strong version of ourselves
	virtual kis_phy_handler *create_phy_handler(global_registry *in_globalreg, int in_phyid) override {
		return new kis_rtladsb_phy(in_globalreg, in_phyid);
	}

    kis_rtladsb_phy(global_registry *in_globalreg, int in_phyid);

    static int packet_handler(CHAINCALL_PARMS);

protected:
    std::shared_ptr<kis_adsb_icao> icaodb;

    int pack_comp_gps;

    // Convert a JSON record to a RTL-based device key
    mac_addr json_to_mac(Json::Value in_json);

    // convert to a device record & push into device tracker, return false
    // if we can't do anything with it
    bool json_to_rtl(Json::Value in_json, kis_packet *packet);

    bool is_adsb(Json::Value json);

    std::shared_ptr<rtladsb_tracked_adsb> add_adsb(kis_packet *packet, 
            Json::Value json, std::shared_ptr<kis_tracked_device_base> rtlholder);

    double f_to_c(double f);

    int cpr_mod(int a, int b);
    int cpr_nl(double lat);
    int cpr_n(double lat, int odd);
    double cpr_dlon(double lat, int odd);
    void decode_cpr(std::shared_ptr<rtladsb_tracked_adsb> adsb, kis_packet *packet);

    std::shared_ptr<packet_chain> packetchain;
    std::shared_ptr<entry_tracker> entrytracker;
    std::shared_ptr<device_tracker> devicetracker;

    int rtladsb_adsb_id;

    int pack_comp_common, pack_comp_json, pack_comp_meta;

    std::shared_ptr<tracker_element_string> rtl_manuf;

    std::shared_ptr<kis_net_httpd_simple_tracked_endpoint> adsb_map_endp;
    std::shared_ptr<tracker_element> adsb_map_endp_handler();

};

#endif

