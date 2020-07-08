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

#ifndef __ALERTRACKER_H__
#define __ALERTRACKER_H__

#include "config.h"

#include <stdio.h>
#include <time.h>
#include <list>
#include <map>
#include <vector>
#include <algorithm>
#include <string>

#include "globalregistry.h"
#include "kis_mutex.h"
#include "messagebus.h"
#include "packetchain.h"
#include "timetracker.h"
#include "kis_net_microhttpd.h"
#include "kis_gps.h"

#ifdef PRELUDE
#include <libprelude/prelude.hxx>
#define PRELUDE_ANALYZER_NAME "Kismet"
#define PRELUDE_ANALYZER_MODEL "Kismet"
#define PRELUDE_ANALYZER_CLASS "WIDS"
#define PRELUDE_ANALYZER_MANUFACTURER "https://www.kismetwireless.net"
#endif

// TODO:
// - move packet_component to a tracked system & just use the converted
//   kis_alert_info in the future...
// - Move alert_ref into a tracked component and return via rest
// - Add description to alerts

class kis_alert_info : public packet_component {
public:
	kis_alert_info() {
		tm.tv_sec = 0;
		tm.tv_usec = 0;
		channel = "0";

        gps = NULL;

		// We do NOT self-destruct because we get cached in the alertracker
		// for playbacks.  It's responsible for discarding us
		self_destruct = 0;
	}

    virtual ~kis_alert_info() {
        if (gps != NULL)
            delete(gps);
    }

    device_key devicekey;

    std::string header;
	int phy;
	struct timeval tm;
	mac_addr bssid;
	mac_addr source;
	mac_addr dest;
	mac_addr other;
    std::string channel;
    std::string text;

    kis_gps_packinfo *gps;
};

class kis_alert_component : public packet_component {
public:
	kis_alert_component() {
		// We can self destruct because we won't clear out the vector
		// of actual alert info
		self_destruct = 1;
	}

    std::vector<kis_alert_info *> alert_vec;
};

class tracked_alert : public tracker_component {
public:
    tracked_alert() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    tracked_alert(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    tracked_alert(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    tracked_alert(int in_id, kis_alert_info *info) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
        from_alert_info(info);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("tracked_alert");
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

    __Proxy(devicekey, device_key, device_key, device_key, devicekey);

    __Proxy(header, std::string, std::string, std::string, header);
    __Proxy(phy, uint32_t, uint32_t, uint32_t, phy);
    __Proxy(timestamp, double, double, double, timestamp);

    __Proxy(transmitter_mac, mac_addr, mac_addr, mac_addr, transmitter_mac);
    __Proxy(source_mac, mac_addr, mac_addr, mac_addr, source_mac);
    __Proxy(dest_mac, mac_addr, mac_addr, mac_addr, dest_mac);
    __Proxy(other_mac, mac_addr, mac_addr, mac_addr, other_mac);

    __Proxy(channel, std::string, std::string, std::string, channel);
    __Proxy(frequency, double, double, double, frequency);

    __Proxy(text, std::string, std::string, std::string, text);

    __ProxyTrackable(location, kis_tracked_location_triplet, location);

    void from_alert_info(kis_alert_info *info) {
        set_devicekey(info->devicekey);
        set_header(info->header);
        set_phy(info->phy);
        set_timestamp(ts_to_double(info->tm));
        set_transmitter_mac(info->bssid);
        set_source_mac(info->source);
        set_dest_mac(info->dest);
        set_other_mac(info->other);
        set_channel(info->channel);
        set_text(info->text);

        if (info->gps != NULL)
            location->set(info->gps);
    }

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        register_field("kismet.alert.device_key", "Device key of linked device", &devicekey);
        register_field("kismet.alert.header", "Alert type", &header);
        register_field("kismet.alert.phy_id", "ID of phy generating alert", &phy);
        register_field("kismet.alert.timestamp", "Timestamp (sec.ms)", &timestamp);
        register_field("kismet.alert.transmitter_mac", "Transmitter MAC address", &transmitter_mac);
        register_field("kismet.alert.source_mac", "Source MAC address", &source_mac);
        register_field("kismet.alert.dest_mac", "Destination MAC address", &dest_mac);
        register_field("kismet.alert.other_mac", "Other / Extra MAC address", &other_mac);
        register_field("kismet.alert.channel", "Phy-specific channel", &channel);
        register_field("kismet.alert.frequency", "Frequency (khz)", &frequency);
        register_field("kismet.alert.text", "Alert text", &text);
        register_field("kismet.alert.location", "location", &location);
    }

    std::shared_ptr<tracker_element_device_key> devicekey;
    std::shared_ptr<tracker_element_string> header;
    std::shared_ptr<tracker_element_uint32> phy;
    std::shared_ptr<tracker_element_double> timestamp;
    std::shared_ptr<tracker_element_mac_addr> transmitter_mac;
    std::shared_ptr<tracker_element_mac_addr> source_mac;
    std::shared_ptr<tracker_element_mac_addr> dest_mac;
    std::shared_ptr<tracker_element_mac_addr> other_mac;
    std::shared_ptr<tracker_element_string> channel;
    std::shared_ptr<tracker_element_double> frequency;
    std::shared_ptr<tracker_element_string> text;
    std::shared_ptr<kis_tracked_location_triplet> location;
};


static const int alert_time_unit_conv[] = {
    1, 60, 3600, 86400
};

enum alert_time_unit {
    sat_second, sat_minute, sat_hour, sat_day
};

class tracked_alert_definition : public tracker_component {
public:
    tracked_alert_definition() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    tracked_alert_definition(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    tracked_alert_definition(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("tracked_alert_definition");
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

    __Proxy(header, std::string, std::string, std::string, header);
    __Proxy(description, std::string, std::string, std::string, description);
    __Proxy(phy, int64_t, int64_t, int64_t, phy);

    __Proxy(limit_unit, uint64_t, alert_time_unit, alert_time_unit, limit_unit);
    __Proxy(limit_rate, uint64_t, uint64_t, uint64_t, limit_rate);

    __Proxy(burst_unit, uint64_t, alert_time_unit, alert_time_unit, burst_unit);
    __Proxy(limit_burst, uint64_t, uint64_t, uint64_t, limit_burst);

    __Proxy(burst_sent, uint64_t, uint64_t, uint64_t, burst_sent);
    __ProxyIncDec(burst_sent, uint64_t, uint64_t, burst_sent);

    __Proxy(total_sent, uint64_t, uint64_t, uint64_t, total_sent);
    __ProxyIncDec(total_sent, uint64_t, uint64_t, total_sent);

    __Proxy(time_last, double, double, double, time_last);

    int get_alert_ref() { return alert_ref; }
    void set_alert_ref(int in_ref) { alert_ref = in_ref; }

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        register_field("kismet.alert.definition.header", "Alert type", &header);
        register_field("kismet.alert.definition.description", "Alert description", &description);
        register_field("kismet.alert.definition.phyid", "Alert phy type", &phy);
        register_field("kismet.alert.definition.limit_unit", 
                "Alert limit time unit (defined in alertracker.h)", &limit_unit);
        register_field("kismet.alert.definition.limit_rate", "Alert rate limit", &limit_rate);
        register_field("kismet.alert.definition.burst_unit", 
                "Burst limit time unit (defined in alertracker.h)", &burst_unit);
        register_field("kismet.alert.definition.limit_burst", "Burst rate limit", &limit_burst);
        register_field("kismet.alert.definition.burst_sent", "Alerts sent in burst", &burst_sent);
        register_field("kismet.alert.definition.total_sent", "Total alerts sent", &total_sent);
        register_field("kismet.alert.definition.time_last", 
                "Timestamp of last alert (sec.us)", &time_last);
    }

    // Non-exposed internal reference
    int alert_ref;

    // Alert type and description
    std::shared_ptr<tracker_element_string> header;
    std::shared_ptr<tracker_element_string> description;
    // Phynum this is linked to
    std::shared_ptr<tracker_element_int64> phy;

    // Units, rate limit, burst, and burst rate
    std::shared_ptr<tracker_element_uint64> limit_unit;
    std::shared_ptr<tracker_element_uint64> limit_rate;
    std::shared_ptr<tracker_element_uint64> burst_unit;
    std::shared_ptr<tracker_element_uint64> limit_burst;

    // Number of burst and total alerts we've sent of this type
    std::shared_ptr<tracker_element_uint64> burst_sent;
    std::shared_ptr<tracker_element_uint64> total_sent;

    // Timestamp of the last time
    std::shared_ptr<tracker_element_double> time_last;

};

typedef std::shared_ptr<tracked_alert_definition> shared_alert_def;

class alert_tracker : public lifetime_global {
public:
	// Simple struct from reading config lines
	struct alert_conf_rec {
        std::string header;
        alert_time_unit limit_unit;
        int limit_rate;
		alert_time_unit burst_unit;
        int limit_burst;
	};

    static std::string global_name() { return "ALERTTRACKER"; }

    static std::shared_ptr<alert_tracker> create_alertracker() {
        std::shared_ptr<alert_tracker> mon(new alert_tracker());
        Globalreg::globalreg->alertracker = mon.get();
        Globalreg::globalreg->register_lifetime_global(mon);
        Globalreg::globalreg->insert_global(global_name(), mon);
        return mon;
    }

private:
    alert_tracker();

    // Raise an Prelude alert (requires prelude support compiled in)
    int raise_prelude_alert(int in_ref, kis_packet *in_pack, mac_addr bssid, mac_addr source,
            mac_addr dest, mac_addr other, std::string in_channel, std::string in_text);
    int raise_prelude_one_shot(std::string in_header, std::string in_text);

    // Initialize Prelude Client (requires prelude support compiled in)
    void prelude_init_client(const char *analyzer_name);

public:
    virtual ~alert_tracker();

    // Register an alert and get an alert reference number back.
    int register_alert(std::string in_header, std::string in_desc, 
            alert_time_unit in_unit, int in_rate, alert_time_unit in_burstunit, 
            int in_burst, int in_phy);

    // Find a reference from a name
    int fetch_alert_ref(std::string in_header);

    // Will an alert succeed?
    int potential_alert(int in_ref);

    // Raise an alert ...
    int raise_alert(int in_ref, kis_packet *in_pack,
                   mac_addr bssid, mac_addr source, mac_addr dest, mac_addr other,
                   std::string in_channel, std::string in_text);

    // Raise a one-shot communications alert
    int raise_one_shot(std::string in_header, std::string in_text, int in_phy);

    // parse an alert config string
	int parse_alert_str(std::string alert_str, std::string *ret_name, 
					  alert_time_unit *ret_limit_unit, int *ret_limit_rate,
					  alert_time_unit *ret_limit_burst, int *ret_burst_rate);

	// Load alert rates from a config file
	int parse_alert_config(config_file *in_conf);

    // Define an alert and limits
    int define_alert(std::string name, alert_time_unit limit_unit, int limit_rate,
            alert_time_unit limit_burst, int burst_rate);

	// Activate a preconfigured alert from a file
	int activate_configured_alert(std::string in_header, std::string in_desc);
	int activate_configured_alert(std::string in_header, std::string in_desc, int in_phy);

    // Find an activated alert
    int find_activated_alert(std::string in_header);

protected:
    kis_recursive_timed_mutex alert_mutex;

    std::shared_ptr<packet_chain> packetchain;
    std::shared_ptr<entry_tracker> entrytracker;

    int alert_vec_id, alert_entry_id, alert_timestamp_id, alert_def_id;

    // Check and age times
    int check_times(shared_alert_def arec);

	// Parse a foo/bar rate/unit option
	int parse_rate_unit(std::string in_ru, alert_time_unit *ret_unit, int *ret_rate);

    int pack_comp_alert, pack_comp_gps;
    int alert_ref_kismet;

    int next_alert_id;

    // Internal C++ mapping
    std::map<std::string, int> alert_name_map;
    std::map<int, shared_alert_def> alert_ref_map;

    // Tracked mapping for export
    std::shared_ptr<tracker_element_vector> alert_defs_vec;

    int num_backlog;

    // Backlog of alerts to be sent
    std::shared_ptr<tracker_element_vector> alert_backlog_vec;

    // Alert configs we read before we know the alerts themselves
	std::map<std::string, alert_conf_rec *> alert_conf_map;

#ifdef PRELUDE
    // Prelude client
    Prelude::ClientEasy *prelude_client;
    // Do we log alerts to Prelude
    bool prelude_alerts;
#endif

    // Do we log alerts to the kismet database?
    bool log_alerts;

    std::shared_ptr<kis_net_httpd_simple_post_endpoint> define_alert_endp;
    unsigned int define_alert_endpoint(std::ostream& stream, const std::string& uri,
            const Json::Value& json, kis_net_httpd_connection::variable_cache_map& postvars);

    std::shared_ptr<kis_net_httpd_simple_post_endpoint> raise_alert_endp;
    unsigned int raise_alert_endpoint(std::ostream& stream, const std::string& uri,
            const Json::Value& json, kis_net_httpd_connection::variable_cache_map& postvars);

    std::shared_ptr<kis_net_httpd_simple_tracked_endpoint> definitions_endp;
    std::shared_ptr<kis_net_httpd_simple_tracked_endpoint> all_alerts_endp;

    std::shared_ptr<kis_net_httpd_path_tracked_endpoint> last_alerts_endp;

    bool last_alerts_endpoint_path(const std::vector<std::string>& path);
    std::shared_ptr<tracker_element> last_alerts_endpoint(const std::vector<std::string>& path);
};

#endif
