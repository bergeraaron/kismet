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

#include <string>
#include <vector>
#include <sstream>

#include "alertracker.h"
#include "devicetracker.h"
#include "configfile.h"

#include "json_adapter.h"
#include "base64.h"
#include "kis_databaselogfile.h"

alert_tracker::alert_tracker() : lifetime_global() {
    alert_mutex.set_name("alertracker");

	next_alert_id = 0;

    packetchain = Globalreg::fetch_mandatory_global_as<packet_chain>();
    entrytracker = Globalreg::fetch_mandatory_global_as<entry_tracker>();

    alert_vec_id =
        entrytracker->register_field("kismet.alert.list",
                tracker_element_factory<tracker_element_vector>(), 
                "list of alerts");

    alert_timestamp_id =
        entrytracker->register_field("kismet.alert.timestamp",
                tracker_element_factory<tracker_element_double>(), 
                "alert update timestamp");

    alert_entry_id =
        entrytracker->register_field("kismet.alert.alert",
                tracker_element_factory<tracked_alert>(),
                "Kismet alert");

    alert_defs_vec = 
        entrytracker->register_and_get_field_as<tracker_element_vector>("kismet.alert.definition_list",
                tracker_element_factory<tracker_element_vector>(), 
                "Kismet alert definitions");

    alert_backlog_vec =
        entrytracker->register_and_get_field_as<tracker_element_vector>("kismet.alert.backlog",
                tracker_element_factory<tracker_element_vector>(),
                "Kismet alerts");

    alert_def_id =
        entrytracker->register_field("kismet.alert.alert_definition",
                tracker_element_factory<tracked_alert_definition>(),
                "Kismet alert definition");

	// Register the alert component
    pack_comp_alert =
		packetchain->register_packet_component("alert");

	// Register the GPS component
    pack_comp_gps =
		packetchain->register_packet_component("GPS");

	// Register a KISMET alert type with no rate restrictions
    alert_ref_kismet =
		register_alert("KISMET", "Server events", sat_day, 0, sat_day, 0, KIS_PHY_ANY);

    define_alert_endp =
        std::make_shared<kis_net_httpd_simple_post_endpoint>("/alerts/definitions/define_alert",
                [this](std::ostream& stream, const std::string& uri, 
                    const Json::Value& json,
                    kis_net_httpd_connection::variable_cache_map& variable_cache) -> unsigned int {
                return define_alert_endpoint(stream, uri, json, variable_cache);
                });

    raise_alert_endp = 
        std::make_shared<kis_net_httpd_simple_post_endpoint>("/alerts/raise_alerts",
                [this](std::ostream& stream, const std::string& uri, 
                    const Json::Value& json,
                    kis_net_httpd_connection::variable_cache_map& variable_cache) -> unsigned int {
                return raise_alert_endpoint(stream, uri, json, variable_cache);
                });

    definitions_endp = 
        std::make_shared<kis_net_httpd_simple_tracked_endpoint>("/alerts/definitions",
                alert_defs_vec, &alert_mutex);

    all_alerts_endp =
        std::make_shared<kis_net_httpd_simple_tracked_endpoint>("/alerts/all_alerts",
                alert_backlog_vec, &alert_mutex);

    last_alerts_endp = 
        std::make_shared<kis_net_httpd_path_tracked_endpoint>(
                [this](const std::vector<std::string>& path) -> bool {
                return last_alerts_endpoint_path(path);
                },
                [this](const std::vector<std::string>& path) -> std::shared_ptr<tracker_element> {
                return last_alerts_endpoint(path);
                });

#ifdef PRELUDE
    prelude_alerts = Globalreg::globalreg->kismet_config->fetch_opt_bool("prelude_alerts", true);

    // Start client Prelude
    if (prelude_alerts) {
        int ret;
        ret = prelude_init(0, NULL);
        if (ret < 0) {
            _MSG("alert_tracker - Failed to initialize Prelude SIEM connection", MSGFLAG_FATAL);
            Globalreg::globalreg->fatal_condition = 1;
            return;
        }
        prelude_init_client(PRELUDE_ANALYZER_NAME);
    }
#endif

    if (Globalreg::globalreg->kismet_config->fetch_opt("alertbacklog") != "") {
        int scantmp;
        if (sscanf(Globalreg::globalreg->kismet_config->fetch_opt("alertbacklog").c_str(), 
                    "%d", &scantmp) != 1 || scantmp < 0) {
            _MSG("Illegal value for 'alertbacklog' in kismet.conf, expected number greater than zero.",
                    MSGFLAG_FATAL);
            Globalreg::globalreg->fatal_condition = 1;
            return;
        }
        num_backlog = scantmp;
    }

    // Parse config file vector of all alerts
    if (parse_alert_config(Globalreg::globalreg->kismet_config) < 0) {
        _MSG("Failed to parse alert values from Kismet config file", MSGFLAG_FATAL);
        Globalreg::globalreg->fatal_condition = 1;
        return;
    }

    log_alerts = Globalreg::globalreg->kismet_config->fetch_opt_bool("kis_log_alerts", true);
}

alert_tracker::~alert_tracker() {
    local_locker lock(&alert_mutex);

    Globalreg::globalreg->RemoveGlobal("ALERTTRACKER");
    Globalreg::globalreg->alertracker = NULL;

#ifdef PRELUDE
    if (prelude_alerts) {
        prelude_deinit();
        delete prelude_client;
    }
#endif
}

void alert_tracker::prelude_init_client(const char *analyzer_name) {
#ifdef PRELUDE
    try {
        std::string version = 
            Globalreg::globalreg->version_major + "." + 
            Globalreg::globalreg->version_minor + "." +
            Globalreg::globalreg->version_tiny;

        prelude_client = 
            new Prelude::ClientEasy(analyzer_name, 4, PRELUDE_ANALYZER_MODEL, 
                PRELUDE_ANALYZER_CLASS, PRELUDE_ANALYZER_MANUFACTURER, version.c_str());
        prelude_client->start();
    } catch (Prelude::PreludeError const & error) {
        _MSG(std::string("alert_tracker failed to initialize connection to Prelude: ") + 
            error.what(), MSGFLAG_FATAL);
        Globalreg::globalreg->fatal_condition = 1;

        return;
    }
#endif
}

int alert_tracker::register_alert(std::string in_header, std::string in_description, 
        alert_time_unit in_unit, int in_rate, alert_time_unit in_burstunit,
        int in_burst, int in_phy) {
    local_locker lock(&alert_mutex);

    // Bail if this header is registered
    if (alert_name_map.find(in_header) != alert_name_map.end()) {
        _MSG("Tried to re-register duplicate alert " + in_header, MSGFLAG_ERROR);
        return -1;
    }

    // Make sure we're not going to overstep our range
    if ((unsigned int) in_burstunit > sat_day)
        in_burstunit = sat_day;
    if ((unsigned int) in_unit > sat_day)
        in_unit = sat_day;

    // Bail if the rates are impossible
    if (in_burstunit > in_unit) {
        _MSG("Failed to register alert " + in_header + ", time unit for "
                "burst rate must be less than or equal to the time unit "
                "for the max rate", MSGFLAG_ERROR);
        return -1;
    }

    auto arec =
        std::make_shared<tracked_alert_definition>(alert_def_id);

    arec->set_alert_ref(next_alert_id++);
    arec->set_header(str_upper(in_header));
    arec->set_description(in_description);
    arec->set_limit_unit(in_unit);
    arec->set_limit_rate(in_rate);
    arec->set_burst_unit(in_burstunit);
    arec->set_limit_burst(in_burst);
    arec->set_phy(in_phy);
    arec->set_time_last(0);

    alert_name_map.insert(std::make_pair(arec->get_header(), arec->get_alert_ref()));
    alert_ref_map.insert(std::make_pair(arec->get_alert_ref(), arec));

    alert_defs_vec->push_back(arec);

    return arec->get_alert_ref();
}

int alert_tracker::fetch_alert_ref(std::string in_header) {
    local_locker lock(&alert_mutex);

    auto ni = alert_name_map.find(in_header);

    if (ni != alert_name_map.end())
        return ni->second;

    return -1;
}

int alert_tracker::check_times(shared_alert_def arec) {
    // Alerts limited to 0 are squelched
    if (arec->get_limit_rate() == 0) {
        return 0;
    }

    struct timeval now;
    gettimeofday(&now, NULL);

    // If the last time we sent anything was longer than the main rate limit,
    // then we reset back to empty
    if (arec->get_time_last() < (now.tv_sec - 
                alert_time_unit_conv[arec->get_limit_unit()])) {
        arec->set_total_sent(0);
        arec->set_burst_sent(0);
        return 1;
    }

    // If the last time we sent anything was longer than the burst rate, we can
    // reset the burst to 0
    if (arec->get_time_last() < (now.tv_sec - 
                alert_time_unit_conv[arec->get_burst_unit()])) {
        arec->set_burst_sent(0);
    }

    // If we're under the limit on both, we're good to go
    if (arec->get_burst_sent() < arec->get_limit_burst() && 
            arec->get_total_sent() < arec->get_limit_rate())
        return 1;

    return 0;
}

int alert_tracker::potential_alert(int in_ref) {
    local_locker lock(&alert_mutex);

    std::map<int, shared_alert_def>::iterator aritr = alert_ref_map.find(in_ref);

    if (aritr == alert_ref_map.end())
        return 0;

    shared_alert_def arec = aritr->second;

    return check_times(arec);
}

int alert_tracker::raise_alert(int in_ref, kis_packet *in_pack,
        mac_addr bssid, mac_addr source, mac_addr dest, 
        mac_addr other, std::string in_channel, std::string in_text) {

    local_demand_locker lock(&alert_mutex);

    lock.lock();

    std::map<int, shared_alert_def>::iterator aritr = alert_ref_map.find(in_ref);

    if (aritr == alert_ref_map.end())
        return -1;

    shared_alert_def arec = aritr->second;

    if (check_times(arec) != 1)
        return 0;

    lock.unlock();

    kis_alert_info *info = new kis_alert_info;

    info->header = arec->get_header();
    info->phy = arec->get_phy();
    gettimeofday(&(info->tm), NULL);

    info->bssid = bssid;
    info->source = source;
    info->dest  = dest;
    info->other = other;

    info->channel = in_channel;	

    info->text = in_text;

    // Increment and set the timers
    arec->inc_burst_sent(1);
    arec->inc_total_sent(1);
    arec->set_time_last(ts_to_double(info->tm));

    lock.lock();

    alert_backlog_vec->push_back(std::make_shared<tracked_alert>(alert_entry_id, info));
    if ((int) alert_backlog_vec->size() > num_backlog) 
        alert_backlog_vec->erase(alert_backlog_vec->begin());

    lock.unlock();

    // Try to get the existing alert info
    if (in_pack != NULL)  {
        auto acomp = in_pack->fetch<kis_alert_component>(pack_comp_alert);

        // if we don't have an alert container, make one on this packet
        if (acomp == NULL) {
            acomp = new kis_alert_component;
            in_pack->insert(pack_comp_alert, acomp);
        }

        // Attach it to the packet
        acomp->alert_vec.push_back(info);

        // Also get GPS
        kis_gps_packinfo *pack_gpsinfo =
            (kis_gps_packinfo *) in_pack->fetch(pack_comp_gps);
        info->gps = new kis_gps_packinfo(pack_gpsinfo);
    }

#ifdef PRELUDE
    // Send alert to Prelude
    if (prelude_alerts)
        raise_prelude_alert(in_ref, in_pack, info->bssid, info->source, 
            info->dest, info->other, info->channel, info->text);
#endif

	// Send the text info
	_MSG(info->header + " " + info->text, MSGFLAG_ALERT);

    if (log_alerts) {
        auto dbf = 
            Globalreg::FetchGlobalAs<kis_database_logfile>("DATABASELOG");
        if (dbf != NULL) {
            auto ta = std::make_shared<tracked_alert>(alert_entry_id);
            ta->from_alert_info(info);
            dbf->log_alert(ta);
        }
    }

	return 1;
}

int alert_tracker::raise_one_shot(std::string in_header, std::string in_text, int in_phy) {
    local_demand_locker lock(&alert_mutex);

	kis_alert_info *info = new kis_alert_info;

	info->header = in_header;
	info->phy = in_phy;
	gettimeofday(&(info->tm), NULL);

	info->bssid = mac_addr(0);
	info->source = mac_addr(0);
	info->dest  = mac_addr(0);
	info->other = mac_addr(0);

	info->channel = "";	

	info->text = in_text;

    lock.lock();
	alert_backlog_vec->push_back(std::make_shared<tracked_alert>(alert_entry_id, info));
	if ((int) alert_backlog_vec->size() > num_backlog) {
		alert_backlog_vec->erase(alert_backlog_vec->begin());
	}
    lock.unlock();

#ifdef PRELUDE
    // Send alert to Prelude
    if (prelude_alerts)
        raise_prelude_one_shot(in_header, in_text);
#endif

	// Send the text info
	_MSG(info->header + " " + info->text, MSGFLAG_ALERT);

    if (log_alerts) {
        auto dbf =
            Globalreg::FetchGlobalAs<kis_database_logfile>("DATABASELOG");
        if (dbf != NULL) {
            auto ta = std::make_shared<tracked_alert>(alert_entry_id);
            ta->from_alert_info(info);
            dbf->log_alert(ta);
        }
    }

	return 1;
}

int alert_tracker::raise_prelude_alert(int in_ref, kis_packet *in_pack,
        mac_addr bssid, mac_addr source, mac_addr dest,
        mac_addr other, std::string in_channel, std::string in_text) {

#ifdef PRELUDE
    mac_addr emptymac = mac_addr(0);

    Prelude::IDMEF idmef;

    // Classification
    idmef.set("alert.classification.text", "Suspicious network detected");

    // Source
    if (source != emptymac) {
        idmef.set("alert.source(0).node.address(0).category", "mac");
        idmef.set("alert.source(0).node.address(0).address", source.mac_to_string().c_str());
    }

    // Target
    if (dest != emptymac) {
        idmef.set("alert.target(0).node.address(0).category", "mac");
        idmef.set("alert.target(0).node.address(0).address", dest.mac_to_string().c_str());
    }

    // Assessment
    idmef.set("alert.assessment.impact.severity", "high");
    idmef.set("alert.assessment.impact.completion", "succeeded");
    idmef.set("alert.assessment.impact.description", in_text);

    // Additional Data
    if (bssid != emptymac) {
        idmef.set("alert.additional_data(>>).meaning", "BSSID");
        idmef.set("alert.additional_data(-1).data", bssid.mac_to_string().c_str());
    }

    if (other != emptymac) {
        idmef.set("alert.additional_data(>>).meaning", "Other");
        idmef.set("alert.additional_data(-1).data", other.mac_to_string().c_str());
    }

    idmef.set("alert.additional_data(>>).meaning", "Channel");
    idmef.set("alert.additional_data(-1).data", in_channel);

    idmef.set("alert.additional_data(>>).meaning", "in_ref");
    idmef.set("alert.additional_data(-1).data", in_ref);

    prelude_client->sendIDMEF(idmef);
#endif

    return 0;
}

int alert_tracker::raise_prelude_one_shot(std::string in_header, std::string in_text) {
#ifdef PRELUDE
    mac_addr emptymac = mac_addr(0);

    Prelude::IDMEF idmef;

    // Classification
    idmef.set("alert.classification.text", "Suspicious network detected");

    // Assessment
    idmef.set("alert.assessment.impact.severity", "high");
    idmef.set("alert.assessment.impact.completion", "succeeded");
    idmef.set("alert.assessment.impact.description", in_text);

    idmef.set("alert.additional_data(>>).alert_type", "in_ref");
    idmef.set("alert.additional_data(-1).data", in_header);

    prelude_client->sendIDMEF(idmef);
#endif

    return 0;
}

int alert_tracker::parse_alert_str(std::string alert_str, std::string *ret_name, 
        alert_time_unit *ret_limit_unit, int *ret_limit_rate,
        alert_time_unit *ret_limit_burst, 
        int *ret_burst_rate) {

	std::vector<std::string> tokens = str_tokenize(alert_str, ",");

	if (tokens.size() != 3) {
        _MSG_ERROR("Malformed limits for alert '{}'", alert_str);
		return -1;
	}

	(*ret_name) = str_upper(tokens[0]);

	if (parse_rate_unit(str_lower(tokens[1]), ret_limit_unit, ret_limit_rate) != 1 ||
		parse_rate_unit(str_lower(tokens[2]), ret_limit_burst, ret_burst_rate) != 1) {
        _MSG_ERROR("Malformed limits for alert '{}'", alert_str);
		return -1;
	}

	return 1;
}

// Split up a rate/unit string into real values
int alert_tracker::parse_rate_unit(std::string in_ru, alert_time_unit *ret_unit,
        int *ret_rate) {
    std::vector<std::string> units = str_tokenize(in_ru, "/");

    if (units.size() == 1) {
        // Unit is per minute if not specified
        (*ret_unit) = sat_minute;
    } else {
        // Parse the string unit
        if (units[1] == "sec" || units[1] == "second") {
            (*ret_unit) = sat_second;
        } else if (units[1] == "min" || units[1] == "minute") {
            (*ret_unit) = sat_minute;
        } else if (units[1] == "hr" || units[1] == "hour") { 
            (*ret_unit) = sat_hour;
        } else if (units[1] == "day") {
            (*ret_unit) = sat_day;
        } else {
            _MSG("Invalid time unit for alert rate '" + units[1] + "'", 
                    MSGFLAG_ERROR);
            return -1;
        }
    }

    // Get the number
    if (sscanf(units[0].c_str(), "%d", ret_rate) != 1) {
        _MSG("Invalid rate '" + units[0] + "' for alert", MSGFLAG_ERROR);
        return -1;
    }

    return 1;
}

int alert_tracker::parse_alert_config(config_file *in_conf) {
    std::vector<std::string> clines = in_conf->fetch_opt_vec("alert");

    for (unsigned int x = 0; x < clines.size(); x++) {
        alert_conf_rec *rec = new alert_conf_rec;

        if (parse_alert_str(clines[x], &(rec->header), &(rec->limit_unit), 
                    &(rec->limit_rate), &(rec->burst_unit), 
                    &(rec->limit_burst)) < 0) {
            _MSG_FATAL("Invalid 'alert' config option {}; expected HEADER,rate,burstrate", clines[x]);
            Globalreg::globalreg->fatal_condition = 1;
            delete rec;
            return -1;
        }

        alert_conf_map.insert(std::make_pair(rec->header, rec));
    }

    return 1;
}

int alert_tracker::define_alert(std::string name, alert_time_unit limit_unit, int limit_rate,
        alert_time_unit burst_unit, int burst_rate) {
    local_locker lock(&alert_mutex);

    auto ai = alert_conf_map.find(str_upper(name));
    if (ai != alert_conf_map.end()) {
        _MSG_ERROR("alerttracker - tried to define alert '{}' twice.", name);
        return -1;
    }

    alert_conf_rec *rec = new alert_conf_rec;
    rec->header = str_upper(name);
    rec->limit_unit = limit_unit;
    rec->limit_rate = limit_rate;
    rec->burst_unit = burst_unit;
    rec->limit_burst = burst_rate;

    alert_conf_map.insert(std::make_pair(rec->header, rec));

    return 1;
}

int alert_tracker::activate_configured_alert(std::string in_header, std::string in_desc) {
	return activate_configured_alert(in_header, in_desc, KIS_PHY_UNKNOWN);
}

int alert_tracker::activate_configured_alert(std::string in_header, std::string in_desc, int in_phy) {
    alert_conf_rec *rec;

    {
        local_locker lock(&alert_mutex);

        std::string hdr = str_upper(in_header);

        auto hi = alert_conf_map.find(hdr);

        if (hi == alert_conf_map.end()) {
            _MSG_INFO("Using default rates of 10/min, 1/sec for alert '{}'", in_header);
            define_alert(in_header, sat_minute, 10, sat_second, 1);

            auto hi_full = alert_conf_map.find(hdr);
            if (hi_full == alert_conf_map.end()) {
                _MSG_ERROR("Failed to define default rate alert '{}'", in_header);
                return -1;
            }

            rec = hi_full->second;
        } else {
            rec = hi->second;
        }
    }

	return register_alert(rec->header, in_desc, rec->limit_unit, rec->limit_rate, 
            rec->burst_unit, rec->limit_burst, in_phy);
}

int alert_tracker::find_activated_alert(std::string in_header) {
    local_locker lock(&alert_mutex);

    for (auto x : alert_ref_map) {
        if (x.second->get_header() == in_header)
            return x.first;
    }

    return -1;
}

bool alert_tracker::last_alerts_endpoint_path(const std::vector<std::string>& path) {
    // /alerts/last-time/[timestamp]/alerts
    // /alerts/wrapped/last-time/[timestamp]/alerts
   
    if (path.size() < 4)
        return false;

    // timestamp validated in actual response
    if (path[0] == "alerts" && path[1] == "last-time" && path[3] == "alerts") {
        return true;
    }

    if (path.size() == 5 && path[0] == "alerts" && path[1] == "wrapped" && 
            path[2] == "last-time" && path[4] == "alerts") {
        return true;
    }

    return false;
}

std::shared_ptr<tracker_element> alert_tracker::last_alerts_endpoint(const std::vector<std::string>& path) {
    std::shared_ptr<tracker_element> transmit;
    std::shared_ptr<tracker_element_map> wrapper;
    std::shared_ptr<tracker_element_vector> msgvec = std::make_shared<tracker_element_vector>(alert_vec_id);
    bool wrap = false;
    double since_time = 0;

    // timestamp validated in actual response
    if (path[0] == "alerts" && path[1] == "last-time" && path[3] == "alerts") {
        wrap = false;
        std::stringstream ss{path[2]};
        ss >> since_time;
    }

    if (path.size() == 5 && path[0] == "alerts" && path[1] == "wrapped" && 
            path[2] == "last-time" && path[4] == "alerts") {
        wrap = true;
        std::stringstream ss{path[3]};
        ss >> since_time;
    }

    if (wrap) {
        wrapper = std::make_shared<tracker_element_map>();
        wrapper->insert(msgvec);

        auto ts = std::make_shared<tracker_element_double>(alert_timestamp_id, ts_now_to_double());
        wrapper->insert(ts);

        transmit = wrapper;
    } else {
        transmit = msgvec;
    }

    {
        local_locker lock(&alert_mutex);

        for (auto i : *alert_backlog_vec) {
            auto ai = std::static_pointer_cast<tracked_alert>(i);
            if (since_time < ai->get_timestamp()) {
                msgvec->push_back(ai);
            }
        }
    }

    return transmit;
}

unsigned int alert_tracker::define_alert_endpoint(std::ostream& stream, const std::string& uri,
        const Json::Value& json, kis_net_httpd_connection::variable_cache_map& variable_cache) {
    try {
        auto name = json["name"].asString();
        auto description = json["description"].asString();

        alert_time_unit limit_unit;
        int limit_rate;

        alert_time_unit burst_unit;
        int burst_rate;

        if (parse_rate_unit(str_lower(json.get("throttle", "").asString()),
                    &limit_unit, &limit_rate) < 0) {
            throw std::runtime_error("could not parse throttle limits");
        }

        if (parse_rate_unit(str_lower(json.get("burst", "").asString()),
                    &burst_unit, &burst_rate) < 0) {
            throw std::runtime_error("could not parse burst limits");
        }

        int phyid = KIS_PHY_ANY;

        auto phyname = json.get("phyname", "").asString();

        if (phyname != "any" && phyname != "") {
            auto devicetracker = 
                Globalreg::fetch_mandatory_global_as<device_tracker>();
            kis_phy_handler *phyh = devicetracker->fetch_phy_handler_by_name(phyname);

            if (phyh == NULL)
                throw std::runtime_error("could not find phy");

            phyid = phyh->fetch_phy_id();
        }

        if (define_alert(name, limit_unit, limit_rate, burst_unit, burst_rate) < 0) {
            stream << "Could not define alert\n";
            return 503;
        }

        if (activate_configured_alert(name, description, phyid) < 0) {
            stream << "Could not activate alert\n";
            return 504;
        }

    } catch (const std::exception& e) {
        stream << "Invalid request: " << e.what() << "\n";
        return 400;
    };

    return 200;
}

unsigned int alert_tracker::raise_alert_endpoint(std::ostream& stream, const std::string& uri,
        const Json::Value& json, kis_net_httpd_connection::variable_cache_map& variable_cache) {
    try {
        auto name = json["name"].asString();
        auto text = json["text"].asString();

        auto aref = fetch_alert_ref(name);

        if (aref < 0) {
            stream << "Invalid request:  Unknown alert type\n";
            return 400;
        }

        auto bssid = json.get("bssid", "").asString();
        auto source = json.get("source", "").asString();
        auto dest = json.get("dest", "").asString();
        auto other = json.get("other", "").asString();
        auto channel = json.get("channel", "").asString();

        mac_addr bssid_mac, source_mac, dest_mac, other_mac;

        if (bssid.length() != 0)
            bssid_mac = mac_addr(bssid);

        if (source.length() != 0)
            source_mac = mac_addr(source);

        if (dest.length() != 0)
            dest_mac = mac_addr(dest);

        if (other.length() != 0)
            other_mac = mac_addr(other);

        if (bssid_mac.error || source_mac.error || dest_mac.error || other_mac.error)
            throw std::runtime_error("invalid MAC address");

        if (!potential_alert(aref))
            throw std::runtime_error("alert throttle reached, alert not raised.");

        raise_alert(aref, nullptr, bssid_mac, source_mac, dest_mac, other_mac,
                channel, text);

    } catch (const std::exception& e) {
        stream << "Invalid request: " << e.what() << "\n";
        return 400;
    };

    stream << "Success: Alert raised\n";
    return 200;
}

