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

#include <string.h>

#include "alertracker.h"
#include "base64.h"
#include "configfile.h"
#include "datasourcetracker.h"
#include "endian_magic.h"
#include "getopt.h"
#include "globalregistry.h"
#include "kismet_json.h"
#include "kis_databaselogfile.h"
#include "kis_httpd_registry.h"
#include "messagebus.h"
#include "pcapng_stream_ringbuf.h"
#include "socketclient.h"
#include "streamtracker.h"
#include "structured.h"
#include "timetracker.h"

datasource_tracker_source_probe::datasource_tracker_source_probe(std::string in_definition, 
        std::shared_ptr<tracker_element_vector> in_protovec) :
    probe_lock {std::make_shared<kis_recursive_timed_mutex>()},
    timetracker {Globalreg::fetch_mandatory_global_as<time_tracker>()},
    proto_vec {in_protovec},
    transaction_id {0},
    definition {in_definition},
    cancelled {false} { }

datasource_tracker_source_probe::~datasource_tracker_source_probe() {
    // Cancel any timers
    for (auto i : cancel_timer_vec)
        timetracker->remove_timer(i);

    // Cancel any existing transactions
    for (auto i : ipc_probe_map)
        i.second->close_source();
}

void datasource_tracker_source_probe::cancel() {
    {
        local_locker lock(probe_lock);

        cancelled = true;

        // Cancel any timers
        for (auto i : cancel_timer_vec)
            timetracker->remove_timer(i);

        // Cancel any other competing probing sources; this may trigger the callbacks
        // which will call the completion function, but we'll ignore them because
        // we're already cancelled
        for (auto i : ipc_probe_map)
            i.second->close_source();

        // Defer deleting sources until the probe map is cleared
    }

    // Unlock just before we call the CB so that we're not callbacked inside a thread lock;
    // call back with whatever we found - if we got something, great, otherwise we callback a 
    // nullptr
    if (probe_cb) 
        probe_cb(source_builder);
}

shared_datasource_builder datasource_tracker_source_probe::get_proto() {
    local_locker lock(probe_lock);
    return source_builder;
}

void datasource_tracker_source_probe::complete_probe(bool in_success, unsigned int in_transaction,
        std::string in_reason __attribute__((unused))) {
    local_locker lock(probe_lock);

    // If we're already in cancelled state these callbacks mean nothing, ignore them, we're going
    // to be torn down so we don't even need to find our transaction
    if (cancelled)
        return;

    auto v = ipc_probe_map.find(in_transaction);

    if (v != ipc_probe_map.end()) {
        if (in_success) {
            source_builder = v->second->get_source_builder();
        }

        // Move them to the completed vec
        complete_vec.push_back(v->second);

        // Remove them from the map
        ipc_probe_map.erase(v);
    } else {
        // fprintf(stderr, "debug - dstp - complete_probe - couldn't find transaction record for transaction %u\n", in_transaction);
    }

    // If we've succeeded, cancel any others, cancel will take care of our
    // callback for completion
    if (in_success) {
        cancel();
        return;
    } else {
        // If we've exhausted everything in the map, we're also done
        if (ipc_probe_map.size() == 0) {
            cancel();
            return;
        }
    }
}

void datasource_tracker_source_probe::probe_sources(std::function<void (shared_datasource_builder)> in_cb) {
    {
        local_locker lock(probe_lock);
        probe_cb = in_cb;
    }

    std::vector<shared_datasource_builder> remote_builders;

    unsigned int ncreated = 0;

    // Do some basic validation on the definition
    // If there's a comma in the interface name and no colon, someone probably typoed; 
    // if there's a comma before the colon, also probably a typo
    auto comma_pos = definition.find(",");
    auto colon_pos = definition.find(":");

    if ((comma_pos != std::string::npos && colon_pos == std::string::npos) || comma_pos < colon_pos) {
        _MSG_ERROR("Found a ',' in the source definition '{}'.  Sources should be defined as "
                "interface:option1,option2,... this is likely a typo in your 'source=' config "
                "or in your '-c' option on the command line.", definition);
        cancel();
        return;
    }

    for (auto i : *proto_vec) {
        auto b = std::static_pointer_cast<kis_datasource_builder>(i);

        if (!b->get_probe_capable())
            continue;
       
        unsigned int transaction = ++transaction_id;

        // Instantiate a local prober datasource
        shared_datasource pds = b->build_datasource(b, probe_lock);

        {
            local_locker lock(probe_lock);
            ipc_probe_map[transaction] = pds;
            ncreated++;
        }

        // Set up the cancellation timer
        int cancel_timer = 
            timetracker->register_timer(SERVER_TIMESLICES_SEC * 10, NULL, 0, 
                    [this] (int) -> int {
                        _MSG_ERROR("Datasource {} cancelling source probe due to timeout", definition);
                        cancel();
                        return 0;
                    });

        // Log the cancellation timer
        cancel_timer_vec.push_back(cancel_timer);

        pds->probe_interface(definition, transaction, 
                [cancel_timer, this](unsigned int transaction, bool success, std::string reason) {
                    timetracker->remove_timer(cancel_timer);
                    complete_probe(success, transaction, reason);
                });
    }

    // We've done all we can; if we haven't gotten an answer yet and we
    // have nothing in our transactional map, we've failed
    if (ncreated == 0) {
        cancel();
        return;
    }

}

datasource_tracker_source_list::datasource_tracker_source_list(std::shared_ptr<tracker_element_vector> in_protovec) :
    list_lock {std::make_shared<kis_recursive_timed_mutex>()},
    timetracker {Globalreg::fetch_mandatory_global_as<time_tracker>()},
    proto_vec {in_protovec},
    transaction_id {0},
    cancelled {false} { }

datasource_tracker_source_list::~datasource_tracker_source_list() {
    cancelled = true;

    // Cancel any probing sources and delete them
    for (auto s : list_vec)
        s->close_source();

    for (auto s : complete_vec)
        s->close_source();
}

void datasource_tracker_source_list::cancel() {
    local_locker lock(list_lock);

    if (cancelled)
        return;

    // Abort anything already underway
    for (auto i : ipc_list_map) {
        i.second->close_source();
    }

    cancelled = true;

    // Trigger the callback
    if (list_cb) 
        list_cb(listed_sources);
}

void datasource_tracker_source_list::complete_list(std::vector<shared_interface> in_list, unsigned int in_transaction) {
    local_locker lock(list_lock);

    // If we're already in cancelled state these callbacks mean nothing, ignore them
    if (cancelled)
        return;

    for (auto i = in_list.begin(); i != in_list.end(); ++i) {
        listed_sources.push_back(*i);
    }

    auto v = ipc_list_map.find(in_transaction);
    if (v != ipc_list_map.end()) {
        complete_vec.push_back(v->second);
        ipc_list_map.erase(v);
    }

    // If we've emptied the vec, end
    if (ipc_list_map.size() == 0) {
        cancel();
        return;
    }
}

void datasource_tracker_source_list::list_sources(std::function<void (std::vector<shared_interface>)> in_cb) {
    list_cb = in_cb;

    std::vector<shared_datasource_builder> remote_builders;

    bool created_ipc = false;

    for (auto i : *proto_vec) {
        shared_datasource_builder b = std::static_pointer_cast<kis_datasource_builder>(i);

        if (!b->get_list_capable())
            continue;
       
        unsigned int transaction = ++transaction_id;

        // Instantiate a local lister 
        shared_datasource pds = b->build_datasource(b, list_lock);

        {
            local_locker lock(list_lock);
            ipc_list_map[transaction] = pds;
            list_vec.push_back(pds);
            created_ipc = true;
        }

        pds->list_interfaces(transaction, 
            [this] (unsigned int transaction, std::vector<shared_interface> interfaces) {
                complete_list(interfaces, transaction);
            });
    }

    // If we didn't create any IPC events we'll never complete; call cancel directly
    if (!created_ipc)
        cancel();
}


datasource_tracker::datasource_tracker() :
    kis_net_httpd_cppstream_handler() {

    dst_lock.set_name("datasourcetracker");

    timetracker = Globalreg::fetch_mandatory_global_as<time_tracker>();
    eventbus = Globalreg::fetch_mandatory_global_as<event_bus>();

    proto_id = 
        Globalreg::globalreg->entrytracker->register_field("kismet.datasourcetracker.driver",
                tracker_element_factory<kis_datasource_builder>(),
                "Datasource driver information");

    source_id =
        Globalreg::globalreg->entrytracker->register_field("kismet.datasourcetracker.datasource",
                tracker_element_factory<kis_datasource>(nullptr, nullptr),
                "Datasource");

    proto_vec =
        Globalreg::globalreg->entrytracker->register_and_get_field_as<tracker_element_vector>("kismet.datasourcetracker.drivers",
                tracker_element_factory<tracker_element_vector>(), "Known drivers");

    datasource_vec =
        Globalreg::globalreg->entrytracker->register_and_get_field_as<tracker_element_vector>("kismet.datasourcetracker.sources",
                tracker_element_factory<tracker_element_vector>(), "Configured sources");

    all_sources_endp =
        std::make_shared<kis_net_httpd_simple_tracked_endpoint>("/datasource/all_sources",
                [this]() -> std::shared_ptr<tracker_element> {
                    local_shared_locker sl(&dst_lock);
                    auto serial_vec = std::make_shared<tracker_element_vector>(datasource_vec);
                    return serial_vec;
                });

    defaults_endp =
        std::make_shared<kis_net_httpd_simple_tracked_endpoint>("/datasource/defaults",
                config_defaults, &dst_lock);

    types_endp =
        std::make_shared<kis_net_httpd_simple_tracked_endpoint>("/datasource/types", 
                proto_vec, &dst_lock);

    list_interfaces_endp =
        std::make_shared<kis_net_httpd_simple_tracked_endpoint>("/datasource/list_interfaces", 
                [this]() -> std::shared_ptr<tracker_element> {
                    // Locker for waiting for the list callback
                    auto cl = std::make_shared<conditional_locker<std::vector<shared_interface> >>();

                    cl->lock();

                    // Initiate the open
                    list_interfaces(
                        [cl](std::vector<shared_interface> iflist) {
                            cl->unlock(iflist);
                        });

                    // Block until the list cmd unlocks us
                    auto iflist = cl->block_until();

                    auto iv = std::make_shared<tracker_element_vector>();

                    for (auto li : iflist)
                        iv->push_back(li);

                    return iv;
                });

    bind_httpd_server();
}

datasource_tracker::~datasource_tracker() {
    Globalreg::globalreg->RemoveGlobal("DATASOURCETRACKER");

    if (remote_tcp_server != nullptr) {
        auto pollabletracker = 
            Globalreg::fetch_mandatory_global_as<pollable_tracker>();
        remote_tcp_server->shutdown();
        pollabletracker->remove_pollable(remote_tcp_server);
    }

    if (completion_cleanup_id >= 0)
        timetracker->remove_timer(completion_cleanup_id);

    if (database_log_timer >= 0) {
        timetracker->remove_timer(database_log_timer);
        databaselog_write_datasources();
    }

    for (auto i : probing_map)
        i.second->cancel();

    for (auto i : listing_map)
        i.second->cancel();
}

void datasource_tracker::databaselog_write_datasources() {
    if (!database_log_enabled)
        return;

    std::shared_ptr<kis_database_logfile> dbf =
        Globalreg::FetchGlobalAs<kis_database_logfile>("DATABASELOG");
    
    if (dbf == NULL)
        return;

    // Fire off a database log, using a copy of the datasource vec
    std::shared_ptr<tracker_element_vector> v;

    {
        local_shared_locker l(&dst_lock);
        v = std::make_shared<tracker_element_vector>(datasource_vec);
    }

    dbf->log_datasources(v);
}

std::shared_ptr<datasource_tracker_defaults> datasource_tracker::get_config_defaults() {
    return config_defaults;
}

void datasource_tracker::trigger_deferred_startup() {
    bool used_args = false;

    completion_cleanup_id = -1;
    next_probe_id = 0;
    next_list_id = 0;

    next_source_num = 0;

    tcp_buffer_sz = 
        Globalreg::globalreg->kismet_config->fetch_opt_as<size_t>("tcp_buffer_kb", 512);

    config_defaults = 
        Globalreg::globalreg->entrytracker->register_and_get_field_as<datasource_tracker_defaults>("kismet.datasourcetracker.defaults",
                tracker_element_factory<datasource_tracker_defaults>(),
                "Datasource default values");

    if (Globalreg::globalreg->kismet_config->fetch_opt_bool("channel_hop", true)) {
        _MSG("Enabling channel hopping by default on sources which support channel "
                "control.", MSGFLAG_INFO);
        config_defaults->set_hop(true);
    }

    std::string optval;
    if ((optval = Globalreg::globalreg->kismet_config->fetch_opt("channel_hop_speed")) != "") {
        try {
            double dv = string_to_rate(optval, 1);
            config_defaults->set_hop_rate(dv);
            _MSG("Setting default channel hop rate to " + optval, MSGFLAG_INFO);
        } catch (const std::exception& e) {
            _MSG_FATAL("Could not parse channel_hop_speed= config: {}", e.what());
            Globalreg::globalreg->fatal_condition = 1;
            return;
        }
    } else {
        _MSG("No channel_hop_speed= in kismet config, setting hop "
                "rate to 1/sec", MSGFLAG_INFO);
        config_defaults->set_hop_rate(1);
    }

    if (Globalreg::globalreg->kismet_config->fetch_opt_bool("split_source_hopping", true)) {
        _MSG("Enabling channel list splitting on sources which share the same list "
                "of channels", MSGFLAG_INFO);
        config_defaults->set_split_same_sources(true);
    }

    if (Globalreg::globalreg->kismet_config->fetch_opt_bool("randomized_hopping", true)) {
        _MSG("Enabling channel list shuffling to optimize overlaps", MSGFLAG_INFO);
        config_defaults->set_random_channel_order(true);
    }

    if (Globalreg::globalreg->kismet_config->fetch_opt_bool("retry_on_source_error", true)) {
        _MSG("Sources will be re-opened if they encounter an error", MSGFLAG_INFO);
        config_defaults->set_retry_on_error(true);
    }

    std::string listen = Globalreg::globalreg->kismet_config->fetch_opt("remote_capture_listen");
    uint32_t listenport = 
        Globalreg::globalreg->kismet_config->fetch_opt_uint("remote_capture_port", 0);

    if (listen.length() == 0) {
        _MSG("No remote_capture_listen= line found in kismet.conf; no remote "
                "capture will be enabled.", MSGFLAG_INFO);
    }

    if (listenport == 0) {
        _MSG("No remote_capture_port= line found in kismet.conf; no remote "
                "capture will be enabled.", MSGFLAG_INFO);
    }

    config_defaults->set_remote_cap_listen(listen);
    config_defaults->set_remote_cap_port(listenport);

    config_defaults->set_remote_cap_timestamp(Globalreg::globalreg->kismet_config->fetch_opt_bool("override_remote_timestamp", true));

    httpd_pcap = std::make_shared<datasource_tracker_httpd_pcap>();

    // Register js module for UI
    std::shared_ptr<kis_httpd_registry> httpregistry = 
        Globalreg::fetch_mandatory_global_as<kis_httpd_registry>("WEBREGISTRY");
    httpregistry->register_js_module("kismet_ui_datasources", 
            "js/kismet.ui.datasources.js");

    database_log_enabled = false;

    if (Globalreg::globalreg->kismet_config->fetch_opt_bool("kis_log_datasources", true)) {
        unsigned int lograte =
            Globalreg::globalreg->kismet_config->fetch_opt_uint("kis_log_datasource_rate", 30);

        _MSG("Saving datasources to the Kismet database log every " + uint_to_string(lograte) + 
                " seconds.", MSGFLAG_INFO);

        database_log_enabled = true;
        database_logging = false;

        database_log_timer =
            timetracker->register_timer(SERVER_TIMESLICES_SEC * lograte, NULL, 1, 
                    [this](int) -> int {

                        {
                            local_locker l(&dst_lock);

                            if (database_logging) {
                                _MSG("Attempting to log datasources, but datasources are still "
                                        "being saved from the last logging attempt.  It's possible "
                                        "your system is extremely over capacity; try increasing the "
                                        "delay in 'kis_log_datasource_rate' in kismet_logging.conf",
                                        MSGFLAG_ERROR);
                                return 1;
                            }

                            database_logging = true;
                        }

                        std::thread t([this] {
                            databaselog_write_datasources();

                            {
                                local_locker l(&dst_lock);
                                database_logging = false;
                            }

                        });

                        t.detach();

                        return 1;
                    });

    } else {
        database_log_timer = -1;
    }


    // Create an alert for source errors
    auto alertracker = Globalreg::fetch_mandatory_global_as<alert_tracker>("ALERTTRACKER");

    alertracker->define_alert("SOURCEERROR", sat_second, 1, sat_second, 10);
    alertracker->activate_configured_alert("SOURCEERROR",
            "A data source encountered an error.  Depending on the source configuration "
            "Kismet may automatically attempt to re-open the source.");

    std::vector<std::string> src_vec;

    int option_idx = 0;

	static struct option packetsource_long_options[] = {
		{ "capture-source", required_argument, 0, 'c' },
		{ 0, 0, 0, 0 }
	};

    optind = 0;

    // Activate remote capture
    listen = config_defaults->get_remote_cap_listen();
    listenport = config_defaults->get_remote_cap_port();

    if (config_defaults->get_remote_cap_listen().length() != 0 && 
            config_defaults->get_remote_cap_port() != 0) {
        _MSG("Launching remote capture server on " + listen + ":" + 
                uint_to_string(listenport), MSGFLAG_INFO);
        remote_tcp_server = std::make_shared<tcp_server_v2>();
        if (remote_tcp_server->configure_server(listenport, 1024, listen, std::vector<std::string>()) < 0) {
            _MSG("Failed to launch remote capture TCP server, check your "
                    "remote_capture_listen= and remote_capture_port= lines in "
                    "kismet.conf", MSGFLAG_FATAL);
            Globalreg::globalreg->fatal_condition = 1;
        }
        remote_tcp_server->set_new_connection_cb([this](int fd) -> void {
                new_remote_tcp_connection(fd);
                });

        auto pollabletracker =
            Globalreg::fetch_mandatory_global_as<pollable_tracker>();
        pollabletracker->register_pollable(remote_tcp_server);
    }

    remote_complete_timer = -1;

    while (1) {
        int r = getopt_long(Globalreg::globalreg->argc, Globalreg::globalreg->argv, "-c:",
                packetsource_long_options, &option_idx);

        if (r < 0) break;

        if (r == 'c') {
            used_args = true;
            src_vec.push_back(std::string(optarg));
        }
    }

    if (used_args) {
        _MSG("Data sources passed on the command line (via -c source), ignoring "
                "source= definitions in the Kismet config file.", MSGFLAG_INFO);
    } else {
        src_vec = Globalreg::globalreg->kismet_config->fetch_opt_vec("source");
    }

    if (src_vec.size() == 0) {
        _MSG("No data sources defined; Kismet will not capture anything until "
                "a source is added.", MSGFLAG_INFO);
        return;
    }

    auto stagger_thresh = 
        Globalreg::globalreg->kismet_config->fetch_opt_uint("source_stagger_threshold", 16);
    auto simul_open = 
        Globalreg::globalreg->kismet_config->fetch_opt_uint("source_launch_group", 10);
    auto simul_open_delay = 
        Globalreg::globalreg->kismet_config->fetch_opt_uint("source_launch_delay", 10);

    auto launch_func = [](datasource_tracker *dst, std::string src) {
            dst->open_datasource(src, 
                    [src](bool success, std::string reason, shared_datasource) {
                if (success) {
                    _MSG_INFO("Data source '{}' launched successfully", src);
                } else {
                    if (reason.length() != 0) {
                        _MSG_ERROR("Data source '{}' failed to launch: {}", src, reason);
                    } else {
                        _MSG_ERROR("Data source '{}' failed to launch, no error provided.", src);
                    }
                }
            });
    };

    if (stagger_thresh == 0 || src_vec.size() <= stagger_thresh) {
        auto source_t = std::thread([launch_func](datasource_tracker *dst, 
                    const std::vector<std::string>& src_vec) {
                for (auto i : src_vec) {
                    launch_func(dst, i);
                }
                }, this, src_vec);
        source_t.detach();
    } else {
        std::vector<std::string> work_vec;
        unsigned int group_number = 0;

        for (auto i : src_vec) {
            work_vec.push_back(i);

            if (work_vec.size() > simul_open) {
                // Pass a copy of the work vec so that we can immediately clear it
                auto launch_t = std::thread([launch_func, simul_open_delay](datasource_tracker *dst,
                            const std::vector<std::string> src_vec, unsigned int gn) {

                    // All the threads launch more or less at once, so each thread sleeps for
                    // its allocated amount of time before launching the vector
                    sleep(gn * simul_open_delay);
                    _MSG_INFO("Launching local source group {}", gn + 1);

                    for (auto i : src_vec) {
                        launch_func(dst, i);
                    }
                }, this, work_vec, group_number);
                launch_t.detach();

                work_vec.clear();
                group_number++;
            }
        }

        // Launch the last of the group
        auto launch_t = std::thread([launch_func, simul_open_delay](datasource_tracker *dst,
                    const std::vector<std::string> src_vec, unsigned int gn) {

                    sleep(gn * simul_open_delay);
                    _MSG_INFO("Launching local source group {}", gn);

                    for (auto i : src_vec) {
                        launch_func(dst, i);
                    }
                }, this, work_vec, group_number);
                launch_t.detach();
    }

    return;
}

void datasource_tracker::trigger_deferred_shutdown() {
    local_locker lock(&dst_lock);

    for (auto i : *datasource_vec) {
        std::static_pointer_cast<kis_datasource>(i)->close_source();
    }
}

void datasource_tracker::iterate_datasources(datasource_tracker_worker *in_worker) {
    std::shared_ptr<tracker_element_vector> immutable_copy;

    {
        local_locker lock(&dst_lock);
        immutable_copy = std::make_shared<tracker_element_vector>(datasource_vec);
    }

    for (auto kds : *immutable_copy) {
        in_worker->handle_datasource(std::static_pointer_cast<kis_datasource>(kds));
    }

    in_worker->finalize();
}

bool datasource_tracker::remove_datasource(const uuid& in_uuid) {
    local_locker lock(&dst_lock);

    // Look for it in the sources vec and fully close it and get rid of it
    for (auto i = datasource_vec->begin(); i != datasource_vec->end(); ++i) {
        shared_datasource kds = std::static_pointer_cast<kis_datasource>(*i);

        if (kds->get_source_uuid() == in_uuid) {
            std::stringstream ss;

            _MSG_INFO("Closing source '{}' and removing it from the list of available "
                    "datasources.", kds->get_source_name());

            // close it
            kds->close_source();

            // Remove it
            datasource_vec->erase(i);

            // Done
            return true;
        }
    }

    return false;
}

shared_datasource datasource_tracker::find_datasource(const uuid& in_uuid) {
    local_shared_locker lock(&dst_lock);

    for (auto i : *datasource_vec) {
        shared_datasource kds = std::static_pointer_cast<kis_datasource>(i);

        if (kds->get_source_uuid() == in_uuid) 
            return kds;
    }

    return nullptr;
}

bool datasource_tracker::close_datasource(const uuid& in_uuid) {
    local_locker lock(&dst_lock);

    for (auto i : *datasource_vec) {
        shared_datasource kds = std::static_pointer_cast<kis_datasource>(i);

        if (kds->get_source_uuid() == in_uuid) {
            _MSG_INFO("Closing source '{}'", kds->get_source_name());

            // close it
            kds->close_source();

            // Done
            return true;
        }
    }

    return false;
}

int datasource_tracker::register_datasource(shared_datasource_builder in_builder) {
    local_locker lock(&dst_lock);

    for (auto i : *proto_vec) {
        shared_datasource_builder b = std::static_pointer_cast<kis_datasource_builder>(i);

        if (str_lower(b->get_source_type()) == str_lower(in_builder->get_source_type())) {
            _MSG_ERROR("Already registered a data source for type '{}', check that you don't have "
                    "two copies of the same plugin installed in different locations or under "
                    "different names.", b->get_source_type());
            return -1;
        }
    }

    proto_vec->push_back(in_builder);

    return 1;
}

void datasource_tracker::open_datasource(const std::string& in_source, 
        const std::function<void (bool, std::string, shared_datasource)>& in_cb) {
    // fprintf(stderr, "debug - DST open source %s\n", in_source.c_str());

    // Open a datasource only from the string definition

    std::string interface;
    std::string options;
    std::vector<opt_pair> opt_vec;
    std::string type;

    size_t cpos = in_source.find(":");

    // Parse basic options and interface, extract type
    if (cpos == std::string::npos) {
        interface = in_source;
        type = "auto";
    } else {
        interface = in_source.substr(0, cpos);
        options = in_source.substr(cpos + 1, in_source.size() - cpos);

        string_to_opts(options, ",", &opt_vec);

        type = str_lower(fetch_opt("type", &opt_vec));

        if (type == "")
            type = "auto";
    }

    // So long as we have a type - that is, an explicitly defined type which
    // is not "auto" - we know what driver is supposed to open it.  We look
    // for that driver in the prototype vector, confirm it can open it, and fire
    // the launch command at it
    if (type != "auto") {
        local_demand_locker lock(&dst_lock);
        lock.lock();

        shared_datasource_builder proto;

        bool proto_found = false;

        for (auto i : *proto_vec) {
            proto = std::static_pointer_cast<kis_datasource_builder>(i);

            if (str_lower(proto->get_source_type()) == str_lower(type)) {
                proto_found = true;
                break;
            }
        }

        if (!proto_found) {
            auto ss = fmt::format("Unable to find datasource for '{}'.  Make sure that any "
                    "required plugins are installed, that the capture interface is available, "
                    "and that you installed all the Kismet helper packages.", type);

            if (in_cb != NULL) {
                lock.unlock();
                in_cb(false, ss, NULL);
                lock.lock();
            }

            return;
        }

        // Open the source with the processed options
        open_datasource(in_source, proto, in_cb);
        return;
    }

    // Otherwise we have to initiate a probe, which is async itself, and 
    // tell it to call our CB when it completes.  The probe will find if there 
    // is a driver that can claim the source string we were given, and 
    // we'll initiate opening it if there is
    _MSG_INFO("Probing interface '{}' to find datasource type", interface);

    // Create a DSTProber to handle the probing
    shared_dst_source_probe dst_probe(new datasource_tracker_source_probe(in_source, proto_vec));
    unsigned int probeid = ++next_probe_id;

    // Record and initiate it
    {
        local_locker dl(&dst_lock);
        probing_map[probeid] = dst_probe;
    }

    // Initiate the probe
    dst_probe->probe_sources([this, probeid, in_cb](shared_datasource_builder builder) {
        // Lock on completion
        local_demand_locker lock(&dst_lock);
        lock.lock();

        // fprintf(stderr, "debug - moving probe to completed vec\n");

        auto i = probing_map.find(probeid);

        if (i != probing_map.end()) {
            if (builder == nullptr) {
                // We couldn't find a type, return an error to our initial open CB
                auto ss = fmt::format("Unable to find driver for '{}'.  Make sure that any required plugins "
                        "are loaded, the interface is available, and any required Kismet helper packages are "
                        "installed.", i->second->get_definition());
                _MSG(ss, MSGFLAG_ERROR);
                lock.unlock();
                in_cb(false, ss, NULL);
                lock.lock();
            } else {
                // We got a builder
                auto ss = fmt::format("Found type '{}' for '{}'", builder->get_source_type(), i->second->get_definition());
                _MSG(ss, MSGFLAG_INFO);

                // Initiate an open w/ a known builder, associate the prototype definition with it
                open_datasource(i->second->get_definition(), builder, in_cb);
            }

            // Mark this object for completion when the callback triggers
            probing_complete_vec.push_back(i->second);

            // Remove us from the active vec
            probing_map.erase(i);

            // Schedule a cleanup 
            schedule_cleanup();
        } else {
            // fprintf(stderr, "debug - DST couldn't find response %u\n", probeid);
        }
    });

    return;
}

void datasource_tracker::open_datasource(const std::string& in_source, 
        shared_datasource_builder in_proto,
        const std::function<void (bool, std::string, shared_datasource)>& in_cb) {
    local_locker lock(&dst_lock);

    // Make a data source from the builder
    shared_datasource ds = in_proto->build_datasource(in_proto, nullptr);

    ds->open_interface(in_source, 0, 
        [this, ds, in_cb] (unsigned int, bool success, std::string reason) {
            // Always merge it so that it gets scheduled for re-opening; when we
            // know the type we know how to keep trying
            merge_source(ds);

            // Whenever we succeed (or fail) at opening a deferred open source,
            // call our callback w/ whatever we know
            if (success) {
                in_cb(true, "", ds);
            } else {
                // It's 'safe' to put them in the broken source vec because all we do is
                // clear that vector on a timer; if the source is in error state but
                // bound elsewhere in the system it won't be removed.
                local_locker lock(&dst_lock);
                broken_source_vec.push_back(ds);
                in_cb(false, reason, ds);
                schedule_cleanup();
            }
        });
}

void datasource_tracker::merge_source(shared_datasource in_source) {
    local_locker lock(&dst_lock);

    // Get the UUID and compare it to our map; re-use a UUID if we knew
    // it before, otherwise add a new one
    uuid u = in_source->get_source_uuid();

    auto i = uuid_source_num_map.find(u);
    if (i != uuid_source_num_map.end()) {
        in_source->set_source_number(i->second);
    } else {
        in_source->set_source_number(++next_source_num);
        uuid_source_num_map[u] = in_source->get_source_number();
        eventbus->publish(std::make_shared<event_new_datasource>(in_source));
    }

    // Figure out channel hopping
    calculate_source_hopping(in_source);

    if (database_log_enabled) {
        std::shared_ptr<kis_database_logfile> dbf =
            Globalreg::FetchGlobalAs<kis_database_logfile>("DATABASELOG");

        if (dbf != NULL) {
            dbf->log_datasource(in_source);
        }
    }

    datasource_vec->push_back(in_source);
}

void datasource_tracker::list_interfaces(const std::function<void (std::vector<shared_interface>)>& in_cb) {
    local_locker lock(&dst_lock);

    // Create a DSTProber to handle the probing
    auto dst_list = std::make_shared<datasource_tracker_source_list>(proto_vec);
    unsigned int listid = ++next_list_id;

    // Record it
    listing_map[listid] = dst_list;

    // Set up a cancellation timer
    int cancel_timer = 
        timetracker->register_timer(SERVER_TIMESLICES_SEC * 10, NULL, 0, 
            [dst_list] (int) -> int {
                dst_list->cancel();
                return 0;
            });


    // Initiate the probe
    dst_list->list_sources([this, cancel_timer, listid, in_cb](std::vector<shared_interface> interfaces) {
        // We're complete; cancel the timer if it's still around.
        timetracker->remove_timer(cancel_timer);

        local_demand_locker lock(&dst_lock);
        lock.lock();

        // Figure out what interfaces are in use by active sources and amend their
        // UUID records in the listing
        for (auto il = interfaces.begin(); il != interfaces.end(); ++il) {
            for (auto s : *datasource_vec) {
                shared_datasource sds = std::static_pointer_cast<kis_datasource>(s);
                if (!sds->get_source_remote() &&
                        ((*il)->get_interface() == sds->get_source_interface() ||
                         (*il)->get_interface() == sds->get_source_cap_interface())) {
                    (*il)->set_in_use_uuid(sds->get_source_uuid());
                    break;
                }
            }
        }

        lock.unlock();
        in_cb(interfaces);
        lock.lock();

        auto i = listing_map.find(listid);

        if (i != listing_map.end()) {
            listing_complete_vec.push_back(i->second);
            listing_map.erase(i);
            schedule_cleanup();
        } else {
            // fprintf(stderr, "debug - DST couldn't find response %u\n", probeid);
        }
    });
}

void datasource_tracker::schedule_cleanup() {
    local_locker lock(&dst_lock);

    if (completion_cleanup_id >= 0)
        return;

    completion_cleanup_id = 
        timetracker->register_timer(1, NULL, 0, [this] (int) -> int {
            local_demand_locker lock(&dst_lock);
           
            lock.lock();
            auto d_pcv = probing_complete_vec;
            auto d_lcv = listing_complete_vec;
            auto d_bsv = broken_source_vec;

            completion_cleanup_id = -1;

            probing_complete_vec.clear();
            listing_complete_vec.clear();
            broken_source_vec.clear();
            lock.unlock();

            // Actually purge them outside of lockdown
            d_pcv.clear();
            d_lcv.clear();
            d_bsv.clear();

            return 0;
        });
    //fprintf(stderr, "debug - dst scheduling cleanup as %d\n", completion_cleanup_id);
}

void datasource_tracker::new_remote_tcp_connection(int in_fd) {
    // Make a new connection handler with its own mutex
    auto conn_handler = 
        std::make_shared<buffer_handler<ringbuf_v2>>((tcp_buffer_sz * 1024), (tcp_buffer_sz * 1024));

    // Bind it to the tcp socket
    auto socketcli = 
        std::make_shared<socket_client>(in_fd, conn_handler);

    // Bind a new incoming remote which will pivot to the proper data source type
    auto incoming_remote = new dst_incoming_remote(conn_handler, 
                [this] (dst_incoming_remote *i, std::string in_type, std::string in_def, 
                    uuid in_uuid, std::shared_ptr<buffer_handler_generic> in_handler) {
            in_handler->remove_read_buffer_interface();
            open_remote_datasource(i, in_type, in_def, in_uuid, in_handler);
        });

    conn_handler->set_read_buffer_interface(incoming_remote);

    // Register the connection as pollable
    auto pollabletracker = 
        Globalreg::fetch_mandatory_global_as<pollable_tracker>();
    pollabletracker->register_pollable(socketcli);
}

void datasource_tracker::open_remote_datasource(dst_incoming_remote *incoming,
        const std::string& in_type, const std::string& in_definition, const uuid& in_uuid, 
        std::shared_ptr<buffer_handler_generic> in_handler) {
    shared_datasource merge_target_device;
     
    local_locker lock(&dst_lock);

    // Look for an existing datasource with the same UUID
    for (auto p : *datasource_vec) {
        shared_datasource d = std::static_pointer_cast<kis_datasource>(p);

        if (!d->get_source_builder()->get_remote_capable())
            continue;

        if (d->get_source_uuid() == in_uuid) {
            merge_target_device = d;
            break;
        }
    }

    if (merge_target_device != NULL) {
        if (merge_target_device->get_source_running()) {
            _MSG_ERROR("Incoming remote connection for source '{}' matches existing source '{}', "
                    "which is still running.  The running instance will be closed; make sure "
                    "that multiple remote captures are not running for the same source.",
                    in_uuid.uuid_to_string(), merge_target_device->get_source_name());
            merge_target_device->close_source();
        } else {
            _MSG_INFO("Matching new remote source '{}' with known source with UUID '{}'",
                    in_definition, in_uuid.uuid_to_string());
        }
                    
        // Explicitly unlock our mutex before running a thread
        lock.unlock();

        auto dup_definition(in_definition);

        // Generate a detached thread for joining the ring buffer; it acts as a blocking
        // wait for the buffer to be filled
        incoming->handshake_rb(std::thread([this, merge_target_device, in_handler, dup_definition]  {
                    merge_target_device->connect_remote(in_handler, dup_definition, NULL);
                    calculate_source_hopping(merge_target_device);
                }));

        return;
    }

    // Otherwise look for a prototype that can handle it
    for (auto p : *proto_vec) {
        shared_datasource_builder b = std::static_pointer_cast<kis_datasource_builder>(p);

        if (!b->get_remote_capable())
            continue;

        if (b->get_source_type() == in_type) {
            // Explicitly unlock the mutex before we fire the connection handler
            lock.unlock();

            // Make a data source from the builder
            shared_datasource ds = b->build_datasource(b, in_handler->get_mutex());
            ds->connect_remote(in_handler, in_definition,
                [this, ds](unsigned int, bool success, std::string msg) {
                    if (success)
                        merge_source(ds); 
                    else
                        broken_source_vec.push_back(ds);
                });

            return;
        }
    }

    _MSG_ERROR("Kismet could not find a datasource driver for incoming remote source "
            "'{}' defined as '{}'; make sure that Kismet was compiled with all the "
            "data source drivers and that any necessary plugins have been loaded.",
            in_type, in_definition);
    in_handler->protocol_error();

}

// Basic DST worker for figuring out how many sources of the same type
// exist, and are hopping
class dst_chansplit_worker : public datasource_tracker_worker {
public:
    dst_chansplit_worker(datasource_tracker *in_dst,
            std::shared_ptr<datasource_tracker_defaults> in_defaults, 
            shared_datasource in_ds) {
        dst = in_dst;
        defaults = in_defaults;
        target_sources.push_back(in_ds);
        initial_ds = in_ds;
        match_type = in_ds->get_source_builder()->get_source_type();
    }

    virtual void handle_datasource(shared_datasource in_src) {
        // Don't dupe ourselves
        if (in_src == initial_ds)
            return;

        // Don't look at ones we don't care about
        if (in_src->get_source_builder()->get_source_type() != match_type)
            return;

        // Don't look at ones that aren't open yet
        if (!in_src->get_source_running()) 
            return;

        bool match_list = true;

        auto initial_channels = initial_ds->get_source_channels_vec();
        auto compare_channels = in_src->get_source_channels_vec();

        if (initial_channels->size() != compare_channels->size())
            return;

        for (auto first_chan : *initial_channels) {
            bool matched_cur_chan = false;

            for (auto comp_chan : *compare_channels) {
                if (get_tracker_value<std::string>(first_chan) == 
                        get_tracker_value<std::string>(comp_chan)) {
                    matched_cur_chan = true;
                    break;
                }
            }

            if (!matched_cur_chan) {
                match_list = false;
                break;
            }
        }

        if (match_list)
            target_sources.push_back(in_src);
    }

    virtual void finalize() {
        if (target_sources.size() <= 1) {
            initial_ds->set_channel_hop(defaults->get_hop_rate(),
                    initial_ds->get_source_hop_vec(),
                    defaults->get_random_channel_order(),
                    0, 0, NULL);
            return;
        }

        _MSG_INFO("Splitting channels for interfaces using '{}' among {} interfaces",
                match_type, target_sources.size());

        int nintf = 0;
        for (auto ds : target_sources) {
            int offt_count = target_sources.size();

            auto ds_hopchans = (ds)->get_source_hop_vec();

            int ds_offt = (ds_hopchans->size() / offt_count) * nintf;

            double rate = defaults->get_hop_rate();

            if (ds->get_definition_opt("channel_hoprate") != "") {
                try {
                    rate = dst->string_to_rate(ds->get_definition_opt("channel_hoprate"), -1);
                } catch (const std::exception& e) {
                    _MSG_ERROR("Source '{}' could not parse channel_hoprate= option: {}, using default "
                            "channel rate.", ds->get_source_name(), e.what());
                    rate = -1;
                }
            }

            if (rate < 0) {
                rate = defaults->get_hop_rate();
            }

            ds->set_channel_hop(rate, ds_hopchans, defaults->get_random_channel_order(),
                    ds_offt, 0, NULL);

            nintf++;
        }

    }

protected:
    std::string match_type;

    datasource_tracker *dst;

    shared_datasource initial_ds;
    std::vector<shared_datasource> target_sources;

    std::shared_ptr<datasource_tracker_defaults> defaults;

};

void datasource_tracker::calculate_source_hopping(shared_datasource in_ds) {
    if (!in_ds->get_definition_opt_bool("channel_hop", true)) {
        // Source doesn't hop regardless of defaults
        return;
    }

    // Turn on channel hopping if we do that
    if (config_defaults->get_hop() && in_ds->get_source_builder()->get_tune_capable() &&
            in_ds->get_source_builder()->get_hop_capable()) {
        // Do we split sources?
        if (config_defaults->get_split_same_sources()) {
            dst_chansplit_worker worker(this, config_defaults, in_ds);
            iterate_datasources(&worker);
        } else {
            in_ds->set_channel_hop(config_defaults->get_hop_rate(),
                    in_ds->get_source_hop_vec(),
                    config_defaults->get_random_channel_order(),
                    0, 0, NULL);
        }
    }
}

void datasource_tracker::queue_dead_remote(dst_incoming_remote *in_dead) {
    local_locker lock(&dst_lock);

    for (auto x : dst_remote_complete_vec) {
        if (x == in_dead)
            return;
    }

    if (remote_complete_timer <= 0) {
        remote_complete_timer =
            timetracker->register_timer(1, NULL, 0, 
                [this] (int) -> int {
                    local_locker lock(&dst_lock);

                    for (auto x : dst_remote_complete_vec) {
                        delete(x);
                    }

                    dst_remote_complete_vec.clear();

                    remote_complete_timer = 0;
                    return 0;
                });
    }

}


bool datasource_tracker::httpd_verify_path(const char *path, const char *method) {
    std::string stripped = httpd_strip_suffix(path);

    if (strcmp(method, "POST") == 0) {
        if (stripped == "/datasource/add_source")
            return true;

        std::vector<std::string> tokenurl = str_tokenize(path, "/");

        if (tokenurl.size() < 5)
            return false;

        // /datasource/by-uuid/aaa-bbb-cc-dd/source.json 
        if (tokenurl[1] == "datasource") {
            if (tokenurl[2] == "by-uuid") {
                uuid u(tokenurl[3]);

                if (u.error)
                    return false;

                local_shared_locker lock(&dst_lock);

                if (uuid_source_num_map.find(u) == uuid_source_num_map.end())
                    return false;

                if (httpd_strip_suffix(tokenurl[4]) == "set_channel") {
                    return true;
                }

                if (httpd_strip_suffix(tokenurl[4]) == "set_hop") {
                    return true;
                }

                return false;
            }
        }

        return false;
    }

    if (strcmp(method, "GET") == 0) {
        
        if (!httpd_can_serialize(path))
            return false;

        std::vector<std::string> tokenurl = str_tokenize(path, "/");

        if (tokenurl.size() < 5)
            return false;

        // /datasource/by-uuid/aaa-bbb-cc-dd/source.json 
        if (tokenurl[1] == "datasource") {
            if (tokenurl[2] == "by-uuid") {
                uuid u(tokenurl[3]);

                if (u.error)
                    return false;

                {
                    local_shared_locker l(&dst_lock);
                    if (uuid_source_num_map.find(u) == uuid_source_num_map.end())
                        return false;
                }

                if (httpd_strip_suffix(tokenurl[4]) == "source")
                    return true;

                if (httpd_strip_suffix(tokenurl[4]) == "close_source")
                    return true;

                if (httpd_strip_suffix(tokenurl[4]) == "open_source")
                    return true;

                if (httpd_strip_suffix(tokenurl[4]) == "disable_source")
                    return true;

                if (httpd_strip_suffix(tokenurl[4]) == "enable_source")
                    return true;

                if (httpd_strip_suffix(tokenurl[4]) == "pause_source")
                    return true;
                
                if (httpd_strip_suffix(tokenurl[4]) == "resume_source")
                    return true;

                return false;
            }
        }

    }

    return false;
}

void datasource_tracker::httpd_create_stream_response(kis_net_httpd *httpd,
        kis_net_httpd_connection *connection,
       const char *path, const char *method, const char *upload_data,
       size_t *upload_data_size, std::stringstream &stream) {

    if (strcmp(method, "GET") != 0) {
        return;
    }

    std::string stripped = httpd_strip_suffix(path);

    if (!httpd_can_serialize(path))
        return;


    std::vector<std::string> tokenurl = str_tokenize(path, "/");

    if (tokenurl.size() < 5) {
        return;
    }

    // /datasource/by-uuid/aaa-bbb-cc-dd/source.json 
    if (tokenurl[1] == "datasource") {
        if (tokenurl[2] == "by-uuid") {
            uuid u(tokenurl[3]);

            if (u.error) {
                return;
            }

            shared_datasource ds;

            {
                local_shared_locker lock(&dst_lock);
                for (auto i : *datasource_vec) {
                    shared_datasource dsi = std::static_pointer_cast<kis_datasource>(i);

                    if (dsi->get_source_uuid() == u) {
                        ds = dsi;
                        break;
                    }
                }
            }

            if (ds == NULL) {
                stream << "Error";
                return;
            }

            if (httpd_strip_suffix(tokenurl[4]) == "source") {
                httpd_serialize(path, stream, ds, nullptr, connection);
                return;
            }

            if (httpd_strip_suffix(tokenurl[4]) == "close_source" ||
                    httpd_strip_suffix(tokenurl[4]) == "disable_source") {
                if (ds->get_source_running()) {
                    _MSG("Closing source '" + ds->get_source_name() + "' from REST "
                            "interface request.", MSGFLAG_INFO);
                    ds->disable_source();
                    stream << "Closing source " << ds->get_source_uuid().uuid_to_string();
                    return;
                } else {
                    stream << "Source already closed, disabling source " <<
                        ds->get_source_uuid().uuid_to_string();
                    ds->disable_source();
                    return;
                }
            }

            if (httpd_strip_suffix(tokenurl[4]) == "open_source") {
                if (!ds->get_source_running()) {
                    _MSG("Re-opening source '" + ds->get_source_name() + "' from REST "
                            "interface request.", MSGFLAG_INFO);
                    ds->open_interface(ds->get_source_definition(), 0, NULL);
                    stream << "Re-opening source";
                    return;
                } else {
                    stream << "Source already open";
                    connection->httpcode = 500;
                    return;
                }
            }

            if (httpd_strip_suffix(tokenurl[4]) == "pause_source") {
                if (!ds->get_source_paused()) {
                    _MSG("Pausing source '" + ds->get_source_name() + "' from REST "
                            "interface request.", MSGFLAG_INFO);
                    ds->set_source_paused(true);
                    stream << "Pausing source";
                    return;
                } else {
                    stream << "Source already paused";
                    connection->httpcode = 500;
                    return;
                }
            }

            if (httpd_strip_suffix(tokenurl[4]) == "resume_source") {
                if (ds->get_source_paused()) {
                    _MSG("Resuming source '" + ds->get_source_name() + "' from REST "
                            "interface request.", MSGFLAG_INFO);
                    ds->set_source_paused(false);
                    stream << "Resuming source";
                    return;
                } else {
                    stream << "Source already running";
                    connection->httpcode = 500;
                    return;
                }
            }
            
            return;
        }
    }

}

int datasource_tracker::httpd_post_complete(kis_net_httpd_connection *concls) {
    if (!httpd_can_serialize(concls->url)) {
        concls->response_stream << "Invalid request, cannot serialize URL";
        concls->httpcode = 400;
        return MHD_YES;
    }

    // All the posts require login
    if (!httpd->has_valid_session(concls, true)) {
        return MHD_YES;
    }

    std::string stripped = httpd_strip_suffix(concls->url);

    shared_structured structdata;

    try {
        if (concls->variable_cache.find("json") != concls->variable_cache.end()) {
            structdata.reset(new structured_json(concls->variable_cache["json"]->str()));
        } else {
            throw std::runtime_error("unable to find POST data");
        }

        if (stripped == "/datasource/add_source") {
            // Locker for waiting for the open callback
            std::shared_ptr<conditional_locker<shared_datasource> > cl(new conditional_locker<shared_datasource>());

            shared_datasource r;
            std::string error_reason;

            if (!structdata->has_key("definition")) {
                throw std::runtime_error("POST data missing source definition");
            }

            cl->lock();

            bool cmd_complete_success = false;

            // Initiate the open
            open_datasource(structdata->key_as_string("definition"),
                    [&error_reason, cl, &cmd_complete_success](bool success, std::string reason, 
                        shared_datasource ds) {

                        cmd_complete_success = success;

                        // Unlock the locker so we unblock below
                        if (success) {
                            cl->unlock(ds);
                        } else {
                            error_reason = reason;
                            cl->unlock(NULL);
                        }
                    });

            // Block until the open cmd unlocks us
            r = cl->block_until();

            if (cmd_complete_success) {
                httpd_serialize(concls->url, concls->response_stream, r, nullptr, concls);
                concls->httpcode = 200;
            } else {
                concls->response_stream << error_reason;
                concls->httpcode = 500;
            }

            return MHD_YES;
        } 

        // No single url we liked, split and look at the path
        std::vector<std::string> tokenurl = str_tokenize(concls->url, "/");

        if (tokenurl.size() < 5) {
            throw std::runtime_error("Unknown URI");
        }


        // /datasource/by-uuid/aaa-bbb-cc-dd/command.cmd / .jcmd
        if (tokenurl[1] == "datasource" && tokenurl[2] == "by-uuid") {
            uuid u(tokenurl[3]);

            if (u.error) 
                throw std::runtime_error("Invalid UUID");

            shared_datasource ds;

            {
                local_shared_locker lock(&dst_lock);

                if (uuid_source_num_map.find(u) == uuid_source_num_map.end())
                    throw std::runtime_error("Could not find a source with that UUID");

                for (auto i : *datasource_vec) {
                    shared_datasource dsi = std::static_pointer_cast<kis_datasource>(i);

                    if (dsi->get_source_uuid() == u) {
                        ds = dsi;
                        break;
                    }
                }

                if (ds == NULL) {
                    throw std::runtime_error("Could not find a source with that UUID");
                }
            }

            if (httpd_strip_suffix(tokenurl[4]) == "set_channel") {
                if (structdata->has_key("channel")) {
                    std::shared_ptr<conditional_locker<std::string> > cl(new conditional_locker<std::string>());
                    std::string ch = structdata->key_as_string("channel", "");

                    if (ch.length() == 0) {
                        throw std::runtime_error("Invalid channel, could not parse as string");
                    }

                    _MSG_INFO("Setting data source '{}' channel '{}'",
                            ds->get_source_name(), ch);

                    bool cmd_complete_success = false;

                    cl->lock();

                    // Initiate the channel set
                    ds->set_channel(ch, 0, 
                            [cl, &cmd_complete_success](unsigned int, bool success, 
                                std::string reason) {

                                cmd_complete_success = success;

                                cl->unlock(reason);
                            });

                    // Block until the open cmd unlocks us
                    std::string reason = cl->block_until();

                    if (cmd_complete_success) {
                        concls->response_stream << "Success";
                        concls->httpcode = 200;
                    } else {
                        concls->response_stream << reason;
                        concls->httpcode = 500;
                    }
                                
                    return MHD_YES;

                } else {
                    // We need at least a channels or a rate to kick into
                    // hopping mode
                    if (!structdata->has_key("channels") &&
                            !structdata->has_key("rate")) {
                        throw std::runtime_error("invalid hop command, expected channel, channels, or rate");
                    }

                    // Get the channels as a vector, default to the source 
                    // default if the CGI doesn't define them
                    shared_structured chstruct;
                    std::vector<std::string> converted_channels;

                    if (structdata->has_key("channels")) {
                        chstruct = structdata->get_structured_by_key("channels");
                        converted_channels = chstruct->as_string_vector();
                    } else {
                        for (auto c : *(ds->get_source_hop_vec()))
                            converted_channels.push_back(get_tracker_value<std::string>(c));
                    }

                    std::shared_ptr<conditional_locker<std::string> > cl(new conditional_locker<std::string>());

                    // Get the hop rate and the shuffle; default to the source
                    // state if we don't have them provided
                    double rate = 
                        structdata->key_as_number("rate", ds->get_source_hop_rate());

                    unsigned int shuffle = 
                        structdata->key_as_number("shuffle",
                                ds->get_source_hop_shuffle());

                    _MSG_INFO("Source '{}' setting new hop rate and channel pattern.",
                            ds->get_source_name());

                    bool cmd_complete_success = false;

                    cl->lock();

                    // Initiate the channel set
                    ds->set_channel_hop(rate, converted_channels, shuffle, 
                            ds->get_source_hop_offset(),
                            0, [cl, &cmd_complete_success](unsigned int, bool success, 
                                std::string reason) {

                                cmd_complete_success = success;

                                cl->unlock(reason);
                            });

                    // Block until the open cmd unlocks us
                    std::string reason = cl->block_until();

                    if (cmd_complete_success) {
                        concls->response_stream << "Success";
                        concls->httpcode = 200;
                    } else {
                        concls->response_stream << reason;
                        concls->httpcode = 500;
                    }

                    return MHD_YES;
                }
            } else if (httpd_strip_suffix(tokenurl[4]) == "set_hop") {
                _MSG("Setting source '" + ds->get_source_name() + "' channel hopping", 
                        MSGFLAG_INFO);

                bool cmd_complete_success = false;
                std::shared_ptr<conditional_locker<std::string> > cl(new conditional_locker<std::string>());

                cl->lock();

                // Set it to channel hop using all the current hop attributes
                ds->set_channel_hop(ds->get_source_hop_rate(),
                        ds->get_source_hop_vec(),
                        ds->get_source_hop_shuffle(),
                        ds->get_source_hop_offset(), 0,
                        [cl, &cmd_complete_success](unsigned int, bool success, 
                            std::string reason) {

                            cmd_complete_success = success;

                            cl->unlock(reason);
                        });

                // Block until the open cmd unlocks us
                std::string reason = cl->block_until();

                if (cmd_complete_success) {
                    concls->response_stream << "Success";
                    concls->httpcode = 200;
                } else {
                    concls->response_stream << reason;
                    concls->httpcode = 500;
                }

                return MHD_YES;
            }
        }

        // Otherwise no URL path we liked
        concls->response_stream << "Invalid request, invalid URL";
        concls->httpcode = 400;
        return MHD_YES;
    
    } catch (const std::exception& e) {
        concls->response_stream << "Invalid request " << e.what();
        concls->httpcode = 400;
        return MHD_YES;
    }

    return MHD_YES;
}

double datasource_tracker::string_to_rate(std::string in_str, double in_default) {
    double v, dv;

    std::vector<std::string> toks = str_tokenize(in_str, "/");

    if (toks.size() != 2)
        throw std::runtime_error("Expected [value]/sec or [value]/min or [value]/dwell");

    v = string_to_n<double>(toks[0]);

    if (toks[1] == "sec") {
        return v;
    } else if (toks[1] == "dwell") {
        // Channel dwell is # of *seconds per hop* for very long hop intervals; so to get
        // hops per minute it's dwell seconds.  We convert to a double # of hops per minute,
        // then apply the formula below to turn that into the double value; simplified to:
        dv = 1.0f / v;

        return dv;
    } else if (toks[1] == "min") {
        // Channel hop is # of hops a second, timed in usec, so to get hops per
        // minute we get a minutes worth of usecs (60m), divide by the number
        // of hops per minute, then divide a second by that.
        // dv = (double) 1000000 / (double) ((double) (1000000 * 60) / (double) v);
        // simplified to:
        dv = v / 60.0f;

        return dv;
    } else {
        throw std::runtime_error("Expected [value]/sec or [value]/min");
    }
}

bool datasource_tracker_httpd_pcap::httpd_verify_path(const char *path, const char *method) {
    if (strcmp(method, "GET") == 0) {

        // Total pcap of all data; we put it in 2 locations
        if (strcmp(path, "/pcap/all_packets.pcapng") == 0) 
            return true;

        if (strcmp(path, "/datasource/pcap/all_sources.pcapng") == 0)
            return true;

        // Alternately, per-source capture:
        // /datasource/pcap/by-uuid/aa-bb-cc-dd/aa-bb-cc-dd.pcapng

        std::vector<std::string> tokenurl = str_tokenize(path, "/");

        if (tokenurl.size() < 6) {
            return false;
        }
        if (tokenurl[1] == "datasource") {
            if (tokenurl[2] == "pcap") {
                if (tokenurl[3] == "by-uuid") {
                    uuid u(tokenurl[4]);

                    if (u.error) {
                        return false;
                    }

                    if (datasourcetracker == NULL) {
                        datasourcetracker =
                            Globalreg::fetch_mandatory_global_as<datasource_tracker>("DATASOURCETRACKER");
                    }

                    if (packetchain == NULL) {
                        std::shared_ptr<packet_chain> packetchain = 
                            Globalreg::fetch_mandatory_global_as<packet_chain>("PACKETCHAIN");
                        pack_comp_datasrc = packetchain->register_packet_component("KISDATASRC");
                    }

                    shared_datasource ds = datasourcetracker->find_datasource(u);
                    
                    if (ds != NULL)
                        return true;;
                }
            }
        }
    }

    return false;
}

int datasource_tracker_httpd_pcap::httpd_create_stream_response(kis_net_httpd *httpd,
        kis_net_httpd_connection *connection,
        const char *url, const char *method, const char *upload_data,
        size_t *upload_data_size) {

    if (strcmp(method, "GET") != 0) {
        return MHD_YES;
    }

    auto streamtracker = Globalreg::fetch_mandatory_global_as<stream_tracker>("STREAMTRACKER");

    if (strcmp(url, "/pcap/all_packets.pcapng") == 0 ||
            strcmp(url, "/datasource/pcap/all_sources.pcapng") == 0) {
        // At this point we're logged in and have an aux pointer for the
        // ringbuf aux; We can create our pcap ringbuf stream and attach it.
        // We need to close down the pcapringbuf during teardown.
       
        kis_net_httpd_buffer_stream_aux *saux = 
            (kis_net_httpd_buffer_stream_aux *) connection->custom_extension;
       
        auto *psrb = new pcap_stream_packetchain(Globalreg::globalreg,
                saux->get_rbhandler(), NULL, NULL);

        streamtracker->register_streamer(psrb, "all_sources.pcapng",
                "pcapng", "httpd", "pcapng of all packets on all sources");

        auto id = psrb->get_stream_id();

        saux->set_aux(psrb, 
            [id, streamtracker](kis_net_httpd_buffer_stream_aux *aux) {
                streamtracker->remove_streamer(id);
                if (aux->aux != NULL) {
                    delete (pcap_stream_packetchain *) (aux->aux);
                }
            });

        return MHD_NO;
    }

    // Find per-uuid and make a filtering pcapng
    std::vector<std::string> tokenurl = str_tokenize(url, "/");

    if (tokenurl.size() < 6) {
        return MHD_YES;
    }

    if (tokenurl[1] == "datasource") {
        if (tokenurl[2] == "pcap") {
            if (tokenurl[3] == "by-uuid") {
                uuid u(tokenurl[4]);

                if (u.error) {
                    return MHD_YES;
                }

                datasourcetracker =
                    Globalreg::fetch_mandatory_global_as<datasource_tracker>("DATASOURCETRACKER");

                std::shared_ptr<packet_chain> packetchain = 
                    Globalreg::fetch_mandatory_global_as<packet_chain>("PACKETCHAIN");
                pack_comp_datasrc = packetchain->register_packet_component("KISDATASRC");

                shared_datasource ds = datasourcetracker->find_datasource(u);

                if (ds == NULL)
                    return MHD_YES;

                if (!httpd->has_valid_session(connection)) {
                    connection->httpcode = 503;
                    return MHD_YES;
                }

                // Get the number of this source for fast compare
                unsigned int dsnum = ds->get_source_number();

                // Create the pcap stream and attach it to our ringbuf
                kis_net_httpd_buffer_stream_aux *saux = 
                    (kis_net_httpd_buffer_stream_aux *) connection->custom_extension;

                // Fetch the datasource component and compare *source numbers*, not
                // actual UUIDs - a UUID compare is expensive, a numeric compare is not!
                auto *psrb = new pcap_stream_packetchain(Globalreg::globalreg,
                        saux->get_rbhandler(), 
                        [this, dsnum] (kis_packet *packet) -> bool {
                            packetchain_comp_datasource *datasrcinfo = 
                                (packetchain_comp_datasource *) 
                                packet->fetch(pack_comp_datasrc);
                        
                            if (datasrcinfo == NULL)
                                return false;

                            if (datasrcinfo->ref_source->get_source_number() == dsnum)
                                return true;

                        return false; 
                        }, NULL);


                saux->set_aux(psrb, 
                    [psrb, streamtracker](kis_net_httpd_buffer_stream_aux *aux) {
                        streamtracker->remove_streamer(psrb->get_stream_id());
                        if (aux->aux != NULL) {
                            delete (kis_net_httpd_buffer_stream_aux *) (aux->aux);
                        }
                    });

                streamtracker->register_streamer(psrb, 
                        ds->get_source_name() + ".pcapng",
                        "pcapng", "httpd", 
                        "pcapng of " + ds->get_source_name() + " (" + 
                        ds->get_source_cap_interface());

                return MHD_NO;

            }
        }
    }

    return MHD_YES;
}

dst_incoming_remote::dst_incoming_remote(std::shared_ptr<buffer_handler_generic> in_rbufhandler,
        std::function<void (dst_incoming_remote *, std::string, std::string, 
            uuid, std::shared_ptr<buffer_handler_generic>)> in_cb) :
    kis_external_interface() {
    
    cb = in_cb;

    connect_buffer(in_rbufhandler);

    timerid =
        timetracker->register_timer(SERVER_TIMESLICES_SEC * 10, NULL, 0, 
            [this] (int) -> int {
                _MSG("Remote source connected but didn't send a NEWSOURCE control, "
                        "closing connection.", MSGFLAG_ERROR);

                kill();

                return 0;
            });
}

dst_incoming_remote::~dst_incoming_remote() {
    // Kill the error timer
    timetracker->remove_timer(timerid);

    // Remove ourselves as a handler
    if (ringbuf_handler != NULL)
        ringbuf_handler->remove_read_buffer_interface();

    // Wait for the thread to finish
    handshake_thread.join();
}

bool dst_incoming_remote::dispatch_rx_packet(std::shared_ptr<KismetExternal::Command> c) { if (kis_external_interface::dispatch_rx_packet(c))
        return true;

    // Simple dispatch override, all we do is look for the new source
    if (c->command() == "KDSNEWSOURCE") {
        handle_packet_newsource(c->seqno(), c->content());
        return true;
    }

    return false;
}


void dst_incoming_remote::kill() {
    // Kill the error timer
    timetracker->remove_timer(timerid);

    close_external();

    std::shared_ptr<datasource_tracker> datasourcetracker =
        Globalreg::FetchGlobalAs<datasource_tracker>("DATASOURCETRACKER");

    if (datasourcetracker != NULL) 
        datasourcetracker->queue_dead_remote(this);
}

void dst_incoming_remote::handle_packet_newsource(uint32_t in_seqno, std::string in_content) {
    local_locker lock(ext_mutex);

    KismetDatasource::NewSource c;

    if (!c.ParseFromString(in_content)) {
        _MSG("Could not process incoming remote datsource announcement", MSGFLAG_ERROR);
        kill();

        return;
    }

    if (cb != NULL)
        cb(this, c.sourcetype(), c.definition(), c.uuid(), ringbuf_handler);

    // Zero out the rbuf handler so that it doesn't get closed
    ringbuf_handler.reset();

    kill();
}

void dst_incoming_remote::buffer_error(std::string in_error) {
    _MSG("Incoming remote source failed: " + in_error, MSGFLAG_ERROR);
    kill();
    return;
}

