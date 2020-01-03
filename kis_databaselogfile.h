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

/* The new grand, unified Kismet logging system.
 *
 * The new logfile system combines all the previous Kismet logs into a single entity
 * which can later be extrapolated into the original data types (or all new data types).
 *
 * The new log is based on sqlite3 and is, itself, a database.  It borrows from the nosql
 * methodology by, in general, defining the minimum number of normalized fields and 
 * storing data in traditional JSON format whenever possible.
 *
 * The new log format synergizes with the REST UI to provide dynamic access to 
 * historical data.
 *
 * Docs in docs/dev/log_kismet.md
 *
 */

#ifndef __KISLOGFILE_H__
#define __KISLOGFILE_H__

#include "config.h"

#include <atomic>
#include <memory>
#include <string>

#include "globalregistry.h"
#include "kis_mutex.h"
#include "kis_database.h"
#include "devicetracker.h"
#include "alertracker.h"
#include "logtracker.h"
#include "packetchain.h"
#include "pcapng_stream_ringbuf.h"
#include "sqlite3_cpp11.h"
#include "class_filter.h"
#include "packet_filter.h"
#include "messagebus.h"

// This is a bit of a unique case - because so many things plug into this, it has
// to exist as a global record; we build it like we do any other global record;
// then the builder hooks it, sets the internal builder record, and passed it to
// the logtracker
class kis_database_logfile : public kis_logfile, public kis_database, public lifetime_global,
    public kis_net_httpd_ringbuf_stream_handler, public message_client, public deferred_startup {
public:
    static std::string global_name() { return "DATABASELOG"; }

    static std::shared_ptr<kis_database_logfile> 
        create_kisdatabaselog() {
            std::shared_ptr<kis_database_logfile> mon(new kis_database_logfile());
            Globalreg::globalreg->register_deferred_global(mon);
            Globalreg::globalreg->register_lifetime_global(mon);
            Globalreg::globalreg->insert_global(global_name(), mon);
            return mon;
    }

    kis_database_logfile();
    virtual ~kis_database_logfile();

    virtual void trigger_deferred_startup() override;
    virtual void trigger_deferred_shutdown() override;

    void set_database_builder(shared_log_builder in_builder) {
        builder = in_builder;

        if (builder != nullptr)
            insert(builder);
    }

    virtual bool open_log(std::string in_path) override;
    virtual void close_log() override;

    virtual int database_upgrade_db() override;

    // Log a vector of multiple devices, replacing any old device records
    virtual int log_device(std::shared_ptr<kis_tracked_device_base> in_device);

    // Device logs are non-streaming; we need to know the last time we generated
    // device logs so that we can update just the logs we need.
    virtual time_t get_last_device_log_ts() { return last_device_log; }

    // Log a packet
    virtual int log_packet(kis_packet *in_packet);

    // Log data that isn't a packet; this is a slightly more clunky API because we 
    // can't derive the data from the simple packet interface.  GPS may be null,
    // and other attributes may be empty, if that data is not available
    virtual int log_data(kis_gps_packinfo *gps, struct timeval tv, 
            std::string phystring, mac_addr devmac, uuid datasource_uuid, 
            std::string type, std::string json);

    // Log datasources
    virtual int log_datasources(shared_tracker_element in_datasource_vec);
    // Log a single datasource
    virtual int log_datasource(shared_tracker_element in_datasource);

    // Log an alert; takes a standard tracked_alert element
    virtual int log_alert(std::shared_ptr<tracked_alert> in_alert);

    // Log snapshotted data; Slightly clunkier API since it has to allow for
    // entirely generic data
    virtual int log_snapshot(kis_gps_packinfo *gps, struct timeval tv,
            std::string snaptype, std::string json);

    static void usage(const char *argv0);

    // HTTP handlers
    virtual bool httpd_verify_path(const char *path, const char *method) override;

    virtual int httpd_create_stream_response(kis_net_httpd *httpd,
            kis_net_httpd_connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size) override;

    virtual int httpd_post_complete(kis_net_httpd_connection *concls) override;

    // Messagebus API
    virtual void process_message(std::string in_msg, int in_flags) override;

    // Direct access to the filters for setting programmatically
    std::shared_ptr<packet_filter_mac_addr> get_packet_filter() { 
        return packet_mac_filter;
    }

    std::shared_ptr<class_filter_mac_addr> get_device_filter() {
        return device_mac_filter;
    }

    // event_bus event we inject when the log is opened
    class event_dblog_opened : public eventbus_event {
    public:
        static std::string Event() { return "KISMETDB_LOG_OPEN"; }
        event_dblog_opened() :
            eventbus_event(Event()) { }
        virtual ~event_dblog_opened() {}
    };

protected:
    // Is the database even enabled?
    std::atomic<bool> db_enabled;

    std::shared_ptr<device_tracker> devicetracker;
    std::shared_ptr<gps_tracker> gpstracker;

    int pack_comp_linkframe, pack_comp_gps, pack_comp_no_gps, pack_comp_radiodata,
        pack_comp_device, pack_comp_datasource, pack_comp_common, pack_comp_metablob;

    std::atomic<time_t> last_device_log;

    std::atomic<bool> in_transaction_sync;

    // Nasty define hack for checking if we're blocked on a really slow
    // device by comparing the transaction sync
#define db_lock_with_sync_check(locker, errcode) \
    try { \
        locker.lock(); \
    } catch (const std::runtime_error& e) { \
        if (in_transaction_sync) { \
            fmt::print(stderr, "FATAL: kismetdb log couldn't finish a database transaction within the " \
                    "timeout window for threads ({} seconds).  Usually this happens when " \
                    "the disk you are logging to can not perform adequately, such as a " \
                    "micro-sd.  Try moving logging to a USB device.", KIS_THREAD_DEADLOCK_TIMEOUT); \
            Globalreg::globalreg->fatal_condition = 1; \
            throw std::runtime_error("disk too slow for logging"); \
        } \
        throw(e); \
    }

    // Prebaked parameterized statements
    sqlite3_stmt *device_stmt;
    const char *device_pz;

    sqlite3_stmt *packet_stmt;
    const char *packet_pz;

    sqlite3_stmt *datasource_stmt;
    const char *datasource_pz;

    sqlite3_stmt *data_stmt;
    const char *data_pz;
    
    sqlite3_stmt *alert_stmt;
    const char *alert_pz;

    sqlite3_stmt *msg_stmt;
    const char *msg_pz;
    
    sqlite3_stmt *snapshot_stmt;
    const char *snapshot_pz;

    static int packet_handler(CHAINCALL_PARMS);

    // Keep track of our commit cycles; to avoid thrashing the filesystem with
    // commit state we run a 10 second tranasction commit loop
    kis_recursive_timed_mutex transaction_mutex;
    int transaction_timer;

    // Packet time limit
    unsigned int packet_timeout;
    int packet_timeout_timer;

    // Device time limit
    unsigned int device_timeout;
    int device_timeout_timer;

    // Snapshot time limit
    unsigned int snapshot_timeout;
    int snapshot_timeout_timer;

    // Message time limit
    unsigned int message_timeout;
    int message_timeout_timer;

    // Alert time limit
    unsigned int alert_timeout;
    int alert_timeout_timer;

    // Packet clearing API
    std::shared_ptr<kis_net_httpd_simple_post_endpoint> packet_drop_endp;
    unsigned int packet_drop_endpoint_handler(std::ostream& stream, const std::string& uri,
            shared_structured structured, kis_net_httpd_connection::variable_cache_map& postvars);

    // POI API
    std::shared_ptr<kis_net_httpd_simple_post_endpoint> make_poi_endp;
    unsigned int make_poi_endp_handler(std::ostream& stream, const std::string& uri,
            shared_structured structured, kis_net_httpd_connection::variable_cache_map& postvars);

    std::shared_ptr<kis_net_httpd_simple_tracked_endpoint> list_poi_endp;
    std::shared_ptr<tracker_element> list_poi_endp_handler();

    // Device log filter
    std::shared_ptr<class_filter_mac_addr> device_mac_filter;

    // Packet log filter
    std::shared_ptr<packet_filter_mac_addr> packet_mac_filter;
};

class kis_database_logfile_builder : public kis_logfile_builder {
public:
    kis_database_logfile_builder() :
        kis_logfile_builder() {
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    kis_database_logfile_builder(int in_id) :
        kis_logfile_builder(in_id) {
           
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    kis_database_logfile_builder(int in_id, std::shared_ptr<tracker_element_map> e) :
        kis_logfile_builder(in_id, e) {

        register_fields();
        reserve_fields(e);
        initialize();
    }

    virtual ~kis_database_logfile_builder() { }

    // Custom builder that fetches the global copy and shoves it back down to the 
    // logfile system instead
    virtual shared_logfile build_logfile(shared_log_builder builder) {
        std::shared_ptr<kis_database_logfile> logfile =
            Globalreg::fetch_mandatory_global_as<kis_database_logfile>("DATABASELOG");
        logfile->set_database_builder(builder);
        return logfile;
    }

    virtual void initialize() {
        set_log_class("kismet");
        set_log_name("Kismet Unified Log");
        set_stream(true);
        set_singleton(true);
        set_log_description("Unified Kismet log containing device, data source, packet, "
                "alert, and other runtime data");
    }
};

class pcap_stream_database : public pcap_stream_ringbuf {
public:
    pcap_stream_database(global_registry *in_globalreg, 
            std::shared_ptr<buffer_handler_generic> in_handler);

    virtual ~pcap_stream_database();

    virtual void stop_stream(std::string in_reason);

    // Write packet using database metadata, doing a lookup on the interface UUID.  This is more expensive
    // than the numerical lookup but we need to search by UUID regardless and for many single-source feeds
    // the lookup will be a single compare
    virtual int pcapng_write_database_packet(uint64_t time_s, uint64_t time_us,
            const std::string& interface_uuid, unsigned int dlt, const std::string& data);

    // Populate the interface list with all the interfaces from the database, we'll
    // assign pcapng IDs to them as they get used so only included interfaces will show up
    // in the pcapng idb list
    virtual void add_database_interface(const std::string& in_uuid, const std::string& in_interface,
            const std::string& in_namet);

protected:
    // Record of all interfaces from the database, assign them pcapng idb indexes and DLT types from the
    // first packet we see from them.
    struct db_interface {
    public:
        db_interface(const std::string& uuid, const std::string& interface, const std::string& name) :
            uuid {uuid},
            interface {interface},
            name {name},
            dlt {0},
            pcapnum {-1} { }

        std::string uuid;
        std::string interface;
        std::string name;
        unsigned int dlt;
        int pcapnum;
    };

    std::map<std::string, std::shared_ptr<db_interface>> db_uuid_intf_map;
    int next_pcap_intf_id;

};


#endif

