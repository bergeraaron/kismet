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

#include "devicetracker_view.h"
#include "devicetracker_component.h"
#include "util.h"

#include "kis_mutex.h"
#include "kismet_algorithm.h"

device_tracker_view::device_tracker_view(const std::string& in_id, const std::string& in_description, 
        new_device_cb in_new_cb, updated_device_cb in_update_cb) :
    tracker_component{},
    new_cb {in_new_cb},
    update_cb {in_update_cb} {

    mutex.set_name(fmt::format("devicetracker_view({})", in_id));

    using namespace std::placeholders;

    register_fields();
    reserve_fields(nullptr);

    view_id->set(in_id);
    view_description->set(in_description);

    device_list = std::make_shared<tracker_element_vector>();

    auto uri = fmt::format("/devices/views/{}/devices", in_id);
    device_endp =
        std::make_shared<kis_net_httpd_simple_post_endpoint>(uri, 
                [this](std::ostream& stream, const std::string& uri, shared_structured post_structured,
                    kis_net_httpd_connection::variable_cache_map& variable_cache) -> unsigned int {
                    return device_endpoint_handler(stream, uri, post_structured, variable_cache);
                });

    time_endp =
        std::make_shared<kis_net_httpd_path_tracked_endpoint>(
                [this](const std::vector<std::string>& path) -> bool {
                    return device_time_endpoint_path(path);
                }, 
                [this](const std::vector<std::string>& path) -> std::shared_ptr<tracker_element> {
                    return device_time_endpoint(path);
                });
}

device_tracker_view::device_tracker_view(const std::string& in_id, const std::string& in_description,
        const std::vector<std::string>& in_aux_path, 
        new_device_cb in_new_cb, updated_device_cb in_update_cb) :
    tracker_component{},
    new_cb {in_new_cb},
    update_cb {in_update_cb},
    uri_extras {in_aux_path} {

    using namespace std::placeholders;

    register_fields();
    reserve_fields(nullptr);

    view_id->set(in_id);
    view_description->set(in_description);

    device_list = std::make_shared<tracker_element_vector>();

    // Because we can't lock the device view and acquire locks on devices while the caller
    // might also hold locks on devices, we need to specially handle the mutex ourselves;
    // all our endpoints are registered w/ no mutex, accordingly.
    auto uri = fmt::format("/devices/views/{}/devices", in_id);
    device_endp =
        std::make_shared<kis_net_httpd_simple_post_endpoint>(uri, 
                [this](std::ostream& stream, const std::string& uri, shared_structured post_structured,
                    kis_net_httpd_connection::variable_cache_map& variable_cache) -> unsigned int {
                    return device_endpoint_handler(stream, uri, post_structured, variable_cache);
                });

    time_endp =
        std::make_shared<kis_net_httpd_path_tracked_endpoint>(
                [this](const std::vector<std::string>& path) -> bool {
                    return device_time_endpoint_path(path);
                }, 
                [this](const std::vector<std::string>& path) -> std::shared_ptr<tracker_element> {
                    return device_time_endpoint(path);
                });

    if (in_aux_path.size() == 0)
        return;

    // Concatenate the alternate endpoints and register the same endpoint handlers
    std::stringstream ss;
    for (auto i : in_aux_path)
        ss << i << "/";

    uri = fmt::format("/devices/views/{}devices", ss.str());
    device_uri_endp =
        std::make_shared<kis_net_httpd_simple_post_endpoint>(uri, 
                [this](std::ostream& stream, const std::string& uri, shared_structured post_structured,
                    kis_net_httpd_connection::variable_cache_map& variable_cache) -> unsigned int {
                    return device_endpoint_handler(stream, uri, post_structured, variable_cache);
                });

    time_uri_endp =
        std::make_shared<kis_net_httpd_path_tracked_endpoint>(
                [this](const std::vector<std::string>& path) -> bool {
                    return device_time_uri_endpoint_path(path);
                }, 
                [this](const std::vector<std::string>& path) -> std::shared_ptr<tracker_element> {
                    return device_time_uri_endpoint(path);
                });
    
}

std::shared_ptr<tracker_element_vector> device_tracker_view::do_device_work(device_tracker_view_worker& worker) {
    // Make a copy of the vector
    std::shared_ptr<tracker_element_vector> immutable_copy;
    {
        local_shared_locker dl(&mutex);
        immutable_copy = std::make_shared<tracker_element_vector>(device_list);
    }

    return do_device_work(worker, immutable_copy);
}

std::shared_ptr<tracker_element_vector> device_tracker_view::do_readonly_device_work(device_tracker_view_worker& worker) {
    // Make a copy of the vector
    std::shared_ptr<tracker_element_vector> immutable_copy;
    {
        local_shared_locker dl(&mutex);
        immutable_copy = std::make_shared<tracker_element_vector>(device_list);
    }

    return do_readonly_device_work(worker, immutable_copy);
}

std::shared_ptr<tracker_element_vector> device_tracker_view::do_device_work(device_tracker_view_worker& worker,
        std::shared_ptr<tracker_element_vector> devices) {
    auto ret = std::make_shared<tracker_element_vector>();
    ret->reserve(devices->size());
    kis_recursive_timed_mutex ret_mutex;

    std::for_each(devices->begin(), devices->end(),
            [&](shared_tracker_element val) {

            if (val == nullptr)
                return;

            auto dev = std::static_pointer_cast<kis_tracked_device_base>(val);

            bool m;
            {
                local_locker devlocker(&dev->device_mutex);
                m = worker.match_device(dev);
            }

            if (m) {
                local_locker retl(&ret_mutex);
                ret->push_back(dev);
            }

        });

    worker.set_matched_devices(ret);

    return ret;
}

std::shared_ptr<tracker_element_vector> device_tracker_view::do_readonly_device_work(device_tracker_view_worker& worker,
        std::shared_ptr<tracker_element_vector> devices) {
    auto ret = std::make_shared<tracker_element_vector>();
    ret->reserve(devices->size());
    kis_recursive_timed_mutex ret_mutex;

    std::for_each(devices->begin(), devices->end(),
            [&](shared_tracker_element val) {

            if (val == nullptr)
                return;

            auto dev = std::static_pointer_cast<kis_tracked_device_base>(val);

            bool m;
            {
                local_shared_locker devlocker(&dev->device_mutex);
                m = worker.match_device(dev);
            }

            if (m) {
                local_locker retl(&ret_mutex);
                ret->push_back(dev);
            }

        });

    worker.set_matched_devices(ret);

    return ret;
}

void device_tracker_view::new_device(std::shared_ptr<kis_tracked_device_base> device) {
    if (new_cb != nullptr) {
        local_locker l(&mutex);

        if (new_cb(device)) {
            auto dpmi = device_presence_map.find(device->get_key());

            if (dpmi == device_presence_map.end()) {
                device_presence_map[device->get_key()] = true;
                device_list->push_back(device);
            }

            list_sz->set(device_list->size());
        }
    }
}

void device_tracker_view::update_device(std::shared_ptr<kis_tracked_device_base> device) {

    if (update_cb == nullptr)
        return;

    {
        local_locker l(&mutex);
        bool retain = update_cb(device);

        auto dpmi = device_presence_map.find(device->get_key());

        // If we're adding the device (or keeping it) and we don't have it tracked,
        // add it and record it in the presence map
        if (retain && dpmi == device_presence_map.end()) {
            device_list->push_back(device);
            device_presence_map[device->get_key()] = true;
            list_sz->set(device_list->size());
            return;
        }

        // if we're removing the device, find it in the vector and remove it, and remove
        // it from the presence map; this is expensive
        if (!retain && dpmi != device_presence_map.end()) {
            for (auto di = device_list->begin(); di != device_list->end(); ++di) {
                if (*di == device) {
                    device_list->erase(di);
                    break;
                }
            }
            device_presence_map.erase(dpmi);
            list_sz->set(device_list->size());
            return;
        }
    }
}

void device_tracker_view::remove_device(std::shared_ptr<kis_tracked_device_base> device) {
    local_locker l(&mutex);

    auto di = device_presence_map.find(device->get_key());

    if (di != device_presence_map.end()) {
        device_presence_map.erase(di);

        for (auto vi = device_list->begin(); vi != device_list->end(); ++vi) {
            if (*vi == device) {
                device_list->erase(vi);
                break;
            }
        }
        
        list_sz->set(device_list->size());
    }
}

void device_tracker_view::add_device_direct(std::shared_ptr<kis_tracked_device_base> device) {
    local_locker l(&mutex);

    auto di = device_presence_map.find(device->get_key());

    if (di != device_presence_map.end())
        return;

    device_presence_map[device->get_key()] = true;
    device_list->push_back(device);

    list_sz->set(device_list->size());
}

void device_tracker_view::remove_device_direct(std::shared_ptr<kis_tracked_device_base> device) {
    local_locker l(&mutex);

    auto di = device_presence_map.find(device->get_key());

    if (di != device_presence_map.end()) {
        device_presence_map.erase(di);

        for (auto vi = device_list->begin(); vi != device_list->end(); ++vi) {
            if (*vi == device) {
                device_list->erase(vi);
                break;
            }
        }
        
        list_sz->set(device_list->size());
    }
}

bool device_tracker_view::device_time_endpoint_path(const std::vector<std::string>& path) {
    // /devices/views/[id]/last-time/[time]/devices

    if (path.size() < 6)
        return false;

    if (path[0] != "devices" || path[1] != "views" || path[3] != "last-time" || path[5] != "devices")
        return false;

    if (path[2] != get_view_id())
        return false;

    try {
       string_to_n<int64_t>(path[4]);
    } catch (const std::exception& e) {
        return false;
    }

    return true;
}

std::shared_ptr<tracker_element> device_tracker_view::device_time_endpoint(const std::vector<std::string>& path) {
    // The device worker creates an immutable copy of the device list under its own RO mutex,
    // so we don't have to lock here.
    
    auto ret = std::make_shared<tracker_element_vector>();

    if (path.size() < 6)
        return ret;

    auto tv = string_to_n<int64_t>(path[4], 0);
    time_t ts;

    // Don't allow 'all' devices b/c it's really expensive
    if (tv == 0)
        return ret;

    if (tv < 0)
        ts = time(0) - tv;
    else
        ts = tv;

    auto worker = 
        device_tracker_view_function_worker([&](std::shared_ptr<kis_tracked_device_base> dev) -> bool {
                if (dev->get_last_time() < ts)
                    return false;

                return true;
                });

    return do_readonly_device_work(worker);
}

bool device_tracker_view::device_time_uri_endpoint_path(const std::vector<std::string>& path) {
    // /devices/views/[extrasN]/last-time/[time]/devices
    
    auto extras_sz = uri_extras.size();

    if (extras_sz == 0)
        return false;

    if (path.size() < (5 + extras_sz))
        return false;

    if (path[0] != "devices" || path[1] != "views" || path[extras_sz + 2] != "last-time" || 
            path[extras_sz + 4] != "devices")
        return false;

    for (size_t s = 0; s < extras_sz; s++) {
        if (path[2 + s] != uri_extras[s]) {
            return false;
        }
    }

    try {
        string_to_n<int64_t>(path[3 + extras_sz]);
    } catch (const std::exception& e) {
        return false;
    }

    return true;
}

std::shared_ptr<tracker_element> device_tracker_view::device_time_uri_endpoint(const std::vector<std::string>& path) {
    // The device worker creates an immutable copy of the device list under its own RO mutex,
    // so we don't have to lock here.
    auto ret = std::make_shared<tracker_element_vector>();

    auto extras_sz = uri_extras.size();

    if (extras_sz == 0)
        return ret;

    if (path.size() < (5 + extras_sz))
        return ret;

    auto tv = string_to_n<int64_t>(path[3 + extras_sz], 0);
    time_t ts;

    // Don't allow 'all' devices b/c it's really expensive
    if (tv == 0)
        return ret;

    if (tv < 0)
        ts = time(0) + tv;
    else
        ts = tv;

    auto worker = 
        device_tracker_view_function_worker([&](std::shared_ptr<kis_tracked_device_base> dev) -> bool {
                if (dev->get_last_time() < ts)
                    return false;

                return true;
                });

    return do_readonly_device_work(worker);
}

unsigned int device_tracker_view::device_endpoint_handler(std::ostream& stream, 
        const std::string& uri, shared_structured structured,
        std::map<std::string, std::shared_ptr<std::stringstream>>& postvars) {
    // Summarization vector based on simplification part of shared data
    auto summary_vec = std::vector<SharedElementSummary>{};

    // Rename cache generated by summarization
    auto rename_map = std::make_shared<tracker_element_serializer::rename_map>();

    // Timestamp limitation
    time_t timestamp_min = 0;

    // String search term, if any
    auto search_term = std::string{};

    // Search paths, if any
    auto search_paths = std::vector<std::vector<int>>{};

    // Order path
    auto order_field = std::vector<int>{};

    // Regular expression terms, if any
    auto regex = shared_structured{};

    // Wrapper, if any, we insert under
    std::shared_ptr<tracker_element_string_map> wrapper_elem;

    // Field we transmit in the final stage (derived array, or map)
    std::shared_ptr<tracker_element> transmit;

    // Windowed response elements, used in datatables and others
    auto length_elem = std::make_shared<tracker_element_uint64>();
    auto start_elem = std::make_shared<tracker_element_uint64>();

    // Total and filtered output sizes
    auto total_sz_elem = std::make_shared<tracker_element_uint64>();
    auto filtered_sz_elem = std::make_shared<tracker_element_uint64>();

    // Output device list, should be copied into for final output
    auto output_devices_elem = std::make_shared<tracker_element_vector>();

    // Datatables specific draw element
    auto dt_draw_elem = std::make_shared<tracker_element_uint64>();

    try {
        // If the structured component has a 'fields' record, derive the fields
        // simplification
        if (structured->has_key("fields")) {
            auto fields = structured->get_structured_by_key("fields");
            auto fvec = fields->as_vector();

            for (const auto& i : fvec) {
                if (i->is_string()) {
                    auto s = std::make_shared<tracker_element_summary>(i->as_string());
                    summary_vec.push_back(s);
                } else if (i->is_array()) {
                    auto mapvec = i->as_string_vector();

                    if (mapvec.size() != 2)
                        throw structured_data_exception("Invalid field mapping, expected "
                                "[field, rename]");

                    auto s = std::make_shared<tracker_element_summary>(mapvec[0], mapvec[1]);
                    summary_vec.push_back(s);
                } else {
                    throw structured_data_exception("Invalid field mapping, expected "
                            "field or [field,rename]");
                }
            }
        }

        // Capture timestamp and negative-offset timestamp
        int64_t raw_ts = structured->key_as_number("last_time", 0);
        if (raw_ts < 0)
            timestamp_min = time(0) + raw_ts;
        else
            timestamp_min = raw_ts;

        // Regex
        if (structured->has_key("regex"))
            regex = structured->get_structured_by_key("regex");

    } catch (const structured_data_exception& e) {
        stream << "Invalid request: " << e.what() << "\n";
        return 400;
    }

    // Input fields from variables
    unsigned int in_window_start = 0;
    unsigned int in_window_len = 0;
    unsigned int in_dt_draw = 0;
    int in_order_column_num = 0;
    unsigned int in_order_direction = 0;

    // Column number->path field mapping
    auto column_number_map = structured_data::structured_num_map{};

    // Parse datatables sub-data for windowing, etc
    try {
        // Extract the column number -> column fieldpath data
        if (structured->has_key("colmap")) 
            column_number_map = structured->get_structured_by_key("colmap")->as_number_map();

        if (structured->key_as_bool("datatable", false)) {
            // Extract from the raw postvars 
            if (postvars.find("start") != postvars.end())
                *(postvars["start"]) >> in_window_start;

            if (postvars.find("length") != postvars.end())
                *(postvars["length"]) >> in_window_len;

            if (postvars.find("draw") != postvars.end())
                *(postvars["draw"]) >> in_dt_draw;

            if (postvars.find("search[value]") != postvars.end())
                *(postvars["search[value]"]) >> search_term;

            // Search every field we return
            if (search_term.length() != 0) 
                for (const auto& svi : summary_vec)
                    search_paths.push_back(svi->resolved_path);

            // We only allow ordering by a single column, we don't do sub-ordering;
            // look for that single column
            if (postvars.find("order[0][column]") != postvars.end())
                *(postvars["order[0][column]"]) >> in_order_column_num;

            // We can only sort by a column that makes sense
            auto column_index = column_number_map.find(in_order_column_num);
            if (column_index == column_number_map.end())
                in_order_column_num = -1;

            // What direction do we sort in
            if (in_order_column_num >= 0 &&
                    postvars.find("order[0][dir]") != postvars.end()) {
                auto order = postvars.find("order[0][dir]")->second->str();

                if (order == "asc")
                    in_order_direction = 1;
                else
                    in_order_direction = 0;

                // Resolve the path, we only allow the first one
                auto index_array = column_index->second->as_vector();
                if (index_array.size() > 0) {
                    if (index_array[0]->is_array()) {
                        // We only allow the first field, but make sure we're not a nested array
                        auto index_sub_array = index_array[0]->as_string_vector();
                        if (index_sub_array.size() > 0) {
                            auto summary = tracker_element_summary{index_sub_array[0]};
                            order_field = summary.resolved_path;
                        }
                    } else {
                        // Otherwise get the first array
                        auto column_index_vec = column_index->second->as_string_vector();
                        if (column_index_vec.size() >= 1) {
                            auto summary = tracker_element_summary{column_index_vec[0]};
                            order_field = summary.resolved_path;
                        }
                    }
                }
            }

            if (in_window_len > 500) 
                in_window_len = 500;

            // Set the window elements for datatables
            length_elem->set(in_window_len);
            start_elem->set(in_window_start);
            dt_draw_elem->set(in_dt_draw);

            // Set up the datatables wrapper
            wrapper_elem = std::make_shared<tracker_element_string_map>();
            transmit = wrapper_elem;

            wrapper_elem->insert("draw", dt_draw_elem);
            wrapper_elem->insert("data", output_devices_elem);
            wrapper_elem->insert("recordsTotal", total_sz_elem);
            wrapper_elem->insert("recordsFiltered", filtered_sz_elem);

            // We transmit the wrapper elem
            transmit = wrapper_elem;
        }
    } catch (const std::exception& e) {
        stream << "Invalid request: " << e.what() << "\n";
        return 400;
    }

    // Next vector we do work on
    auto next_work_vec = std::make_shared<tracker_element_vector>();

    // Copy the entire vector list, under lock, to the next work vector; this makes it an independent copy
    // which is protected from the main vector being grown/shrank.  While we're in there, log the total
    // size of the original vector for windowed ops.
    {
        local_shared_locker l(&mutex);

        next_work_vec->set(device_list->begin(), device_list->end());
        total_sz_elem->set(next_work_vec->size());
    }

    // If we have a time filter, apply that first, it's the fastest.
    if (timestamp_min > 0) {
        auto worker = 
            device_tracker_view_function_worker([timestamp_min] (std::shared_ptr<kis_tracked_device_base> dev) -> bool {
                    if (dev->get_last_time() < timestamp_min)
                        return false;
                    return true;
                    });

        // Do the work and copy the vector
        auto ts_vec = do_readonly_device_work(worker, next_work_vec);
        next_work_vec->set(ts_vec->begin(), ts_vec->end());
    }

    // Apply a string filter
    if (search_term.length() > 0 && search_paths.size() > 0) {
        auto worker =
            device_tracker_view_icasestringmatch_worker(search_term, search_paths);
        auto s_vec = do_readonly_device_work(worker, next_work_vec);
        next_work_vec->set(s_vec->begin(), s_vec->end());
    }

    // Apply a regex filter
    if (regex != nullptr) {
        try {
            auto worker = 
                device_tracker_view_regex_worker(regex);
            auto r_vec = do_readonly_device_work(worker, next_work_vec);
            next_work_vec = r_vec;
            // next_work_vec->set(r_vec->begin(), r_vec->end());
        } catch (const std::exception& e) {
            stream << "Invalid regex: " << e.what() << "\n";
            return 400;
        }
    }

    // Apply the filtered length
    filtered_sz_elem->set(next_work_vec->size());

    // Slice from the beginning of the list
    if (in_window_start >= next_work_vec->size()) 
        in_window_start = 0;

    // Update the start
    start_elem->set(in_window_start);

    tracker_element_vector::iterator si = std::next(next_work_vec->begin(), in_window_start);
    tracker_element_vector::iterator ei;

    if (in_window_len + in_window_start >= next_work_vec->size() || in_window_len == 0)
        ei = next_work_vec->end();
    else
        ei = std::next(next_work_vec->begin(), in_window_start + in_window_len);

    // Update the end
    length_elem->set(ei - si);

    // Unfortunately we need to do a stable sort to get a consistent display
    if (in_order_column_num >= 0 && order_field.size() > 0) {
        std::stable_sort(next_work_vec->begin(), next_work_vec->end(),
                [&](shared_tracker_element a, shared_tracker_element b) -> bool {
                shared_tracker_element fa;
                shared_tracker_element fb;

                fa = get_tracker_element_path(order_field, a);
                fb = get_tracker_element_path(order_field, b);

                if (fa == nullptr) 
                    return in_order_direction == 0;

                if (fb == nullptr)
                    return in_order_direction != 0;

                if (in_order_direction == 0)
                    return fast_sort_tracker_element_less(fa, fb);

                return fast_sort_tracker_element_less(fb, fa);
            });
    }

    // Summarize into the output element
    for (auto i = si; i != ei; ++i) {
        output_devices_elem->push_back(summarize_single_tracker_element(*i, summary_vec, rename_map));
    }

    // If the transmit wasn't assigned to a wrapper...
    if (transmit == nullptr)
        transmit = output_devices_elem;

    // serialize
    Globalreg::globalreg->entrytracker->serialize(kishttpd::get_suffix(uri), stream, transmit, rename_map);

    // And done
    return 200;
}


