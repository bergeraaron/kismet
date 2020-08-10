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

#ifndef __JSON_ADAPTER_H__
#define __JSON_ADAPTER_H__

#include "config.h"

#include "globalregistry.h"
#include "trackedelement.h"
#include "devicetracker_component.h"

// Standard JSON serialization adapter; will form complete JSON objects out
// of the input objects.  Best connected to a chainbuf output stream via a
// buffer_handler_ostream_buf or similar
namespace json_adapter {

// Basic packer with some defaulted options - prettyprint and depth used for
// recursive indenting and prettifying the output
void pack(std::ostream &stream, shared_tracker_element e,
        std::shared_ptr<tracker_element_serializer::rename_map> name_map = nullptr,
        bool prettyprint = false, unsigned int depth = 0,
        std::function<std::string (const std::string&)> name_permuter = 
            [](const std::string& s) -> std::string { return s; });

std::string sanitize_string(const std::string& in) noexcept;
std::size_t sanitize_extra_space(const std::string& in) noexcept;

class serializer : public tracker_element_serializer {
public:
    serializer() :
        tracker_element_serializer() { }

    virtual int serialize(shared_tracker_element in_elem, std::ostream &stream,
            std::shared_ptr<rename_map> name_map = nullptr) override {
        pack(stream, in_elem, name_map);
        return 0;
    }
};

}

// "ELK-style" JSON adapter.  This will behave the same as the normal JSON
// serializer with a few important differences:  
// 1. If the top-level object *is a vector type*, it will serialize each 
// member of the vector independently as a complete JSON object separated 
// by newlines.  This allows for a 'streamed' JSON output which will not 
// require loading the entire object into RAM.
// 2. To avoid conflicts with the ELK interpretation of field names, all 
// dots are converted to underscores
namespace ek_json_adapter {

class serializer : public tracker_element_serializer {
public:
    serializer() :
        tracker_element_serializer() { }

    virtual int serialize(shared_tracker_element in_elem, std::ostream &stream,
            std::shared_ptr<rename_map> name_map = nullptr) override {
        local_locker lock(&mutex);

        if (in_elem->get_type() == tracker_type::tracker_vector) {
            for (auto i : *(std::static_pointer_cast<tracker_element_vector>(in_elem))) {
                if (i == nullptr)
                    continue;

                json_adapter::pack(stream, i, name_map, false, 0,
                        [](const std::string& s) { 
                            return multi_replace_all(s, ".", "_");
                        });
                stream << "\n";
            }
        } else {
            // No longer accept invalid data for ekjson, it MUST be a vector as the top-level object
            stream << "{\"error\": \"Invalid data supplied for ekjson.  Ekjson endpoints can only be serialized from vectors.\"}\n";
            return -1;
        }

        return 0;
    }
};

}

// Iterative JSON
// The 'old' ekjson format, iterative json converts all *vector objects* into *an object per
// newline*.  This retains the existing kismet names for fields.
namespace it_json_adapter {
class serializer : public tracker_element_serializer {
public:
    serializer() :
        tracker_element_serializer() { }

    virtual int serialize(shared_tracker_element in_elem, std::ostream &stream,
            std::shared_ptr<rename_map> name_map = nullptr) override {
        local_locker lock(&mutex);

        if (in_elem->get_type() == tracker_type::tracker_vector) {
            for (auto i : *(std::static_pointer_cast<tracker_element_vector>(in_elem))) {
                json_adapter::pack(stream, i, name_map);
                stream << "\n";
            }
        } else {
            stream << "<h1>Invalid format for itjson</h1>itjson endpoints can only be used with array or list results\n";
            return -1;
            // json_adapter::pack(stream, in_elem, name_map);
        }

        return 1;
    }
};

}

// "Pretty" JSON adapter.  This will include metadata about the fields, and format
// it to be human readable.
namespace pretty_json_adapter {

class serializer : public tracker_element_serializer {
public:
    serializer() :
        tracker_element_serializer() { }

    virtual int serialize(shared_tracker_element in_elem, std::ostream &stream,
            std::shared_ptr<rename_map> name_map = nullptr) override {
        // Call the packer in pretty mode
        json_adapter::pack(stream, in_elem, name_map, true, 1);

        return 1;
    }

};

}

// "Storage" JSON adapter.  This adapter is intended to create JSON data suitable for
// re-importing into Kismet (like for storing state data into a database for future
// instances).
//
// Every record is split into an object containing multiple metadata fields; these
// fields define the base field name and base field type; for instance a device
// top-level record would be represented as:
// {
//    "objname": "kismet.device.base",
//    "objtype": "tracker_map",
//    "objdata": {
//       ... device fields
//     }
// }
//
// Sub-objects inside a map will be represented as:
// {
// ...
//    "kismet.device.base.key": {
//        "objname": "kismet.device.base.key",
//        "objtype": "tracker_uint64",
//        "objdata": 31777509604288
//     }
// ...
// }

namespace storage_json_adapter {

void pack(std::ostream &stream, shared_tracker_element e,
        std::shared_ptr<tracker_element_serializer::rename_map> name_map = nullptr);

class serializer : public tracker_element_serializer {
public:
    serializer() :
        tracker_element_serializer() { }

    virtual int serialize(shared_tracker_element in_elem, std::ostream &stream,
            std::shared_ptr<rename_map> name_map = nullptr) override {
        // Call the packer in pretty mode
        pack(stream, in_elem, name_map);

        return 1;
    }

};

}


#endif
