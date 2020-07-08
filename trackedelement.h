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

#ifndef __TRACKEDELEMENT_H__
#define __TRACKEDELEMENT_H__

#include "config.h"

#include <stdio.h>
#include <stdint.h>

#include <functional>

#include <string>
#include <stdexcept>

#include <vector>
#include <map>
#include <memory>
#include <unordered_map>

#include "fmt.h"

#include "kis_mutex.h"
#include "macaddr.h"
#include "uuid.h"

class entry_tracker;
class tracker_element;

using shared_tracker_element = std::shared_ptr<tracker_element>;

// Very large key wrapper class, needed for keying devices with per-server/per-phy 
// but consistent keys.  Components are store in big-endian format internally so that
// they are consistent across platforms.
//
// Values are exported as big endian, hex, [SPKEY]_[DKEY]
class device_key {
public:
    friend bool operator <(const device_key& x, const device_key& y);
    friend bool operator ==(const device_key& x, const device_key& y);
    friend std::ostream& operator<<(std::ostream& os, const device_key& k);
    friend std::istream& operator>>(std::istream& is, device_key& k);

    device_key();

    device_key(const device_key& k);

    // Create a key from a computed phy hash and a mac address
    device_key(uint32_t in_pkey, mac_addr in_device);

    // Create a key from a computed phy hash and a computed mac address
    device_key(uint32_t in_pkey, uint64_t in_device);

    // Create a key from an incoming string/exported key; this should only happen during
    // deserialization and rest queries; it's fairly expensive otherwise
    device_key(std::string in_keystr);

    std::string as_string() const;

    // Generate a cached phykey component; phyhandlers do this to cache
    static uint32_t gen_pkey(std::string in_phy);

    // Generate a cached SP key combination
    static uint64_t gen_spkey(uuid s_uuid, std::string phy);

    bool get_error() { return error; }

    uint64_t get_spkey() const {
        return spkey;
    }

    uint64_t get_dkey() const {
        return dkey;
    }

protected:
    uint64_t spkey, dkey;
    bool error;
};

bool operator <(const device_key& x, const device_key& y);
bool operator ==(const device_key& x, const device_key& y);
std::ostream& operator<<(std::ostream& os, const device_key& k);
std::istream& operator>>(std::istream& is, device_key& k);

namespace std {
    template<> struct hash<device_key> {
        std::size_t operator()(device_key const& d) const noexcept {
            std::size_t h1 = std::hash<uint64_t>{}(d.get_spkey());
            std::size_t h2 = std::hash<uint64_t>{}(d.get_dkey());
            return h1 ^ (h2 << 1);
        }
    };
}

// Types of fields we can track and automatically resolve
// Statically assigned type numbers which MUST NOT CHANGE as things go forwards for 
// binary/fast serialization, new types must be added to the end of the list
enum class tracker_type {
    tracker_string = 0,

    tracker_int8 = 1, 
    tracker_uint8 = 2,

    tracker_int16 = 3, 
    tracker_uint16 = 4,

    tracker_int32 = 5, 
    tracker_uint32 = 6,

    tracker_int64 = 7,
    tracker_uint64 = 8,

    tracker_float = 9,
    tracker_double = 10,

    // Less basic types
    tracker_mac_addr = 11, 
    tracker_uuid = 12,

    // Vector and named map
    tracker_vector = 13, 
    tracker_map = 14,

    // unsigned integer map (int-keyed data not field-keyed)
    tracker_int_map = 15,

    // Mac map (mac-keyed tracker data)
    tracker_mac_map = 16,

    // String-keyed map
    tracker_string_map = 17,
    
    // Double-keyed map
    tracker_double_map = 18,

    // Byte array
    tracker_byte_array = 19,

    // Large key
    tracker_key = 20,

    // Key-map (Large keys, 128 bit or higher, using the TrackedKey class)
    tracker_key_map = 21,

    // "Complex-Scalar" types provide memory-efficient maps for specific collections
    // of data Kismet uses; RRDs use vectors of doubles and frequency counting use maps
    // of double:double, both of which benefit greatly from not tracking element fields for 
    // the collected types.
    
    // Vector of scalar double, not object, values
    tracker_vector_double = 22,

    // Map of double:double, not object, values
    tracker_double_map_double = 23,

    // Vector of strings
    tracker_vector_string = 24,

    // Hash-keyed map, using size_t as the keying element
    tracker_hashkey_map = 25,

    // Alias of another field
    tracker_alias = 26,
};

class tracker_element {
public:
    tracker_element() = delete;

    tracker_element(tracker_type t) : 
        type(t),
        tracked_id(-1) { }

    tracker_element(tracker_type t, int id) :
        type(t),
        tracked_id(id) { }

    virtual ~tracker_element() { };

    // Factory-style for easily making more of the same if we're subclassed
    virtual std::unique_ptr<tracker_element> clone_type() {
        return nullptr;
    }

    virtual std::unique_ptr<tracker_element> clone_type(int in_id) {
        return nullptr;
    }

    // Called prior to serialization output
    virtual void pre_serialize() { }

    // Called after serialization is completed
    virtual void post_serialize() { }

    template<typename CT>
    static std::shared_ptr<CT> safe_cast_as(std::shared_ptr<tracker_element> e) {
        if (e == nullptr)
            throw std::runtime_error(fmt::format("null trackedelement can not be safely cast"));

#if TE_TYPE_SAFETY == 1
        if (e->get_type() != CT::static_type())
            throw std::runtime_error(fmt::format("trackedelement can not safely cast a {} to a {}",
                        e->get_type_as_string(), type_to_string(CT::static_type())));
#endif

        return std::static_pointer_cast<CT>(e);
    }

    virtual uint32_t get_signature() const {
        return static_cast<uint32_t>(type);
    }

    int get_id() const {
        return tracked_id;
    }

    void set_id(int id) {
        tracked_id = id;
    }

    void set_local_name(const std::string& in_name) {
        local_name = in_name;
    }

    std::string get_local_name() {
        return local_name;
    }

    void set_dynamic_entity(const std::string& in_name) {
        set_local_name(in_name);
        set_id(adler32_checksum(in_name));
    }

    void set_type(tracker_type type);

    tracker_type get_type() const { 
        return type; 
    }

    std::string get_type_as_string() const {
        return type_to_string(get_type());
    }

    // Coercive set - attempt to fit incoming data into the type (for basic types)
    // Set string values - usable for strings, macs, UUIDs
    virtual void coercive_set(const std::string& in_str) = 0;
    // Set numerical values - usable for all numeric types
    virtual void coercive_set(double in_num) = 0;
    // Attempt to coerce one complete item to another
    virtual void coercive_set(const shared_tracker_element& in_elem) = 0;

    static std::string type_to_string(tracker_type t);
    static tracker_type typestring_to_type(const std::string& s);
    static std::string type_to_typestring(tracker_type t);

    tracker_type enforce_type(tracker_type t) {
        if (get_type() != t) 
            throw std::runtime_error(fmt::format("invalid trackedelement access id {}, cannot use a {} "
                        "as a {}", tracked_id, type_to_string(get_type()), type_to_string(t)));

        return t;
    }

    tracker_type enforce_type(tracker_type t1, tracker_type t2) {
        if (get_type() == t1)
            return t1;
        
        if (get_type() == t2)
            return t2;

        throw std::runtime_error(fmt::format("invalid trackedelement access id {}, cannot use a {} "
                    "as a {} or {}", tracked_id, type_to_string(get_type()), type_to_string(t1), type_to_string(t2)));
    }

protected:
    tracker_type type;
    int tracked_id;

    // Overridden name for this instance only
    std::string local_name;
};

// Generator function for making various elements
template<typename SUB, typename... Args>
std::unique_ptr<tracker_element> tracker_element_factory(const Args& ... args) {
    auto dup = std::unique_ptr<SUB>(new SUB(args...));
    return std::move(dup);
}

// Aliased element used to link one element to anothers name, for instance to
// allow the dot11 tracker a way to link the most recently used ssid from the
// map to a custom field
class tracker_element_alias : public tracker_element {
public:
    tracker_element_alias() :
        tracker_element(tracker_type::tracker_alias) { }

    tracker_element_alias(int in_id) :
        tracker_element(tracker_type::tracker_alias, in_id) { }

    tracker_element_alias(int id, std::shared_ptr<tracker_element> e) :
        tracker_element(tracker_type::tracker_alias, id),
        alias_element(e) { }

    tracker_element_alias(const std::string& al, std::shared_ptr<tracker_element> e) :
        tracker_element{tracker_type::tracker_alias},
        alias_element{e} {
            local_name = al;
        }

    static tracker_type static_type() {
        return tracker_type::tracker_alias;
    }

    virtual void coercive_set(const std::string& in_str) override {
        throw std::runtime_error("cannot coercively set aliases");
    }
    virtual void coercive_set(double in_num) override {
        throw std::runtime_error("cannot coercively set aliases");
    }

    virtual void coercive_set(const shared_tracker_element& e) override {
        throw std::runtime_error("cannot coercively set aliases");
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

    std::shared_ptr<tracker_element> get() {
        return alias_element;
    }

    void set(std::shared_ptr<tracker_element> ae) {
        alias_element = ae;
    }

protected:
    std::shared_ptr<tracker_element> alias_element;

};

// Superclass for generic components for pod-like scalar attributes, though
// they don't need to be explicitly POD
template <class P>
class tracker_element_core_scalar : public tracker_element {
public:
    tracker_element_core_scalar() = delete;

    tracker_element_core_scalar(tracker_type t) :
        tracker_element(t),
        value() { }

    tracker_element_core_scalar(tracker_type t, int id) :
        tracker_element(t, id),
        value() { }

    tracker_element_core_scalar(tracker_type t, int id, const P& v) :
        tracker_element(t, id),
        value(v) { }

    // We don't define coercion, subclasses have to do that
    virtual void coercive_set(const std::string& in_str) override = 0;
    virtual void coercive_set(double in_num) override = 0;
    virtual void coercive_set(const shared_tracker_element& in_elem) override = 0;

    // We don't define cloning, subclasses have to do that
    virtual std::unique_ptr<tracker_element> clone_type() override = 0;
    virtual std::unique_ptr<tracker_element> clone_type(int in_id) override = 0;

    P& get() {
        return value;
    }

    void set(const P& in) {
        value = in;
    }

    inline bool operator<(const tracker_element_core_scalar<P>& rhs) const {
        return value < rhs.value;
    }

    inline bool operator<(const std::shared_ptr<tracker_element> rhs) const {
        if (get_type() != rhs->get_type())
            throw std::runtime_error(fmt::format("Attempted to compare two non-equal field types, "
                        "{} < {}", get_type_as_string(), rhs->get_type_as_string()));

        return value < std::static_pointer_cast<tracker_element_core_scalar<P>>(rhs)->value;
    }

    
    inline bool less_than(const tracker_element_core_scalar<P>& rhs) const {
        return value < rhs.value;
    }

    inline bool less_than(const std::shared_ptr<tracker_element> rhs) const {
        if (get_type() != rhs->get_type())
            throw std::runtime_error(fmt::format("Attempted to compare two non-equal field types, "
                        "{} < {}", get_type_as_string(), rhs->get_type_as_string()));

        return value < safe_cast_as<tracker_element_core_scalar<P>>(rhs)->value;
    }

protected:
    P value;

};

class tracker_element_string : public tracker_element_core_scalar<std::string> {
public:
    tracker_element_string() :
        tracker_element_core_scalar<std::string>(tracker_type::tracker_string) { }

    tracker_element_string(tracker_type t) :
        tracker_element_core_scalar<std::string>(tracker_type::tracker_string) { }

    tracker_element_string(tracker_type t, int id) :
        tracker_element_core_scalar<std::string>(t, id) { }

    tracker_element_string(int id) :
        tracker_element_core_scalar<std::string>(tracker_type::tracker_string, id) { }

    tracker_element_string(int id, const std::string& s) :
        tracker_element_core_scalar<std::string>(tracker_type::tracker_string, id, s) { }

    tracker_element_string(tracker_type t, int id, const std::string& s) :
        tracker_element_core_scalar<std::string>(t, id, s) { }

    tracker_element_string(const std::string& s) :
        tracker_element_core_scalar<std::string>(tracker_type::tracker_string, 0, s) { }

    static tracker_type static_type() {
        return tracker_type::tracker_string;
    }

    virtual void coercive_set(const std::string& in_str) override;
    virtual void coercive_set(double in_num) override;
    virtual void coercive_set(const shared_tracker_element& e) override;

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

    using tracker_element_core_scalar<std::string>::less_than;
    inline bool less_than(const tracker_element_string& rhs) const;

    size_t length() {
        return value.length();
    }

};

class tracker_element_byte_array : public tracker_element_string {
public:
    tracker_element_byte_array() :
        tracker_element_string(tracker_type::tracker_byte_array) { }

    tracker_element_byte_array(int id) :
        tracker_element_string(tracker_type::tracker_byte_array, id) { }

    tracker_element_byte_array(int id, const std::string& s) :
        tracker_element_string(tracker_type::tracker_byte_array, id, s) { }

    static tracker_type static_type() {
        return tracker_type::tracker_byte_array;
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

    template<typename T>
    void set(const T& v) {
        value = std::string(v);
    }

    void set(const uint8_t* v, size_t len) {
        value = std::string((const char *) v, len);
    }

    void set(const char *v, size_t len) {
        value = std::string(v, len);
    }

    size_t length() const {
        return value.length();
    }

    std::string to_hex() const {
        std::stringstream ss;
        auto fflags = ss.flags();

        ss << std::uppercase << std::setfill('0') << std::setw(2) << std::hex;

        for (size_t i = 0; i < value.length(); i++) 
            ss << value.data()[i];

        ss.flags(fflags);

        return ss.str();
    }

};

class tracker_element_device_key : public tracker_element_core_scalar<device_key> {
public:
    tracker_element_device_key() :
        tracker_element_core_scalar<device_key>(tracker_type::tracker_key) { }

    tracker_element_device_key(int id) :
        tracker_element_core_scalar<device_key>(tracker_type::tracker_key, id) { }

    static tracker_type static_type() {
        return tracker_type::tracker_key;
    }

    virtual void coercive_set(const std::string& in_str) override {
        throw(std::runtime_error("Cannot coercive_set a devicekey from a string"));
    }

    virtual void coercive_set(double in_num) override {
        throw(std::runtime_error("Cannot coercive_set a devicekey from a numeric"));
    }

    // Attempt to coerce one complete item to another
    virtual void coercive_set(const shared_tracker_element& in_elem) override {
        throw(std::runtime_error("Cannot coercive_set a devicekey from an element"));
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
};

class tracker_element_uuid : public tracker_element_core_scalar<uuid> {
public:
    tracker_element_uuid() :
        tracker_element_core_scalar<uuid>(tracker_type::tracker_uuid) { }

    tracker_element_uuid(int id) :
        tracker_element_core_scalar<uuid>(tracker_type::tracker_uuid, id) { }

    tracker_element_uuid(int id, const uuid& u) :
        tracker_element_core_scalar<uuid>(tracker_type::tracker_uuid, id, u) { }

    static tracker_type static_type() {
        return tracker_type::tracker_uuid;
    }

    virtual void coercive_set(const std::string& in_str) override;
    virtual void coercive_set(double in_num) override;
    virtual void coercive_set(const shared_tracker_element& e) override;

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

};

class tracker_element_mac_addr : public tracker_element_core_scalar<mac_addr> {
public:
    tracker_element_mac_addr() :
        tracker_element_core_scalar<mac_addr>(tracker_type::tracker_mac_addr) { }

    tracker_element_mac_addr(int id) :
        tracker_element_core_scalar<mac_addr>(tracker_type::tracker_mac_addr, id) { }

    tracker_element_mac_addr(int id, const std::string& s) :
        tracker_element_core_scalar<mac_addr>(tracker_type::tracker_mac_addr, id, mac_addr(s)) { }

    tracker_element_mac_addr(int id, const mac_addr& m) :
        tracker_element_core_scalar<mac_addr>(tracker_type::tracker_mac_addr, id, m) { }

    static tracker_type static_type() {
        return tracker_type::tracker_mac_addr;
    }

    virtual void coercive_set(const std::string& in_str) override;
    virtual void coercive_set(double in_num) override;
    virtual void coercive_set(const shared_tracker_element& e) override;

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

};

// Simplify numeric conversion w/ an interstitial scalar-like that holds all 
// our numeric subclasses
template<class N>
class tracker_element_core_numeric : public tracker_element {
public:
    tracker_element_core_numeric() = delete;

    tracker_element_core_numeric(tracker_type t) :
        tracker_element(t) { 
        value = 0;
    }

    tracker_element_core_numeric(tracker_type t, int id) :
        tracker_element(t, id) { 
        value = 0;
    }

    tracker_element_core_numeric(tracker_type t, int id, const N& v) :
        tracker_element(t, id),
        value(v) { }

    virtual void coercive_set(const std::string& in_str) override {
        // Inefficient workaround for compilers that don't define std::stod properly
        // auto d = std::stod(in_str);
        
        std::stringstream ss(in_str);
        double d;

        ss >> d;

        if (ss.fail())
            throw std::runtime_error("could not convert string to numeric");

        coercive_set(d);
    }

    virtual void coercive_set(double in_num) override {
        if (in_num < value_min || in_num > value_max)
            throw std::runtime_error(fmt::format("cannot coerce to {}, number out of range",
                        this->get_type_as_string()));

        this->value = static_cast<N>(in_num);
    }

    virtual void coercive_set(const shared_tracker_element& e) override {
        switch (e->get_type()) {
            case tracker_type::tracker_int8:
            case tracker_type::tracker_uint8:
            case tracker_type::tracker_int16:
            case tracker_type::tracker_uint16:
            case tracker_type::tracker_int32:
            case tracker_type::tracker_uint32:
            case tracker_type::tracker_int64:
            case tracker_type::tracker_uint64:
            case tracker_type::tracker_float:
            case tracker_type::tracker_double:
                coercive_set(std::static_pointer_cast<tracker_element_core_numeric>(e)->get());
                break;
            case tracker_type::tracker_string:
                coercive_set(std::static_pointer_cast<tracker_element_string>(e)->get());
                break;
            default:
                throw std::runtime_error(fmt::format("Could not coerce {} to {}",
                            e->get_type_as_string(), this->get_type_as_string()));
        }
    }

    // We don't define cloning, subclasses have to do that
    virtual std::unique_ptr<tracker_element> clone_type() override {
        return nullptr;
    }

    virtual std::unique_ptr<tracker_element> clone_type(int in_id) override {
        return nullptr;
    }

    N& get() {
        return value;
    }

    void set(const N& in) {
        value = in;
    }

    inline bool operator==(const tracker_element_core_numeric<N>& rhs) const { 
        return value == rhs.value;
    }

    inline bool operator==(const N& rhs) const {
        return value != rhs;
    }

    inline bool operator!=(const tracker_element_core_numeric<N>& rhs) const { 
        return !(value == rhs.value); 
    }

    inline bool operator!=(const N& rhs) const {
        return value != rhs;
    }

    inline bool operator<=(const tracker_element_core_numeric<N>& rhs) const {
        return value <= rhs.value;
    }

    inline bool operator<=(const N& rhs) const {
        return value <= rhs;
    }

    inline bool operator<(const tracker_element_core_numeric<N>& rhs) const {
        return value < rhs.value;
    }

    inline bool operator<(const N& rhs) {
        return value < rhs;
    }

    inline bool operator>=(const tracker_element_core_numeric<N>& rhs) const {
        return value >= rhs.value;
    }

    inline bool operator>=(const N& rhs) {
        return value >= rhs;
    }

    inline bool operator>(const tracker_element_core_numeric<N>& rhs) const {
        return value > rhs.value;
    }

    inline bool operator>(const N& rhs) const {
        return value  > rhs;
    }

    tracker_element_core_numeric<N>& operator+=(const N& rhs) {
        value += rhs;
        return *this;
    }

    tracker_element_core_numeric<N>& operator-=(const N& rhs) {
        value -= rhs;
        return *this;
    }

    friend tracker_element_core_numeric<N> operator+(tracker_element_core_numeric lhs,
            const tracker_element_core_numeric<N>& rhs) {
        lhs += rhs;
        return lhs;
    }

    friend tracker_element_core_numeric<N> operator-(tracker_element_core_numeric lhs,
            const tracker_element_core_numeric<N>& rhs) {
        lhs -= rhs;
        return lhs;
    }

    tracker_element_core_numeric<N>& operator|=(const tracker_element_core_numeric<N>& rhs) {
        value |= rhs.value;
        return *this;
    }

    tracker_element_core_numeric<N>& operator|=(const N& rhs) {
        value |= rhs;
        return *this;
    }

    tracker_element_core_numeric<N>& operator&=(const tracker_element_core_numeric<N>& rhs) {
        value &= rhs.value;
        return *this;
    }

    tracker_element_core_numeric<N>& operator&=(const N& rhs) {
        value &= rhs;
        return *this;
    }

    tracker_element_core_numeric<N>& operator^=(const tracker_element_core_numeric<N>& rhs) {
        value ^= rhs.value;
        return *this;
    }

    tracker_element_core_numeric<N>& operator^=(const N& rhs) {
        value ^= rhs;
        return *this;
    }

    inline bool less_than(const tracker_element_core_numeric<N>& rhs) const {
        return value < rhs.value;
    }

    inline bool less_than(const std::shared_ptr<tracker_element> rhs) const {
        if (get_type() != rhs->get_type())
            throw std::runtime_error(fmt::format("Attempted to compare two non-equal field types, "
                        "{} < {}", get_type_as_string(), rhs->get_type_as_string()));

        return value < safe_cast_as<tracker_element_core_numeric<N>>(rhs)->value;
    }

protected:
    // Min/max ranges for conversion
    N value_min, value_max;
    N value;
};

class tracker_element_uint8 : public tracker_element_core_numeric<uint8_t> {
public:
    tracker_element_uint8() :
        tracker_element_core_numeric<uint8_t>(tracker_type::tracker_uint8) {
            value_min = 0;
            value_max = INT8_MAX;
        }

    tracker_element_uint8(int id) :
        tracker_element_core_numeric<uint8_t>(tracker_type::tracker_uint8, id) {
            value_min = 0;
            value_max = INT8_MAX;
        }

    tracker_element_uint8(int id, const uint8_t& v) :
        tracker_element_core_numeric<uint8_t>(tracker_type::tracker_uint8, id, v) {
            value_min = 0;
            value_max = INT8_MAX;
        }

    static tracker_type static_type() {
        return tracker_type::tracker_uint8;
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
};

class tracker_element_int8 : public tracker_element_core_numeric<int8_t> {
public:
    tracker_element_int8() :
        tracker_element_core_numeric<int8_t>(tracker_type::tracker_int8) {
            value_min = INT8_MIN;
            value_max = INT8_MAX;
        }

    tracker_element_int8(int id) :
        tracker_element_core_numeric<int8_t>(tracker_type::tracker_int8, id) {
            value_min = INT8_MIN;
            value_max = INT8_MAX;
        }

    tracker_element_int8(int id, const int8_t& v) :
        tracker_element_core_numeric<int8_t>(tracker_type::tracker_int8, id, v) {
            value_min = INT8_MIN;
            value_max = INT8_MAX;
        }

    static tracker_type static_type() {
        return tracker_type::tracker_int8;
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
};

class tracker_element_uint16 : public tracker_element_core_numeric<uint16_t> {
public:
    tracker_element_uint16() :
        tracker_element_core_numeric<uint16_t>(tracker_type::tracker_uint16) {
            value_min = 0;
            value_max = UINT16_MAX;
        }

    tracker_element_uint16(int id) :
        tracker_element_core_numeric<uint16_t>(tracker_type::tracker_uint16, id) {
            value_min = 0;
            value_max = UINT16_MAX;
        }

    tracker_element_uint16(int id, const uint16_t& v) :
        tracker_element_core_numeric<uint16_t>(tracker_type::tracker_uint16, id, v) {
            value_min = 0;
            value_max = UINT16_MAX;
        }

    static tracker_type static_type() {
        return tracker_type::tracker_uint16;
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
};

class tracker_element_int16 : public tracker_element_core_numeric<int16_t> {
public:
    tracker_element_int16() :
        tracker_element_core_numeric<int16_t>(tracker_type::tracker_int16) {
            value_min = INT16_MIN;
            value_max = INT16_MAX;
        }

    tracker_element_int16(int id) :
        tracker_element_core_numeric<int16_t>(tracker_type::tracker_int16, id) {
            value_min = INT16_MIN;
            value_max = INT16_MAX;
        }

    tracker_element_int16(int id, const int16_t& v) :
        tracker_element_core_numeric<int16_t>(tracker_type::tracker_int16, id, v) {
            value_min = INT16_MIN;
            value_max = INT16_MAX;
        }

    static tracker_type static_type() {
        return tracker_type::tracker_int16;
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
};

class tracker_element_uint32 : public tracker_element_core_numeric<uint32_t> {
public:
    tracker_element_uint32() :
        tracker_element_core_numeric<uint32_t>(tracker_type::tracker_uint32) {
            value_min = 0;
            value_max = UINT32_MAX;
        }

    tracker_element_uint32(int id) :
        tracker_element_core_numeric<uint32_t>(tracker_type::tracker_uint32, id) {
            value_min = 0;
            value_max = UINT32_MAX;
        }

    tracker_element_uint32(int id, const uint32_t& v) :
        tracker_element_core_numeric<uint32_t>(tracker_type::tracker_uint32, id, v) {
            value_min = 0;
            value_max = UINT32_MAX;
        }

    static tracker_type static_type() {
        return tracker_type::tracker_uint32;
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
};

class tracker_element_int32 : public tracker_element_core_numeric<int32_t> {
public:
    tracker_element_int32() :
        tracker_element_core_numeric<int32_t>(tracker_type::tracker_int32) {
            value_min = INT32_MIN;
            value_max = INT32_MAX;
        }

    tracker_element_int32(int id) :
        tracker_element_core_numeric<int32_t>(tracker_type::tracker_int32, id) {
            value_min = INT32_MIN;
            value_max = INT32_MAX;
        }

    tracker_element_int32(int id, const int32_t& v) :
        tracker_element_core_numeric<int32_t>(tracker_type::tracker_int32, id, v) {
            value_min = INT32_MIN;
            value_max = INT32_MAX;
        }

    static tracker_type static_type() {
        return tracker_type::tracker_int32;
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
};

class tracker_element_uint64 : public tracker_element_core_numeric<uint64_t> {
public:
    tracker_element_uint64() :
        tracker_element_core_numeric<uint64_t>(tracker_type::tracker_uint64) {
            value_min = 0;
            value_max = UINT64_MAX;
        }

    tracker_element_uint64(int id) :
        tracker_element_core_numeric<uint64_t>(tracker_type::tracker_uint64, id) {
            value_min = 0;
            value_max = UINT64_MAX;
        }

    tracker_element_uint64(int id, const uint64_t& v) :
        tracker_element_core_numeric<uint64_t>(tracker_type::tracker_uint64, id, v) {
            value_min = 0;
            value_max = UINT64_MAX;
        }

    static tracker_type static_type() {
        return tracker_type::tracker_uint64;
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
};

class tracker_element_int64 : public tracker_element_core_numeric<int64_t> {
public:
    tracker_element_int64() :
        tracker_element_core_numeric<int64_t>(tracker_type::tracker_int64) {
            value_min = INT64_MIN;
            value_max = INT64_MAX;
        }

    tracker_element_int64(int id) :
        tracker_element_core_numeric<int64_t>(tracker_type::tracker_int64, id) {
            value_min = INT64_MIN;
            value_max = INT64_MAX;
        }

    tracker_element_int64(int id, const int64_t& v) :
        tracker_element_core_numeric<int64_t>(tracker_type::tracker_int64, id, v) {
            value_min = INT64_MIN;
            value_max = INT64_MAX;
        }

    static tracker_type static_type() {
        return tracker_type::tracker_int64;
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
};

class tracker_element_float : public tracker_element_core_numeric<float> {
public:
    tracker_element_float() :
        tracker_element_core_numeric<float>(tracker_type::tracker_float) {
            value_min = std::numeric_limits<float>::min();
            value_max = std::numeric_limits<float>::max();
        }

    tracker_element_float(int id) :
        tracker_element_core_numeric<float>(tracker_type::tracker_float, id) {
            value_min = std::numeric_limits<float>::min();
            value_max = std::numeric_limits<float>::max();
        }

    tracker_element_float(int id, const float& v) :
        tracker_element_core_numeric<float>(tracker_type::tracker_float, id, v) {
            value_min = std::numeric_limits<float>::min();
            value_max = std::numeric_limits<float>::max();
        }

    static tracker_type static_type() {
        return tracker_type::tracker_float;
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
};

class tracker_element_double : public tracker_element_core_numeric<double> {
public:
    tracker_element_double() :
        tracker_element_core_numeric<double>(tracker_type::tracker_double) {
            value_min = std::numeric_limits<double>::min();
            value_max = std::numeric_limits<double>::max();
        }

    tracker_element_double(int id) :
        tracker_element_core_numeric<double>(tracker_type::tracker_double, id) {
            value_min = std::numeric_limits<double>::min();
            value_max = std::numeric_limits<double>::max();
        }

    tracker_element_double(int id, const double& v) :
        tracker_element_core_numeric<double>(tracker_type::tracker_double, id, v) {
            value_min = std::numeric_limits<double>::min();
            value_max = std::numeric_limits<double>::max();
        }

    static tracker_type static_type() {
        return tracker_type::tracker_double;
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
};


// Superclass for generic access to maps via multiple key structures; use a std::map tree
// map;  alternate implementation available as core_unordered_map for structures which don't
// need comparator operations
template <typename MT, typename K, typename V>
class tracker_element_core_map : public tracker_element {
public:
    using map_t = MT;
    using iterator = typename map_t::iterator;
    using const_iterator = typename map_t::const_iterator;
    using pair = std::pair<K, V>;

    tracker_element_core_map() = delete;

    tracker_element_core_map(tracker_type t) : 
        tracker_element(t),
        present_vector(false),
        present_key_vector(false) { }

    tracker_element_core_map(tracker_type t, int id) :
        tracker_element(t, id),
        present_vector(false),
        present_key_vector(false) { }

    // Optionally present as a vector of content when serializing
    void set_as_vector(const bool in_v) {
        present_vector = in_v;
    }

    bool as_vector() const {
        return present_vector;
    }

    // Optionally present as a vector of keys when serializing
    void set_as_key_vector(const bool in_v) {
        present_key_vector = in_v;
    }

    bool as_key_vector() const {
        return present_key_vector;
    }

    virtual void coercive_set(const std::string& in_str) override {
        throw(std::runtime_error("Cannot coercive_set a map from a string"));
    }

    virtual void coercive_set(double in_num) override {
        throw(std::runtime_error("Cannot coercive_set a map from a numeric"));
    }

    // Attempt to coerce one complete item to another
    virtual void coercive_set(const shared_tracker_element& in_elem) override {
        throw(std::runtime_error("Cannot coercive_set a map from an element"));
    }

    map_t& get() {
        return map;
    }

    iterator begin() {
        return map.begin();
    }

    const_iterator cbegin() {
        return map.cbegin();
    }

    iterator end() {
        return map.end();
    }

    const_iterator cend() {
        return map.cend();
    }

    iterator find(const K& k) {
        return map.find(k);
    }

    const_iterator find(const K& k) const {
        return map.find(k);
    }

    iterator erase(const K& k) {
        iterator i = map.find(k);
        return erase(i);
    }

    iterator erase(const_iterator i) {
        return map.erase(i);
    }

    iterator erase(iterator first, iterator last) {
        return map.erase(first, last);
    }

    bool empty() const noexcept {
        return map.empty();
    }

    void clear() noexcept {
        map.clear();
    }

    size_t size() const {
        return map.size();
    }

    // std::insert methods, does not replace existing objects
    std::pair<iterator, bool> insert(pair p) {
        return map.insert(p);
    }

    std::pair<iterator, bool> insert(const K& i, const V& e) {
        return insert(std::make_pair(i, e));
    }

    // insert, and replace if key is found.  if key is not found, insert
    // as normal.
    std::pair<iterator, bool> replace(pair p) {
        auto k = map.find(p.first);
        if (k != map.end())
            map.erase(k);

        return map.insert(p);
    }

    std::pair<iterator, bool> replace(const K& i, const V& e) {
        auto k = map.find(i);
        if (k != map.end())
            map.erase(k);

        return map.insert(std::make_pair(i, e));
    }

protected:
    map_t map;
    bool present_vector, present_key_vector;
};

// Dictionary / map-by-id
class tracker_element_map : public tracker_element_core_map<std::unordered_map<int, std::shared_ptr<tracker_element>>, int, std::shared_ptr<tracker_element>> {
public:
    tracker_element_map() :
        tracker_element_core_map<std::unordered_map<int, std::shared_ptr<tracker_element>>, int, std::shared_ptr<tracker_element>>(tracker_type::tracker_map) { }

    tracker_element_map(int id) :
        tracker_element_core_map<std::unordered_map<int, std::shared_ptr<tracker_element>>, int, std::shared_ptr<tracker_element>>(tracker_type::tracker_map, id) { }

    static tracker_type static_type() {
        return tracker_type::tracker_map;
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

    shared_tracker_element get_sub(int id) {
        auto v = map.find(id);

        if (v == map.end())
            return NULL;

        return v->second;
    }

    template<typename T>
    std::shared_ptr<T> get_sub_as(int id) {
        auto v = map.find(id);

        if (v == map.end())
            return NULL;

        return std::static_pointer_cast<T>(v->second);
    }

    std::pair<iterator, bool> insert(shared_tracker_element e) {
        if (e == NULL) 
            throw std::runtime_error("Attempted to insert null tracker_element with no ID");

        auto existing = map.find(e->get_id());

        if (existing == map.end()) {
            auto p = std::make_pair(e->get_id(), e);
            return map.insert(p);
        } else {
            existing->second = e;
            return std::make_pair(existing, true);
        }
    }

    template<typename TE>
    std::pair<iterator, bool> insert(TE e) {
        if (e == NULL) 
            throw std::runtime_error("Attempted to insert null tracker_element with no ID");

        auto existing = map.find(e->get_id());

        if (existing == map.end()) {
            auto p = std::make_pair(e->get_id(), std::static_pointer_cast<tracker_element>(e));
            return map.insert(p);
        } else {
            existing->second = std::static_pointer_cast<tracker_element>(e);
            return std::make_pair(existing, true);
        }
    }

    template<typename TE>
    std::pair<iterator, bool> insert(int i, TE e) {
        auto existing = map.find(i);

        if (existing == map.end()) {
            auto p = 
                std::make_pair(i, std::static_pointer_cast<tracker_element>(e));
            return map.insert(p);
        } else {
            existing->second = std::static_pointer_cast<tracker_element>(e);
            return std::make_pair(existing, true);
        }
    }

    iterator erase(shared_tracker_element e) {
        if (e == nullptr)
            throw std::runtime_error("Attempted to erase null value from map");

        auto i = map.find(e->get_id());

        if (i != map.end())
            return map.erase(i);

        return i;
    }
};

// Int-keyed map
class tracker_element_int_map : public tracker_element_core_map<std::unordered_map<int, std::shared_ptr<tracker_element>>, int, std::shared_ptr<tracker_element>> {
public:
    tracker_element_int_map() :
        tracker_element_core_map<std::unordered_map<int, std::shared_ptr<tracker_element>>, int, std::shared_ptr<tracker_element>>(tracker_type::tracker_int_map) { }

    tracker_element_int_map(int id) :
        tracker_element_core_map<std::unordered_map<int, std::shared_ptr<tracker_element>>, int, std::shared_ptr<tracker_element>>(tracker_type::tracker_int_map, id) { }

    static tracker_type static_type() {
        return tracker_type::tracker_int_map;
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

};

// Hash key compatible map
class tracker_element_hashkey_map : public tracker_element_core_map<std::unordered_map<size_t, std::shared_ptr<tracker_element>>, size_t, std::shared_ptr<tracker_element>> {
public:
    tracker_element_hashkey_map() :
        tracker_element_core_map<std::unordered_map<size_t, std::shared_ptr<tracker_element>>, size_t, std::shared_ptr<tracker_element>>(tracker_type::tracker_hashkey_map) { }

    tracker_element_hashkey_map(int id) :
        tracker_element_core_map<std::unordered_map<size_t, std::shared_ptr<tracker_element>>, size_t, std::shared_ptr<tracker_element>>(tracker_type::tracker_hashkey_map, id) { }

    static tracker_type static_type() {
        return tracker_type::tracker_int_map;
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

};

// Double-keyed map
class tracker_element_double_map : public tracker_element_core_map<std::unordered_map<double, std::shared_ptr<tracker_element>>, double, std::shared_ptr<tracker_element>> {
public:
    tracker_element_double_map() :
        tracker_element_core_map<std::unordered_map<double, std::shared_ptr<tracker_element>>, double, std::shared_ptr<tracker_element>>(tracker_type::tracker_double_map) { }

    tracker_element_double_map(int id) :
        tracker_element_core_map<std::unordered_map<double, std::shared_ptr<tracker_element>>, double, std::shared_ptr<tracker_element>>(tracker_type::tracker_double_map, id) { }

    static tracker_type static_type() {
        return tracker_type::tracker_double_map;
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
};

// Mac-keyed map, MUST be normal std::map to enable mask handling!
class tracker_element_mac_map : public tracker_element_core_map<std::map<mac_addr, std::shared_ptr<tracker_element>>, mac_addr, std::shared_ptr<tracker_element>> {
public:
    tracker_element_mac_map() :
        tracker_element_core_map<std::map<mac_addr, std::shared_ptr<tracker_element>>, mac_addr, std::shared_ptr<tracker_element>>(tracker_type::tracker_mac_map) { }

    tracker_element_mac_map(int id) :
        tracker_element_core_map<std::map<mac_addr, std::shared_ptr<tracker_element>>, mac_addr, std::shared_ptr<tracker_element>>(tracker_type::tracker_mac_map, id) { }

    static tracker_type static_type() {
        return tracker_type::tracker_mac_map;
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
};

// String-keyed map
class tracker_element_string_map : public tracker_element_core_map<std::unordered_map<std::string, std::shared_ptr<tracker_element>>, std::string, std::shared_ptr<tracker_element>> {
public:
    tracker_element_string_map() :
        tracker_element_core_map<std::unordered_map<std::string, std::shared_ptr<tracker_element>>, std::string, std::shared_ptr<tracker_element>>(tracker_type::tracker_string_map) { }

    tracker_element_string_map(int id) :
        tracker_element_core_map<std::unordered_map<std::string, std::shared_ptr<tracker_element>>, std::string, std::shared_ptr<tracker_element>>(tracker_type::tracker_string_map, id) { }

    static tracker_type static_type() {
        return tracker_type::tracker_string_map;
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
};

// Device-key map
class tracker_element_device_key_map : public tracker_element_core_map<std::unordered_map<device_key, std::shared_ptr<tracker_element>>, device_key, std::shared_ptr<tracker_element>> {
public:
    tracker_element_device_key_map() :
        tracker_element_core_map<std::unordered_map<device_key, std::shared_ptr<tracker_element>>, device_key, std::shared_ptr<tracker_element>>(tracker_type::tracker_key_map) { }

    tracker_element_device_key_map(int id) :
        tracker_element_core_map<std::unordered_map<device_key, std::shared_ptr<tracker_element>>, device_key, std::shared_ptr<tracker_element>>(tracker_type::tracker_key_map, id) { }

    static tracker_type static_type() {
        return tracker_type::tracker_key_map;
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
};

// Double::Double map
class tracker_element_double_map_double : public tracker_element_core_map<std::unordered_map<double, double>, double, double> {
public:
    tracker_element_double_map_double() :
        tracker_element_core_map<std::unordered_map<double, double>, double, double>(tracker_type::tracker_double_map_double) { }

    tracker_element_double_map_double(int id) :
        tracker_element_core_map<std::unordered_map<double, double>, double, double>(tracker_type::tracker_double_map_double, id) { }

    static tracker_type static_type() {
        return tracker_type::tracker_double_map_double;
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
};

// Core vector
template<typename T>
class tracker_element_core_vector : public tracker_element {
public:
    using vector_t = std::vector<T>;
    using iterator = typename vector_t::iterator;
    using const_iterator = typename vector_t::const_iterator;

    tracker_element_core_vector() = delete;

    tracker_element_core_vector(tracker_type t) :
        tracker_element(t) { }

    tracker_element_core_vector(tracker_type t, int id) :
        tracker_element(t, id) { }

    tracker_element_core_vector(tracker_type t, int id, const vector_t& init_v) :
        tracker_element(t, id),
        vector{init_v} { }

    virtual void coercive_set(const std::string& in_str) override {
        throw(std::runtime_error("Cannot coercive_set a scalar vector from a string"));
    }

    virtual void coercive_set(double in_num) override {
        throw(std::runtime_error("Cannot coercive_set a scalar vector from a numeric"));
    }

    // Attempt to coerce one complete item to another
    virtual void coercive_set(const shared_tracker_element& in_elem) override {
        throw(std::runtime_error("Cannot coercive_set a scalar vector from an element"));
    }

    virtual void set(const_iterator a, const_iterator b) {
        vector = vector_t(a, b);
    }

    virtual void set(const vector_t& v) {
        vector = vector_t{v};
    }

    vector_t& get() {
        return vector;
    }

    T& at(size_t idx) {
        return vector.at(idx);
    }

    iterator begin() {
        return vector.begin();
    }

    const_iterator cbegin() {
        return vector.cbegin();
    }

    iterator end() {
        return vector.end();
    }

    const_iterator cend() {
        return vector.cend();
    }

    iterator erase(iterator i) {
        return vector.erase(i);
    }

    iterator erase(iterator first, iterator last) {
        return vector.erase(first, last);
    }

    bool empty() const noexcept {
        return vector.empty();
    }

    void clear() noexcept {
        vector.clear();
    }

    void reserve(size_t cap) {
        vector.reserve(cap);
    }

    size_t size() const {
        return vector.size();
    }

    T& operator[](size_t pos) {
        return vector[pos];
    }

    void push_back(const T& v) {
        vector.push_back(v);
    }

    void push_back(const T&& v) {
        vector.push_back(v);
    }

    template<class... Args >
    void emplace_back( Args&&... args ) {
        vector.emplace_back(args...);
    }

protected:
    vector_t vector;
};

class tracker_element_vector : public tracker_element_core_vector<std::shared_ptr<tracker_element>> {
public:
    tracker_element_vector() : 
        tracker_element_core_vector(tracker_type::tracker_vector) { }

    tracker_element_vector(int id) :
        tracker_element_core_vector(tracker_type::tracker_vector, id) { }

    tracker_element_vector(std::shared_ptr<tracker_element_vector> v) :
        tracker_element_core_vector(tracker_type::tracker_vector, v->get_id()) { 
        vector = vector_t(v->begin(), v->end());
    }

    tracker_element_vector(const_iterator a, const_iterator b) :
        tracker_element_core_vector(tracker_type::tracker_vector) { 
        vector = vector_t(a, b);
    }

    tracker_element_vector(tracker_type t, int id, const vector_t& init_v) :
        tracker_element_core_vector(t, id, init_v) { }

    static tracker_type static_type() {
        return tracker_type::tracker_vector;
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
};

class tracker_element_vector_double : public tracker_element_core_vector<double> {
public:
    tracker_element_vector_double() :
        tracker_element_core_vector<double>(tracker_type::tracker_vector_double) { }

    tracker_element_vector_double(int id) :
        tracker_element_core_vector<double>(tracker_type::tracker_vector_double, id) { }

    tracker_element_vector_double(std::shared_ptr<tracker_element_vector_double> v) :
        tracker_element_core_vector(tracker_type::tracker_vector, v->get_id()) { 
        vector = v->vector;
    }

    tracker_element_vector_double(const_iterator a, const_iterator b) :
        tracker_element_core_vector(tracker_type::tracker_vector) { 
        vector = vector_t(a, b);
    }

    tracker_element_vector_double(const vector_t& v) :
        tracker_element_core_vector(tracker_type::tracker_vector) {
        vector = vector_t(v);
    }

    tracker_element_vector_double(tracker_type t, int id, const vector_t& init_v) :
        tracker_element_core_vector(t, id, init_v) { }

    static tracker_type static_type() {
        return tracker_type::tracker_vector_double;
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
};

class tracker_element_vector_string : public tracker_element_core_vector<std::string> {
public:
    tracker_element_vector_string() :
        tracker_element_core_vector<std::string>(tracker_type::tracker_vector_string) { }

    tracker_element_vector_string(int id) :
        tracker_element_core_vector<std::string>(tracker_type::tracker_vector_string, id) { }

    tracker_element_vector_string(std::shared_ptr<tracker_element_vector_string> v) :
        tracker_element_core_vector(tracker_type::tracker_vector, v->get_id()) { 
        vector = v->vector;
    }

    tracker_element_vector_string(const_iterator a, const_iterator b) :
        tracker_element_core_vector(tracker_type::tracker_vector) { 
        vector = vector_t(a, b);
    }

    tracker_element_vector_string(tracker_type t, int id, const vector_t& init_v) :
        tracker_element_core_vector(t, id, init_v) { }

    static tracker_type static_type() {
        return tracker_type::tracker_vector_string;
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
};

// Templated generic access functions

template<typename T> T get_tracker_value(const shared_tracker_element&);
template<> std::string get_tracker_value(const shared_tracker_element& e);
template<> int8_t get_tracker_value(const shared_tracker_element& e);
template<> uint8_t get_tracker_value(const shared_tracker_element& e);
template<> int16_t get_tracker_value(const shared_tracker_element& e);
template<> uint16_t get_tracker_value(const shared_tracker_element& e);
template<> int32_t get_tracker_value(const shared_tracker_element& e);
template<> uint32_t get_tracker_value(const shared_tracker_element& e);
template<> int64_t get_tracker_value(const shared_tracker_element& e);
template<> uint64_t get_tracker_value(const shared_tracker_element& e);
template<> float get_tracker_value(const shared_tracker_element& e);
template<> double get_tracker_value(const shared_tracker_element& e);
template<> mac_addr get_tracker_value(const shared_tracker_element& e);
template<> uuid get_tracker_value(const shared_tracker_element& e);
template<> device_key get_tracker_value(const shared_tracker_element& e);

template<typename T> void set_tracker_value(const shared_tracker_element& e, const T& v);
template<> void set_tracker_value(const shared_tracker_element& e, const std::string& v);
template<> void set_tracker_value(const shared_tracker_element& e, const int8_t& v);
template<> void set_tracker_value(const shared_tracker_element& e, const uint8_t& v);
template<> void set_tracker_value(const shared_tracker_element& e, const int16_t& v);
template<> void set_tracker_value(const shared_tracker_element& e, const uint16_t& v);
template<> void set_tracker_value(const shared_tracker_element& e, const int32_t& v);
template<> void set_tracker_value(const shared_tracker_element& e, const uint32_t& v);
template<> void set_tracker_value(const shared_tracker_element& e, const int64_t& v);
template<> void set_tracker_value(const shared_tracker_element& e, const uint64_t& v);
template<> void set_tracker_value(const shared_tracker_element& e, const float& v);
template<> void set_tracker_value(const shared_tracker_element& e, const double& v);
template<> void set_tracker_value(const shared_tracker_element& e, const mac_addr& v);
template<> void set_tracker_value(const shared_tracker_element& e, const uuid& v);
template<> void set_tracker_value(const shared_tracker_element& e, const device_key& v);

class tracker_element_summary;
using SharedElementSummary =  std::shared_ptr<tracker_element_summary>;

// Element simplification record for summarizing and simplifying records
class tracker_element_summary {
public:
    tracker_element_summary(const std::string& in_path, const std::string& in_rename);

    tracker_element_summary(const std::vector<std::string>& in_path, const std::string& in_rename);

    tracker_element_summary(const std::string& in_path);

    tracker_element_summary(const std::vector<std::string>& in_path);

    tracker_element_summary(const std::vector<int>& in_path, const std::string& in_rename);
    tracker_element_summary(const std::vector<int>& in_path);

    // copy constructor
    tracker_element_summary(const SharedElementSummary& in_c);

    shared_tracker_element parent_element;
    std::vector<int> resolved_path;
    std::string rename;

protected:
    void parse_path(const std::vector<std::string>& in_path, const std::string& in_rename);
};

// Generic serializer class to allow easy swapping of serializers
class tracker_element_serializer {
public:
    tracker_element_serializer() { }

    using rename_map = std::map<shared_tracker_element, SharedElementSummary>;

    virtual ~tracker_element_serializer() {
        local_locker lock(&mutex);
    }

    virtual int serialize(shared_tracker_element in_elem, 
            std::ostream &stream, std::shared_ptr<rename_map> name_map) = 0;

    // Fields extracted from a summary path need to preserialize their parent
    // paths or updates may not happen in the expected fashion, serializers should
    // call this when necessary
    static void pre_serialize_path(const SharedElementSummary& in_summary);
    static void post_serialize_path(const SharedElementSummary& in_summary);
protected:
    kis_recursive_timed_mutex mutex;
};

// Get an element using path semantics
// Full std::string path
shared_tracker_element get_tracker_element_path(const std::string& in_path, shared_tracker_element elem);
// Split std::string path
shared_tracker_element get_tracker_element_path(const std::vector<std::string>& in_path, 
        shared_tracker_element elem);
// Resolved field ID path
shared_tracker_element get_tracker_element_path(const std::vector<int>& in_path, 
        shared_tracker_element elem);

// Get a list of elements from a complex path which may include vectors
// or key maps.  Returns a vector of all elements within that map.
// For example, for a field spec:
// 'dot11.device/dot11.device.advertised.ssid.map/dot11.advertised.ssid'
// it would return a vector of dot11.advertised.ssid for every SSID in
// the dot11.device.advertised.ssid.map keyed map
std::vector<shared_tracker_element> get_tracker_element_multi_path(const std::string& in_path,
        shared_tracker_element elem);
// Split std::string path
std::vector<shared_tracker_element> get_tracker_element_multi_path(const std::vector<std::string>& in_path, 
        shared_tracker_element elem);
// Resolved field ID path
std::vector<shared_tracker_element> get_tracker_element_multi_path(const std::vector<int>& in_path, 
        shared_tracker_element elem);

// Summarize a complex record using a collection of summary elements.  The summarized
// element is returned, and the rename mapping for serialization is updated in rename.
// When passed a vector, returns a vector of simplified objects.
std::shared_ptr<tracker_element> summarize_tracker_element(shared_tracker_element in, 
        const std::vector<SharedElementSummary>& in_summarization, 
        std::shared_ptr<tracker_element_serializer::rename_map> rename_map);

// Summarize a complex record using a collection of summary elements.  The summarized
// element is returned, and the rename mapping for serialization is updated in rename.
// DOES NOT descend into vectors, only performs summarization on the object provided.
std::shared_ptr<tracker_element> summarize_single_tracker_element(shared_tracker_element in, 
        const std::vector<SharedElementSummary>& in_summarization, 
        std::shared_ptr<tracker_element_serializer::rename_map> rename_map);

// Handle comparing fields
bool sort_tracker_element_less(const std::shared_ptr<tracker_element> lhs, 
        const std::shared_ptr<tracker_element> rhs);

// Compare fields, in a faster, but not type-safe, way.  This should be used only when
// the caller is positive that both fields are of the same type, but avoids a number of
// compares.
bool fast_sort_tracker_element_less(const std::shared_ptr<tracker_element> lhs, 
        const std::shared_ptr<tracker_element> rhs) noexcept;

#endif
