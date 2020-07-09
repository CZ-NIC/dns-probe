/*
 *  Copyright (C) 2018 Brno University of Technology
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <string>
#include <vector>
#include <unordered_set>
#include <array>
#include <sstream>
#include <stdexcept>
#include <algorithm>
#include <cstring>
#include <sstream>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <boost/any.hpp>
#include <type_traits>
#include <sysrepo-cpp/Session.hpp>

#include "ConfigTypes.h"
#include "platform/ThreadManager.h"


namespace DDP {

    /**
     * Base class for config items.
     */
    class ConfigItemBase
    {
    public:
        virtual ~ConfigItemBase() = default;
        /**
         * Method used for extraction from sysrepo. Given value is passed as boost::any. Actual implementation should
         * convert boost::any into appropriate type.
         * @param value Value from sysrepo.
         */
        virtual void from_sysrepo(const boost::any& value) = 0;

        /**
         * Deletes given value from config item. Used mainly for deleting values from leaf-list.
         * @param value Value to delete from config item.
         */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
        virtual void delete_value(const boost::any& value) {}
#pragma GCC diagnostic pop

        /**
         * Provides text representation of the saved value.
         * @return String containing text representation of the value.
         */
        virtual std::string string() const = 0;

        /**
         * Check if given value from sysrepo can be used in config.
         * @param value Checked valued from sysrepo.
         * @return True if value is valid otherwise false.
         */
        virtual bool validate(const boost::any&) const { return true; }
    };

    /**
     * Template for mainly POD types for config items.
     * @tparam Type
     */
    template<typename Type>
    class ConfigItem : public ConfigItemBase
    {
    public:
        /**
         * Access saved value.
         * @return Value inside config item.
         */
        Type value() const { return m_value; }

        /**
         * Save value from sysrepo.
         * @param value Value from sysrepo.
         */
        void from_sysrepo(const boost::any& value) override
        {
            m_value = boost::any_cast<Type>(value);
        }

        /**
         * Implicit conversion to holding type.
         * @return Saved value.
         */
        operator Type() const { return m_value; }

        /**
         * Provides text representation of the saved value.
         * @return String containing text representation of the value.
         */
        std::string string() const override
        {
            std::stringstream str;
            str << m_value;
            return str.str();
        }

    protected:
        Type m_value{}; //!< Saved value.
    };

    /**
     * Specialized implementation for DDP::PcapExportCfg as config item.
     */
    template<>
    class ConfigItem<PcapExportCfg> : public ConfigItemBase
    {
    public:
        /**
         * Access saved value.
         * @return Value inside config item.
         */
        PcapExportCfg value() const { return m_value; }

        bool validate(const boost::any& value) const override
        {
            try {
                auto str_value = boost::any_cast<std::string>(value);
                std::transform(str_value.begin(), str_value.end(), str_value.begin(), toupper);
                return str_value == "DISABLED" || str_value == "INVALID" || str_value == "ALL";
            } catch (...) {
                return false;
            }
        }

        /**
         * Save value from sysrepo.
         * @param value Value from sysrepo.
         */
        void from_sysrepo(const boost::any& value) override
        {
            auto str_value = boost::any_cast<std::string>(value);
            std::transform(str_value.begin(), str_value.end(), str_value.begin(), toupper);

            if(str_value == "DISABLED")
                m_value = PcapExportCfg::DISABLED;
            else if(str_value == "INVALID")
                m_value = PcapExportCfg::INVALID;
            else if(str_value == "ALL")
                m_value = PcapExportCfg::ALL;
            else
                throw std::invalid_argument("Invalid argument for PcapExportCfg");
        }

        /**
         * Implicit conversion to PcapExportCfg.
         * @return Saved value.
         */
        operator PcapExportCfg() { return m_value; }

        /**
         * Provides text representation of the saved value.
         * @return String containing text representation of the value.
         */
        std::string string() const override
        {
            if (m_value == PcapExportCfg::DISABLED)
                return {"DISABLED"};
            else if (m_value == PcapExportCfg::INVALID)
                return {"INVALID"};
            else
                return {"ALL"};
        }

    protected:
        PcapExportCfg m_value{PcapExportCfg::DISABLED}; //!< Saved value.
    };

    /**
     * Specialized implementation for DDP::ExportFormat as config item.
     */
    template<>
    class ConfigItem<ExportFormat> : public ConfigItemBase
    {
    public:
        /**
         * Access saved value.
         * @return Value inside config item.
         */
        ExportFormat value() const { return m_value; }

        bool validate(const boost::any& value) const override
        {
            try {
                auto str_value = boost::any_cast<std::string>(value);
                std::transform(str_value.begin(), str_value.end(), str_value.begin(), toupper);
                return str_value == "PARQUET" || str_value == "CDNS";
            } catch (...) {
                return false;
            }
        }

        /**
         * Save value from sysrepo.
         * @param value Value from sysrepo.
         */
        void from_sysrepo(const boost::any& value) override
        {
            auto str_value = boost::any_cast<std::string>(value);
            std::transform(str_value.begin(), str_value.end(), str_value.begin(), toupper);

            if(str_value == "PARQUET")
                m_value = ExportFormat::PARQUET;
            else if(str_value == "CDNS")
                m_value = ExportFormat::CDNS;
            else
                throw std::invalid_argument("Invalid argument for ExportFormat");
        }

        /**
         * Implicit conversion to ExportFormat.
         * @return Saved value.
         */
        operator ExportFormat() { return m_value; }

        /**
         * Provides text representation of the saved value.
         * @return String containing text representation of the value.
         */
        std::string string() const override
        {
            if (m_value == ExportFormat::PARQUET)
                return {"PARQUET"};
            else
                return {"CDNS"};
        }


    protected:
        ExportFormat m_value{ExportFormat::PARQUET}; //!< Saved value.
    };


    /**
     * Specialized implementation for DDP::ThreadManager::MaskType as config item.
     */
    template<>
    class ConfigItem<ThreadManager::MaskType>: public ConfigItemBase
    {
        using Type = ThreadManager::MaskType;
    public:

        /**
         * Access saved value.
         * @return Value inside config item.
         */
        Type value() const { return m_value; }

        /**
         * Save value from sysrepo.
         * @param value Value from sysrepo.
         */
        void from_sysrepo(const boost::any& value) override
        {
            m_value = boost::any_cast<uint64_t>(value);
        }

        /**
         * Implicit conversion to ThreadManager::MaskType.
         * @return Saved value.
         */
        operator Type() const { return m_value; }

        /**
         * Provides text representation of the saved value.
         * @return String containing text representation of the value.
         */
        std::string string() const override
        {
            std::stringstream str;
            str << "0x" << std::hex << m_value.to_ullong();
            return str.str();
        }

    protected:
        Type m_value{0x7}; //!< Saved value.
    };

    /**
     * Specialized implementation for std::bitset as config item.
     */
    template<size_t size>
    class ConfigBitfield: public ConfigItemBase
    {
        using Type = std::bitset<size>;
    public:

        /**
         * Access saved value.
         * @return Value inside config item.
         */
        Type value() const { return m_value; }

        /**
         * Save value from sysrepo.
         * @param value Value from sysrepo.
         */
        void from_sysrepo(const boost::any& value) override
        {
            auto bit_field = boost::any_cast<std::vector<libyang::S_Type_Bit>>(value);
            if(bit_field.size() != size)
                throw std::invalid_argument("Bitfield contains unexpected count of bits!");

            m_value.reset();

            for(decltype(bit_field.size()) i = 0; i < bit_field.size(); i++) {
                m_value.set(i, static_cast<bool>(bit_field[i]));
            }
        }

        /**
         * Implicit conversion to ConfigBitfield.
         * @return Saved value.
         */
        operator Type() const { return m_value; }

        /**
         * Provides text representation of the saved value.
         * @return String containing text representation of the value.
         */
        std::string string() const override
        {
            std::stringstream str;
            str << "0x" << std::hex << m_value.to_ullong();
            return str.str();
        }

    protected:
        Type m_value{0x0}; //!< Saved value.
    };

    /**
     * Specialized implementation for std::unordered_set<uint16_t> as config item.
     */
    class ConfigPortList: public ConfigItemBase
    {
        using Type = std::unordered_set<uint16_t>;
    public:
        /**
         * Access saved value.
         * @return Value inside config item.
         */
        Type value() const { return m_value; }

        /**
         * Save value from sysrepo.
         * @param value Value from sysrepo.
         */
        void from_sysrepo(const boost::any& value) override
        {
            m_value.insert(boost::any_cast<uint16_t>(value));
        }

        /**
         * Delete value from list.
         * @param value Value from syrepo to delete.
         */
        void delete_value(const boost::any& value) override
        {
            m_value.erase(boost::any_cast<uint16_t>(value));
        }

        /**
         * Implicit conversion to PortList.
         * @return Saved value.
         */
        operator Type() const { return m_value; }

        /**
         * Provides text representation of the saved value.
         * @return String containing text representation of the value.
         */
        std::string string() const override
        {
            std::stringstream str;
            bool first = true;
            for (auto& val : m_value) {
                if (first) {
                    str << std::to_string(val);
                    first = false;
                }
                else
                    str << ", " << std::to_string(val);
            }
            return str.str();
        }

    protected:
        Type m_value{}; //!< Saved value.
    };

    /**
     * Specialized implementation for std::unordered_set<uint32_t> as config item.
     */
    class ConfigIPv4List: public ConfigItemBase
    {
        using Type = std::unordered_set<uint32_t>;
    public:
        /**
         * Access saved value.
         * @return Value inside config item.
         */
        Type value() const { return m_value; }

        /**
         * Save value from sysrepo.
         * @param value Value from sysrepo.
         */
        void from_sysrepo(const boost::any& value) override
        {
            uint32_t addr;
            int ret = inet_pton(AF_INET, boost::any_cast<std::string>(value).c_str(), &addr);
            if (ret != 1)
                throw std::invalid_argument("IPv4 list doesn't contain valid IPv4 address.");
            m_value.insert(addr);
        }

        /**
         * Delete value from list.
         * @param value Value from syrepo to delete.
         */
        void delete_value(const boost::any& value) override
        {
            uint32_t addr;
            int ret = inet_pton(AF_INET, boost::any_cast<std::string>(value).c_str(), &addr);
            if (ret != 1)
                throw std::invalid_argument("IPv4 list doesn't contain valid IPv4 address to delete.");
            m_value.erase(addr);
        }

        /**
         * Implicit conversion to IPv4List
         * @return Save value.
         */
        operator Type() const { return m_value; }

        /**
         * Provides text representation of the saved value.
         * @return String containing text representation of the value.
         */
        std::string string() const override
        {
            std::stringstream str;
            bool first = true;
            for (auto& val : m_value) {
                char buff[INET_ADDRSTRLEN + 4];
                auto* ret = inet_ntop(AF_INET, &val, buff, INET_ADDRSTRLEN + 4);
                if (!ret)
                    continue;
                if (first) {
                    str << buff;
                    first = false;
                }
                else
                    str << ", " << buff;
            }
            return str.str();
        }

    protected:
        Type m_value{}; //!< Saved value.
    };
}

/**
 * Hash function for std::array.
 * Used for storing IPv6 addresses as std::array<uint32_t, 4> in std::unordered_set.
 */
namespace std {
    template<typename T, size_t N>
    struct hash<array<T, N>>
    {
        size_t operator()(const array<T, N>& a) const
        {
            hash<T> hasher;
            size_t h = 0;
            for (size_t i = 0; i < N; ++i)
            {
                h = h * 31 + hasher(a[i]);
            }
            return h;
        }
    };
}

namespace DDP {
    /**
     * Specialized implementation for std::unordered_set<std::array<uint32_t, 4>> as config item.
     */
    class ConfigIPv6List: public ConfigItemBase
    {
        using Type = std::unordered_set<std::array<uint32_t, 4>>;
    public:
        /**
         * Access saved value.
         * @return Value inside config item.
         */
        Type value() const { return m_value; }

        /**
         * Save value from sysrepo.
         * @param value Value from sysrepo.
         */
        void from_sysrepo(const boost::any& value) override
        {
            std::array<uint32_t, 4> addr;
            int ret = inet_pton(AF_INET6, boost::any_cast<std::string>(value).c_str(), addr.data());
            if (ret != 1)
                throw std::invalid_argument("IPv6 list doesn't contain valid IPv6 address.");
            m_value.insert(addr);
        }

        /**
         * Delete value from list.
         * @param value Value from syrepo to delete.
         */
        void delete_value(const boost::any& value) override
        {
            std::array<uint32_t, 4> addr;
            int ret = inet_pton(AF_INET6, boost::any_cast<std::string>(value).c_str(), addr.data());
            if (ret != 1)
                throw std::invalid_argument("IPv6 list doesn't contain valid IPv6 address to delete.");
            m_value.erase(addr);
        }

        /**
         * Implicit conversion to IPv6List
         * @return Save value.
         */
        operator Type() const { return m_value; }

        /**
         * Provides text representation of the saved value.
         * @return String containing text representation of the value.
         */
        std::string string() const override
        {
            std::stringstream str;
            bool first = true;
            for (auto& val : m_value) {
                char buff[INET6_ADDRSTRLEN + 4];
                auto* ret = inet_ntop(AF_INET6, val.data(), buff, INET6_ADDRSTRLEN + 4);
                if (!ret)
                    continue;
                if (first) {
                    str << buff;
                    first = false;
                }
                else
                    str << ", " << buff;
            }
            return str.str();
        }

    protected:
        Type m_value{}; //!< Saved value.
    };
}
