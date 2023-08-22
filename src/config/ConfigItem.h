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
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations including
 *  the two.
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
         * Method used for extraction from configuration file. Given value is passed as boost::any.
         * Actual implementation should convert boost::any into appropriate type.
         * @param value Value from configuration file.
         */
        virtual void add_value(const boost::any& value) = 0;

        /**
         * Deletes given value from config item. Used mainly for deleting values from lists.
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
         * Check if given value from configuration file can be used in config.
         * @param value Checked valued from configuration file.
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
         * @brief Constructors
         */
        ConfigItem() {};
        ConfigItem(Type value) : m_value(value) {};

        /**
         * Access saved value.
         * @return Value inside config item.
         */
        Type value() const { return m_value; }

        /**
         * Save value from configuration file.
         * @param value Value from configuration file.
         */
        void add_value(const boost::any& value) override
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
         * @brief Constructors
         */
        ConfigItem(){};
        ConfigItem(PcapExportCfg value) : m_value(value) {};

        /**
         * Access saved value.
         * @return Value inside config item.
         */
        PcapExportCfg value() const { return m_value; }

        /**
         * Check if given value from configuration file can be used in config.
         * @param value Checked valued from configuration file.
         * @return True if value is valid otherwise false.
         */
        bool validate(const boost::any& value) const override
        {
            try {
                auto str_value = boost::any_cast<std::string>(value);
                std::transform(str_value.begin(), str_value.end(), str_value.begin(), toupper);
                return str_value == "DISABLED" || str_value == "INVALID" || str_value == "ALL";
            } catch (std::exception& e) {
                return false;
            }
        }

        /**
         * Save value from configuration file.
         * @param value Value from configuration file.
         */
        void add_value(const boost::any& value) override
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
         * @brief Constructors
         */
        ConfigItem(){};
        ConfigItem(ExportFormat value) : m_value(value) {};

        /**
         * Access saved value.
         * @return Value inside config item.
         */
        ExportFormat value() const { return m_value; }

        /**
         * Check if given value from configuration file can be used in config.
         * @param value Checked valued from configuration file.
         * @return True if value is valid otherwise false.
         */
        bool validate(const boost::any& value) const override
        {
            try {
                auto str_value = boost::any_cast<std::string>(value);
                std::transform(str_value.begin(), str_value.end(), str_value.begin(), toupper);
                return str_value == "PARQUET" || str_value == "CDNS";
            } catch (std::exception& e) {
                return false;
            }
        }

        /**
         * Save value from configuration file.
         * @param value Value from configuration file.
         */
        void add_value(const boost::any& value) override
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
         * @brief Constructors
         */
        ConfigItem(){};
        ConfigItem(Type value) : m_value(value) {};

        /**
         * Access saved value.
         * @return Value inside config item.
         */
        Type value() const { return m_value; }

        /**
         * Save value from configuration file.
         * @param value Value from configuration file.
         */
        void add_value(const boost::any& value) override
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
     * Specialized implementation for DDP::ExportLocation as config item.
     */
    template<>
    class ConfigItem<ExportLocation> : public ConfigItemBase
    {
    public:
        /**
         * @brief Constructors
         */
        ConfigItem(){};
        ConfigItem(ExportLocation value) : m_value(value) {};

        /**
         * Access saved value.
         * @return Value inside config item.
         */
        ExportLocation value() const { return m_value; }

        bool validate(const boost::any& value) const override
        {
            try {
                auto str_value = boost::any_cast<std::string>(value);
                std::transform(str_value.begin(), str_value.end(), str_value.begin(), toupper);
                return str_value == "LOCAL" || str_value == "REMOTE";
            } catch(...) {
                return false;
            }
        }

        /**
         * Save value from configuration file.
         * @param value Value from configuration file
         */
        void add_value(const boost::any& value) override
        {
            auto str_value = boost::any_cast<std::string>(value);
            std::transform(str_value.begin(), str_value.end(), str_value.begin(), toupper);

            if (str_value == "LOCAL")
                m_value = ExportLocation::LOCAL;
            else if (str_value == "REMOTE")
                m_value = ExportLocation::REMOTE;
            else
                throw std::invalid_argument("Invalid argument for ExportLocation");
        }

        /**
         * Implicit conversion to ExportLocation.
         * @return Saved value.
         */
        operator ExportLocation() { return m_value; }

        /**
         * Provides text representation of the saved value.
         * @return String containing text representation of the value.
         */
        std::string string() const override
        {
            if (m_value == ExportLocation::LOCAL)
                return {"LOCAL"};
            else
                return {"REMOTE"};
        }

    protected:
        ExportLocation m_value{ExportLocation::LOCAL}; //!< Saved value.
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
         * @brief Constructors
         */
        ConfigBitfield(){}
        ConfigBitfield(size_t value) : m_value(value) {}

        /**
         * Access saved value.
         * @return Value inside config item.
         */
        Type value() const { return m_value; }

        /**
         * Save value from configuration file.
         * @param value Value from configuration file.
         */
        void add_value(const boost::any& value) override
        {
            m_value = boost::any_cast<std::bitset<size>>(value);
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
     * Specialized implementation for DDP::IpEncryption as config item.
     */
    template<>
    class ConfigItem<IpEncryption>: public ConfigItemBase
    {
    public:
        /**
         * @brief Constructors
         */
        ConfigItem(){};
        ConfigItem(IpEncryption value) : m_value(value) {};

        /**
         * Access saved value.
         * @return Value inside config item.
         */
        IpEncryption value() const { return m_value; }

        /**
         * Check if given value from configuration file can be used in config.
         * @param value Checked valued from configuration file.
         * @return True if value is valid otherwise false.
         */
        bool validate(const boost::any& value) const override
        {
            try {
                auto str_value = boost::any_cast<std::string>(value);
                std::transform(str_value.begin(), str_value.end(), str_value.begin(), toupper);
                return str_value == "AES" || str_value == "BLOWFISH" || str_value == "MD5" || str_value == "SHA1";
            } catch (std::exception& e) {
                return false;
            }
        }

        /**
         * Save value from configuration file.
         * @param value Value from configuration file.
         */
        void add_value(const boost::any& value) override
        {
            auto str_value = boost::any_cast<std::string>(value);
            std::transform(str_value.begin(), str_value.end(), str_value.begin(), toupper);

            if(str_value == "AES")
                m_value = IpEncryption::AES;
            else if(str_value == "BLOWFISH")
                m_value = IpEncryption::BLOWFISH;
            else if(str_value == "MD5")
                m_value = IpEncryption::MD5;
            else if(str_value == "SHA1")
                m_value = IpEncryption::SHA1;
            else
                throw std::invalid_argument("Invalid argument for IpEncryption");
        }

        /**
         * Implicit conversion to IpEncryption.
         * @return Saved value.
         */
        operator IpEncryption() { return m_value; }

        /**
         * Provides text representation of the saved value.
         * @return String containing text representation of the value.
         */
        std::string string() const override
        {
            if (m_value == IpEncryption::NONE)
                return {"NONE"};
            else if (m_value == IpEncryption::AES)
                return {"AES"};
            else if (m_value == IpEncryption::BLOWFISH)
                return {"BLOWFISH"};
            else if (m_value == IpEncryption::MD5)
                return {"MD5"};
            else if (m_value == IpEncryption::SHA1)
                return {"SHA1"};
            else
                return {"NONE"};
        }


    protected:
        IpEncryption m_value{IpEncryption::NONE}; //!< Saved value.
    };

    /**
     * Specialized implementation for DDP::CList<port_t> as config item.
     */
    template<>
    class ConfigItem<CList<Port_t>>: public ConfigItemBase
    {
    public:
        /**
         * @brief Constructors
         */
        ConfigItem(){};
        ConfigItem(CList<Port_t> value) : m_value(value) {};

        /**
         * Access saved value.
         * @return Value inside config item.
         */
        CList<Port_t> value() const { return m_value; }

        /**
         * Save value from configuration file.
         * @param value Value from configuration file.
         */
        void add_value(const boost::any& value) override
        {
            m_value.insert(boost::any_cast<Port_t>(value));
        }

        /**
         * Delete value from list.
         * @param value Value from configuration file to delete.
         */
        void delete_value(const boost::any& value) override
        {
            m_value.erase(boost::any_cast<Port_t>(value));
        }

        /**
         * Implicit conversion to CList<port_t>.
         * @return Saved value.
         */
        operator CList<Port_t>() { return m_value; }

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
        CList<Port_t> m_value{}; //!< Saved value.
    };


    /**
     * Specialized implementation for DDP::CList<ipv4_t> as config item.
     */
    template<>
    class ConfigItem<CList<IPv4_t>>: public ConfigItemBase
    {
    public:
        /**
         * @brief Constructors
         */
        ConfigItem(){};
        ConfigItem(CList<IPv4_t> value) : m_value(value) {};

        /**
         * Access saved value.
         * @return Value inside config item.
         */
        CList<IPv4_t> value() const { return m_value; }

        /**
         * Save value from configuration file.
         * @param value Value from configuration file.
         */
        void add_value(const boost::any& value) override
        {
            IPv4_t addr;
            int ret = inet_pton(AF_INET, boost::any_cast<std::string>(value).c_str(), &addr);
            if (ret != 1)
                throw std::invalid_argument("IPv4 list doesn't contain valid IPv4 address.");
            m_value.insert(addr);
        }

        /**
         * Delete value from list.
         * @param value Value from configuration file to delete.
         */
        void delete_value(const boost::any& value) override
        {
            IPv4_t addr;
            int ret = inet_pton(AF_INET, boost::any_cast<std::string>(value).c_str(), &addr);
            if (ret != 1)
                throw std::invalid_argument("IPv4 list doesnt't contain valid IPv4 address to delete.");
            m_value.erase(addr);
        }

        /**
         * Implicit conversion to CList<ipv4_t>
         * @return Save value.
         */
        operator CList<IPv4_t>() const { return m_value; }

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
        CList<IPv4_t> m_value{}; //!< Saved value.
    };
}

namespace DDP {
    /**
     * Specialized implementation for DDP::CList<ipv6_t> as config item.
     */
    template<>
    class ConfigItem<CList<IPv6_t>>: public ConfigItemBase
    {
    public:
        /**
         * @brief Constructors
         */
        ConfigItem() : m_value() {};
        ConfigItem(CList<IPv6_t> value) : m_value(value) {};

        /**
         * Access saved value.
         * @return Value inside config item.
         */
        CList<IPv6_t> value() const { return m_value; }

        /**
         * Save value from configuration file.
         * @param value Value from configuration file.
         */
        void add_value(const boost::any& value) override
        {
            IPv6_t addr;
            int ret = inet_pton(AF_INET6, boost::any_cast<std::string>(value).c_str(), &addr);
            if (ret != 1)
                throw std::invalid_argument("IPv6 list doesn't contain valid IPv6 address.");
            m_value.insert(addr);
        }

        /**
         * Delete value from list.
         * @param value Value from configuration file to delete.
         */
        void delete_value(const boost::any& value) override
        {
            IPv6_t addr;
            int ret = inet_pton(AF_INET6, boost::any_cast<std::string>(value).c_str(), &addr);
            if (ret != 1)
                throw std::invalid_argument("IPv6 list doesnt' contain valid IPv6 address to delete.");
            m_value.erase(addr);
        }

        /**
         * Implicit conversion to CList<ipv6_t>
         * @return Save value.
         */
        operator CList<IPv6_t>() const { return m_value; }

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
                auto* ret = inet_ntop(AF_INET6, &val, buff, INET6_ADDRSTRLEN + 4);
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
        CList<IPv6_t> m_value{}; //!< Saved value.
    };

    /**
     * Specialized implementation for DDP::CList<ipv4_prefix_t> as config item.
     */
    template<>
    class ConfigItem<CList<IPv4_prefix_t>>: public ConfigItemBase
    {
    public:
        /**
         * @brief Constructors
         */
        ConfigItem(){};
        ConfigItem(CList<IPv4_prefix_t> value) : m_value(value) {};

        /**
         * Access saved value.
         * @return Value inside config item.
         */
        CList<IPv4_prefix_t> value() const { return m_value; }

        /**
         * Save value from configuration file.
         * @param value Value from configuration file.
         */
        void add_value(const boost::any& value) override
        {
            m_value.insert(parse_ipv4(boost::any_cast<std::string>(value)));
        }

        /**
         * Delete value from list.
         * @param value Value from configuration file to delete.
         */
        void delete_value(const boost::any& value) override
        {
            m_value.erase(parse_ipv4(boost::any_cast<std::string>(value)));
        }

        /**
         * Implicit conversion to CList<ipv4_prefix_t>
         * @return Save value.
         */
        operator CList<IPv4_prefix_t>() const { return m_value; }

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
                auto* ret = inet_ntop(AF_INET, &(val.ip), buff, INET_ADDRSTRLEN + 4);
                if (!ret)
                    continue;

                auto mask = val.mask;
                uint8_t prefix = 0;
                // Brian Kernighan's algorithm to count set bits. The number of loops is equal
                // to bits set in integer.
                while (mask) {
                    mask &= (mask - 1);
                    prefix++;
                }

                if (first) {
                    str << buff << "/" << std::to_string(prefix);
                    first = false;
                }
                else
                    str << ", " << buff << "/" << std::to_string(prefix);
            }
            return str.str();
        }
    protected:
        IPv4_prefix_t parse_ipv4(const std::string& str) {
            IPv4_prefix_t addr;

            auto pos = str.find_last_of('/');
            if (pos == std::string::npos) {
                // full IP address
                int ret = inet_pton(AF_INET, str.c_str(), &(addr.ip));
                if (ret != 1)
                    throw std::invalid_argument("Invalid IPv4 address in IPv4 list..");

                std::memset(&(addr.mask), UINT8_MAX, sizeof(addr.mask));
            }
            else {
                // subnet with mask
                int ret = inet_pton(AF_INET, str.substr(0, pos).c_str(), &(addr.ip));
                if (ret != 1)
                    throw std::invalid_argument("Invalid IPv4 address in IPv4 list.");

                auto mask = std::stoul(str.substr(pos + 1));
                if (mask > 32)
                    throw std::invalid_argument("IPv4 address with invalid mask in IPv4 list.");

                addr.mask = 0;
                for (unsigned i = 0; i < mask; i++) {
                    addr.mask |= (1 << i);
                }

                // mask the IP subnet so we don't have to do it for every comparison with packet IP
                addr.ip &= addr.mask;
            }

            return addr;
        }

        CList<IPv4_prefix_t> m_value{}; //!< Saved value.
    };

    /**
     * Specialized implementation for DDP::CList<ipv6_prefix_t> as config item.
     */
    template<>
    class ConfigItem<CList<IPv6_prefix_t>>: public ConfigItemBase
    {
    public:
        /**
         * @brief Constructors
         */
        ConfigItem() : m_value() {};
        ConfigItem(CList<IPv6_prefix_t> value) : m_value(value) {};

        /**
         * Access saved value.
         * @return Value inside config item.
         */
        CList<IPv6_prefix_t> value() const { return m_value; }

        /**
         * Save value from configuration file.
         * @param value Value from configuration file.
         */
        void add_value(const boost::any& value) override
        {
            m_value.insert(parse_ipv6(boost::any_cast<std::string>(value)));
        }

        /**
         * Delete value from list.
         * @param value Value from configuration file to delete.
         */
        void delete_value(const boost::any& value) override
        {
            m_value.erase(parse_ipv6(boost::any_cast<std::string>(value)));
        }

        /**
         * Implicit conversion to CList<ipv6_prefix_t>
         * @return Save value.
         */
        operator CList<IPv6_prefix_t>() const { return m_value; }

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
                auto* ret = inet_ntop(AF_INET6, &(val.ip), buff, INET6_ADDRSTRLEN + 4);
                if (!ret)
                    continue;

                uint8_t prefix = 0;
                for (unsigned i = 0; i < 4; i++) {
                    uint32_t chunk = val.ip.s6_addr32[i];
                    // Brian Kernighan's algorithm to count set bits. The number of loops is equal
                    // to bits set in integer.
                    while (chunk) {
                        chunk &= (chunk - 1);
                        prefix++;
                    }
                }

                if (first) {
                    str << buff << "/" << std::to_string(prefix);
                    first = false;
                }
                else
                    str << ", " << buff << "/" << std::to_string(prefix);
            }
            return str.str();
        }
    protected:
        IPv6_prefix_t parse_ipv6(const std::string& str) {
            IPv6_prefix_t addr;

            auto pos = str.find_last_of('/');
            if (pos == std::string::npos) {
                // full IP address
                int ret = inet_pton(AF_INET6, str.c_str(), &(addr.ip));
                if (ret != 1)
                    throw std::invalid_argument("Invalid IPv6 address in IPv6 list.");

                std::memset(&(addr.mask), UINT8_MAX, sizeof(addr.mask));
            }
            else {
                // subnet with mask
                int ret = inet_pton(AF_INET6, str.substr(0, pos).c_str(), &(addr.ip));
                if (ret != 1)
                    throw std::invalid_argument("Invalid IPv6 address in IPv6 list.");

                auto mask = std::stoul(str.substr(pos + 1));
                if (mask > 128)
                    throw std::invalid_argument("IPv6 address with invalid mask in IPv6 list.");

                std::memset(&(addr.mask), 0, sizeof(addr.mask));
                for (uint8_t i = 0; i < sizeof(addr.mask.s6_addr); i++) {
                    addr.mask.s6_addr[i] = static_cast<uint8_t>(~0) << (8 - (mask > 8 ? 8 : mask));
                    mask = mask >= 8 ? mask - 8 : 0;
                }

                // mask the IP subnet so we don't have to do it for every comparision with packet IP
                addr.ip.s6_addr32[0] &= addr.mask.s6_addr32[0];
                addr.ip.s6_addr32[1] &= addr.mask.s6_addr32[1];
                addr.ip.s6_addr32[2] &= addr.mask.s6_addr32[2];
                addr.ip.s6_addr32[3] &= addr.mask.s6_addr32[3];
            }

            return addr;
        }

        CList<IPv6_prefix_t> m_value{}; //!< Saved value.
    };

    /**
     * Specialized implementation for DDP::CList<std::string> as config item.
     */
    template<>
    class ConfigItem<CList<std::string>>: public ConfigItemBase
    {
    public:
        /**
         * @brief Constructors
         */
        ConfigItem(){};
        ConfigItem(CList<std::string> value) : m_value(value) {};

        /**
         * Access saved value.
         * @return Value inside config item.
         */
        CList<std::string> value() const { return m_value; }

        /**
         * Save value from configuration file.
         * @param value Value from configuration file.
         */
        void add_value(const boost::any& value) override
        {
            m_value.insert(boost::any_cast<std::string>(value));
        }

        /**
         * Delete value from list.
         * @param value Value from configuration to delete.
         */
        void delete_value(const boost::any& value) override
        {
            m_value.erase(boost::any_cast<std::string>(value));
        }

        /**
         * Implicit conversion to CList<std::string>
         * @return Save value.
         */
        operator CList<std::string>() { return m_value; }

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
                    str << val;
                    first = false;
                }
                else
                    str << ", " << val;
            }
            return str.str();
        }
    protected:
        CList<std::string> m_value{}; //!< Saved value.
    };
}
