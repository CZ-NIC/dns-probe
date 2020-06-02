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
#include <sstream>
#include <stdexcept>
#include <algorithm>
#include <cstring>
#include <sstream>
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
     * Specialized implementation for DDP::ExportLocation as config item.
     */
    template<>
    class ConfigItem<ExportLocation> : public ConfigItemBase
    {
    public:
        /**
         * Access saved value.
         * @return Value inside config item.
         */
        [[nodiscard]] ExportLocation value() const { return m_value; }

        bool validate(const std::any& value) const override
        {
            try {
                auto str_value = std::any_cast<std::string>(value);
                std::transform(str_value.begin(), str_value.end(), str_value.begin(), toupper);
                return str_value == "LOCAL" || str_value == "REMOTE";
            } catch(...) {
                return false;
            }
        }

        /**
         * Save value from sysrepo.
         * @param value Value from sysrepo
         */
        void from_sysrepo(const std::any& value) override
        {
            auto str_value = std::any_cast<std::string>(value);
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
     * Specialized implementation for DDP::ExportIpVersion as config item.
     */
    template<>
    class ConfigItem<ExportIpVersion> : public ConfigItemBase
    {
    public:
        /**
         * Access saved value.
         * @return Value inside config item.
         */
        [[nodiscard]] ExportIpVersion value() const { return m_value; }

        bool validate(const std::any& value) const override
        {
            try {
                auto str_value = std::any_cast<std::string>(value);
                std::transform(str_value.begin(), str_value.end(), str_value.begin(), toupper);
                return str_value == "UNKNOWN" || str_value == "IPV4" || str_value == "IPV6";
            } catch (...) {
                return false;
            }
        }

        /**
         * Save value from sysrepo.
         * @param value Value from sysrepo.
         */
        void from_sysrepo(const std::any& value) override
        {
            auto str_value = std::any_cast<std::string>(value);
            std::transform(str_value.begin(), str_value.end(), str_value.begin(), toupper);

            if (str_value == "UNKNOWN")
                m_value = ExportIpVersion::UNKNOWN;
            else if (str_value == "IPV4")
                m_value = ExportIpVersion::IPV4;
            else if (str_value == "IPV6")
                m_value = ExportIpVersion::IPV6;
            else
                throw std::invalid_argument("Invalid argument for ExportIpVersion: " + str_value);
        }

        /**
         * Implicit conversion to ExportIpVersion.
         * @return Saved value.
         */
        operator ExportIpVersion() { return m_value; }

        /**
         * Provides text representation of the saved value.
         * @return String containing text representation of the value.
         */
        std::string string() const override
        {
            if (m_value == ExportIpVersion::IPV4)
                return {"IPv4"};
            else if (m_value == ExportIpVersion::IPV6)
                return {"IPv6"};
            else
                return {"UNKNOWN"};
        }

    protected:
        ExportIpVersion m_value{ExportIpVersion::UNKNOWN}; //!< Saved value.
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
}