/*
 *  Copyright (C) 2025 CZ.NIC, z. s. p. o.
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

#include <iostream>
#include <fstream>
#include <sys/stat.h>
#include <sys/types.h>
#include <zlib.h>

#include "JsonWriter.h"
#include "utils/Logger.h"


/**
 * @brief Base class for writing data to output
 */
class DDP::JsonWriter::BaseSink
{
    public:
    explicit BaseSink(const std::string& filename) : m_filename(filename) {}
    virtual ~BaseSink() = default;
    virtual void rotate_output(const std::string& filename) = 0;
    virtual int64_t write(const char* data, std::size_t size) = 0;

    protected:
    std::string m_filename;
};

/**
 * @brief Class that writes data to uncompressed local file
 */
class FileSink : public DDP::JsonWriter::BaseSink
{
    public:
    /**
     * @brief Construct a new FileSink object, open new local file
     * @param filename Name of the output file
     */
    explicit FileSink(const std::string& filename) : BaseSink(filename) { open(); }

    /**
     * @brief Destroy the FileSink object, close current local file
     */
    ~FileSink() { close(); }

    /**
     * @brief Close current output file and open a new one
     * @param filename Name of the output file
     */
    void rotate_output(const std::string& filename) override {
        close();
        m_filename = filename;
        open();
    }

    /**
     * @brief Write size bytes to output file
     * @param data Pointer to start of data to write to output
     * @param size Size of data to write in bytes
     * @return Number of bytes written to output
     */
    int64_t write(const char* data, std::size_t size) override {
        m_out.write(data, size);
        if (!m_out)
            throw std::runtime_error("File write failed!");

        return size;
    }

    private:
    /**
     * @brief Open output file
     */
    void open() {
        m_out.open(m_filename + ".part");
        if (m_out.fail())
            throw std::runtime_error("Couldn't open output file " + m_filename + ".part!");
    }

    /**
     * @brief Close output file
     */
    void close() {
        if (m_out.is_open()) {
            m_out.flush();
            m_out.close();
            std::rename((m_filename + ".part").c_str(), m_filename.c_str());
        }
    }

    std::ofstream m_out;
};

/**
 * @brief Class that writes data to GZIP compressed local file
 * 
 */
class GzipFileSink : public DDP::JsonWriter::BaseSink
{
    public:
    /**
     * @brief Construct a new GzipFileSink object, open new local file
     * @param filename Name of the output file
     */
    explicit GzipFileSink(const std::string& filename) : BaseSink(filename), m_out(nullptr) { open(); }

    /**
     * @brief Destroy the GzipFileSink object, close current local file
     */
    ~GzipFileSink() { close(); }

    /**
     * @brief Close current output file and open a new one
     * @param filename Name of the output file
     */
    void rotate_output(const std::string& filename) override {
        close();
        m_filename = filename;
        open();
    }

    /**
     * @brief Write size bytes to output file and compress it with GZIP
     * @param data Pointer to start of data to compress and write to output
     * @param size Size of data to compress and write in bytes
     * @return Number of uncompressed bytes written to output
     */
    int64_t write(const char* data, std::size_t size) override {
        auto ret = gzwrite(m_out, data, size);
        if (ret == 0)
            throw std::runtime_error("File write failed!");

        return ret;
    }

    private:
    /**
     * @brief Open GZIP file
     */
    void open() {
        m_out = gzopen((m_filename + ".part").c_str(), "wb");
        if (!m_out)
            throw std::runtime_error("Couldn't open output file " + m_filename + ".part!");
    }

    /**
     * @brief Close GZIP file
     */
    void close() {
        if (m_out) {
            gzclose(m_out);
            std::rename((m_filename + ".part").c_str(), m_filename.c_str());
        }
    }

    gzFile m_out;
};

DDP::JsonWriter::JsonWriter(Config& cfg, uint32_t process_id)
    : BaseWriter(cfg, process_id, TlsCtxIndex::TRAFFIC, cfg.file_compression.value() ? ".gz" : ""),
    m_bytes_written(0), m_records_exported(0)
{
    m_filename = filename("json", false);
    m_filename += m_sufix;

    if (m_cfg.file_compression.value()) {
        m_sink = std::make_unique<GzipFileSink>(m_filename);
    }
    else
        m_sink = std::make_unique<FileSink>(m_filename);

    load_unsent_files_list();
}


DDP::JsonWriter::~JsonWriter()
{
    m_sink = nullptr;

    try {
        struct stat buffer;
        if (m_bytes_written == 0 && stat(m_filename.c_str(), &buffer) == 0)
            remove(m_filename.c_str());
        else {
            chmod(m_filename.c_str(), 0666);
            if (m_cfg.export_location.value() == ExportLocation::REMOTE) {
                if (!std::rename(m_filename.c_str(), (m_filename + ".part").c_str())) {
                    m_threads.emplace_back(std::async(std::launch::async, send_file,
                                            TlsCtxIndex::TRAFFIC, m_cfg.export_ip.value(),
                                            m_cfg.export_port.value(), m_cfg.backup_export_ip.value(),
                                            m_cfg.backup_export_port.value(), m_filename, ".part",
                                            DEFAULT_TRIES));
                    m_sending_files.insert(m_filename);
                }
            }
#ifdef PROBE_KAFKA
            else if (m_cfg.export_location.value() == ExportLocation::KAFKA) {
                if (!std::rename(m_filename.c_str(), (m_filename + ".part").c_str())) {
                    m_threads.emplace_back(std::async(std::launch::async, send_file_to_kafka, m_cfg.kafka_export,
                                            m_filename, ".part", true));
                    m_sending_files.insert(m_filename);
                }
            }
#endif
        }

        cleanup();
    }
    catch (std::exception& e) {
        Logger("Writer").warning() << "Destructor error: " << e.what();
    }
}

int64_t DDP::JsonWriter::write(std::shared_ptr<std::vector<rapidjson::StringBuffer>> item)
{
    if (item == nullptr)
        return 0;

    for (auto& record : *item) {
        m_bytes_written += m_sink->write(record.GetString(), record.GetSize());
        m_bytes_written += m_sink->write("\n", 1);
        m_records_exported++;
    }

    return item->size();
}

void DDP::JsonWriter::rotate_output()
{
    std::string rotated = m_filename;
    m_filename = filename("json", false);
    m_filename += m_sufix;
    m_sink->rotate_output(m_filename);

    struct stat buffer;
    if (m_bytes_written == 0 && stat(rotated.c_str(), &buffer) == 0) {
        remove(rotated.c_str());
        if (m_cfg.export_location.value() == ExportLocation::REMOTE ||
            m_cfg.export_location.value() == ExportLocation::KAFKA)
            check_file_transfer();
    }
    else {
        chmod(rotated.c_str(), 0666);
        if (m_cfg.export_location.value() == ExportLocation::REMOTE) {
            if (std::rename(rotated.c_str(), (rotated + ".part").c_str()))
                throw std::runtime_error("Couldn't rename the output file!");

            check_file_transfer();
            m_threads.emplace_back(std::async(std::launch::async, send_file, m_type,
                m_cfg.export_ip.value(), m_cfg.export_port.value(), m_cfg.backup_export_ip.value(),
                m_cfg.backup_export_port.value(), rotated, ".part", DEFAULT_TRIES));
            m_sending_files.insert(rotated);
        }
#ifdef PROBE_KAFKA
        else if (m_cfg.export_location.value() == ExportLocation::KAFKA) {
            if (std::rename(rotated.c_str(), (rotated + ".part").c_str()))
                throw std::runtime_error("Couldn't rename the output file!");

            check_file_transfer();
            m_threads.emplace_back(std::async(std::launch::async, send_file_to_kafka, m_cfg.kafka_export,
                rotated, ".part", true));
            m_sending_files.insert(rotated);
        }
#endif
    }

    m_bytes_written = 0;
    m_records_exported = 0;
}