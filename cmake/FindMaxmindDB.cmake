# - Try to find libmaxminddb include dirs and libraries
#
# Usage of this module as follows:
#
#     find_package(MaxmindDB)
#
# Variables used by this module, they can change the default behaviour and need
# to be set before calling find_package:
#
#  MAXMINDDB_ROOT_DIR        Set this variable to the root installation of
#                            libmaxminddb if the module has problems finding the
#                            proper installation path.
#
# Variables defined by this module:
#
#  MAXMINDDB_FOUND                System has libmaxminddb, include and library dirs found
#  MAXMINDDB_INCLUDE_DIR          The libmaxminddb include directories.
#  MAXMINDDB_LIBRARY              The libmaxminddb library

find_path(MAXMINDDB_ROOT_DIR NAMES maxminddb.h HINTS include/*/)
find_path(MAXMINDDB_INCLUDE_DIR NAMES maxminddb.h HINTS ${MAXMINDDB_ROOT_DIR}/include/*/)
find_library(MAXMINDDB_LIBRARY NAMES maxminddb HINTS ${MAXMINDDB_ROOT_DIR}/lib/*/ ${MAXMINDDB_ROOT_DIR}/lib64/*/)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(MaxmindDB DEFAULT_MSG MAXMINDDB_ROOT_DIR MAXMINDDB_LIBRARY)

mark_as_advanced(
        MAXMINDDB_ROOT_DIR
        MAXMINDDB_INCLUDE_DIR
        MAXMINDDB_LIBRARY
)

if(MaxmindDB_FOUND)
    add_library(MaxmindDB::MaxmindDB INTERFACE IMPORTED)
    set_property(TARGET MaxmindDB::MaxmindDB PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${MAXMINDDB_INCLUDE_DIR})
    set_property(TARGET MaxmindDB::MaxmindDB PROPERTY INTERFACE_LINK_LIBRARIES ${MAXMINDDB_LIBRARY})
endif()
