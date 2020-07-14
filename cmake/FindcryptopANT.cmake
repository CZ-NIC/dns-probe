# - Try to find libcryptopANT include dirs and libraries
#
# Usage of this module as follows:
#
#     find_package(cryptopANT)
#
# Variables used by this module, they can change the default behaviour and need
# to be set before calling find_package:
#
#  cryptopANT_ROOT_DIR       Set this variable to the root installation of
#                            libcryptopANT if the module has problems finding the
#                            proper installation path.
#
# Variables defined by this module:
#
#  cryptopANT_FOUND                System has libcryptopANT, include and library dirs found
#  cryptopANT_INCLUDE_DIR          The libcryptopANT include directories.
#  cryptopANT_LIBRARY              The libcryptopANT library

find_path(cryptopANT_ROOT_DIR NAMES include/cryptopANT.h)
find_path(cryptopANT_INCLUDE_DIR NAMES cryptopANT.h HINTS ${cryptopANT_ROOT_DIR}/include)
find_library(cryptopANT_LIBRARY NAMES cryptopANT HINTS ${cryptopANT_ROOT_DIR}/lib)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(cryptopANT DEFAULT_MSG cryptopANT_ROOT_DIR)

mark_as_advanced(
        cryptopANT_ROOT_DIR
        cryptopANT_INCLUDE_DIR
        cryptopANT_LIBRARY
)

if(cryptopANT_FOUND)
    add_library(cryptopANT::cryptopANT INTERFACE IMPORTED)
    set_property(TARGET cryptopANT::cryptopANT PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${cryptopANT_INCLUDE_DIR})
    set_property(TARGET cryptopANT::cryptopANT PROPERTY INTERFACE_LINK_LIBRARIES ${cryptopANT_LIBRARY})
endif()
