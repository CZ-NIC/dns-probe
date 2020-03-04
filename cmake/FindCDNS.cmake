include(FindPkgConfig)

set(OLD_PKGCFG_ENV $ENV{PKG_CONFIG_PATH})
unset(ENV{PKG_CONFIG_PATH})

foreach(PATH IN LISTS CMAKE_SYSTEM_PREFIX_PATH CMAKE_PREFIX_PATH)
    set(ENV{PKG_CONFIG_PATH} "${PATH}/lib/pkgconfig:${PATH}/lib64/pkgconfig:$ENV{PKG_CONFIG_PATH}")
endforeach()

set(ENV{PKG_CONFIG_PATH} "$ENV{PKG_CONFIG_PATH}:${OLD_PKGCFG_ENV}")
pkg_search_module(CDNS IMPORTED_TARGET cdns)
set(ENV{PKG_CONFIG_PATH} "${OLD_PKGCFG_ENV}")

find_package_handle_standard_args(CDNS DEFAULT_MSG CDNS_FOUND)

add_library(CDNS::CDNS INTERFACE IMPORTED)
target_link_libraries(CDNS::CDNS INTERFACE PkgConfig::CDNS)
