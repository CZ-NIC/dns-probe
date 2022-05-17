find_package(PkgConfig REQUIRED)
set(OLD_PKGCFG_ENV $ENV{PKG_CONFIG_PATH})
unset(ENV{PKG_CONFIG_PATH})

foreach(PATH IN LISTS CMAKE_SYSTEM_PREFIX_PATH CMAKE_PREFIX_PATH)
    set(ENV{PKG_CONFIG_PATH} "${PATH}/lib/pkgconfig:${PATH}/lib64/pkgconfig:$ENV{PKG_CONFIG_PATH}")
endforeach()

set(ENV{PKG_CONFIG_PATH} "$ENV{PKG_CONFIG_PATH}:${OLD_PKGCFG_ENV}")
pkg_search_module(DPDK libdpdk)
set(ENV{PKG_CONFIG_PATH} "${OLD_PKGCFG_PATH}")

find_package_handle_standard_args(DPDK DEFAULT_MSG DPDK_FOUND)
