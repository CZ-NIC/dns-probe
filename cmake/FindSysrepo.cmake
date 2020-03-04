include(FindPkgConfig)

set(OLD_PKGCFG_ENV $ENV{PKG_CONFIG_PATH})
unset(ENV{PKG_CONFIG_PATH})

foreach(PATH IN LISTS CMAKE_SYSTEM_PREFIX_PATH CMAKE_PREFIX_PATH)
    set(ENV{PKG_CONFIG_PATH} "${PATH}/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")
endforeach()

set(ENV{PKG_CONFIG_PATH} "$ENV{PKG_CONFIG_PATH}:${OLD_PKGCFG_ENV}")
pkg_search_module(SYSREPOCPP IMPORTED_TARGET sysrepo-cpp)
set(ENV{PKG_CONFIG_PATH} "${OLD_PKGCFG_ENV}")

find_package_handle_standard_args(Sysrepo DEFAULT_MSG SYSREPOCPP_FOUND)

find_package(LibYang REQUIRED)

add_library(Sysrepo::Sysrepo INTERFACE IMPORTED)
target_link_libraries(Sysrepo::Sysrepo INTERFACE PkgConfig::SYSREPOCPP LibYang::LibYang)