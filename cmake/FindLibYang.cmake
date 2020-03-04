include(FindPkgConfig)

set(OLD_PKGCFG_ENV $ENV{PKG_CONFIG_PATH})
unset(ENV{PKG_CONFIG_PATH})

foreach(PATH IN LISTS CMAKE_SYSTEM_PREFIX_PATH CMAKE_PREFIX_PATH)
    set(ENV{PKG_CONFIG_PATH} "${PATH}/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")
endforeach()

set(ENV{PKG_CONFIG_PATH} "$ENV{PKG_CONFIG_PATH}:${OLD_PKGCFG_ENV}")
pkg_search_module(LIBYANG IMPORTED_TARGET libyang)
pkg_search_module(LIBYANGCPP IMPORTED_TARGET libyang-cpp)
set(ENV{PKG_CONFIG_PATH} "${OLD_PKGCFG_ENV}")

find_package_handle_standard_args(LibYang DEFAULT_MSG SYSREPO_FOUND)

add_library(LibYang::LibYang INTERFACE IMPORTED)
target_link_libraries(LibYang::LibYang INTERFACE PkgConfig::LIBYANG PkgConfig::LIBYANGCPP)