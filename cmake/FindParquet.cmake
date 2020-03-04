include(FindPkgConfig)

set(OLD_PKGCFG_ENV $ENV{PKG_CONFIG_PATH})
unset(ENV{PKG_CONFIG_PATH})

foreach(PATH IN LISTS CMAKE_SYSTEM_PREFIX_PATH CMAKE_PREFIX_PATH)
    set(ENV{PKG_CONFIG_PATH} "${PATH}/lib/pkgconfig:${PATH}/lib64/pkgconfig:$ENV{PKG_CONFIG_PATH}")
endforeach()

set(ENV{PKG_CONFIG_PATH} "$ENV{PKG_CONFIG_PATH}:${OLD_PKGCFG_ENV}")
pkg_search_module(PARQUET IMPORTED_TARGET parquet)
set(ENV{PKG_CONFIG_PATH} "${OLD_PKGCFG_PATH}")

find_package_handle_standard_args(Parquet DEFAULT_MSG PARQUET_FOUND)

if(NOT Arrow_FOUND)
    find_package(Arrow REQUIRED)
endif()

add_library(Parquet::Parquet INTERFACE IMPORTED)
target_link_libraries(Parquet::Parquet INTERFACE PkgConfig::PARQUET Arrow::Arrow)
