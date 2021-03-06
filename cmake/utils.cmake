function(FindLibrary library target)
    find_package(PkgConfig REQUIRED)
    set(OLD_PKGCFG_ENV $ENV{PKG_CONFIG_PATH})
    unset(ENV{PKG_CONFIG_PATH})

    foreach(PATH IN LISTS CMAKE_SYSTEM_PREFIX_PATH CMAKE_PREFIX_PATH)
        set(ENV{PKG_CONFIG_PATH} "${PATH}/lib/pkgconfig:${PATH}/lib64/pkgconfig:$ENV{PKG_CONFIG_PATH}")
    endforeach()

    set(ENV{PKG_CONFIG_PATH} "$ENV{PKG_CONFIG_PATH}:${OLD_PKGCFG_ENV}")
    pkg_search_module(${library} ${library})
    set(ENV{PKG_CONFIG_PATH} "${OLD_PKGCFG_PATH}")

    find_package_handle_standard_args(${target} DEFAULT_MSG ${library}_FOUND)
    if (${library}_FOUND)
        set(property_target "${target}::${target}")
        add_library(${property_target} INTERFACE IMPORTED)
        set_property(TARGET ${property_target} PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${${library}_INCLUDE_DIRS})
        set(LIBRARIES)
        foreach(LIB ${${library}_LIBRARIES})
            find_library(${LIB}_PATH ${LIB})
            list(APPEND LIBRARIES ${${LIB}_PATH})
        endforeach()
        set_property(TARGET ${property_target} PROPERTY INTERFACE_LINK_LIBRARIES ${LIBRARIES})
        set_property(TARGET ${property_target} PROPERTY INTERFACE_COMPILE_DEFINITIONS ${${library}_DEFINITIONS})
        set_property(TARGET ${property_target} PROPERTY INTERFACE_COMPILE_OPTIONS ${${library}_CFLAGS})
    endif()
endfunction()