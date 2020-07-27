#Look for an executable
find_program(SPHINX_EXECUTABLE
             NAMES sphinx-build sphinx-build2
             DOC "Path to sphinx-build executable")

include(FindPackageHandleStandardArgs)

#Handle standard arguments to find_package like REQUIRED
find_package_handle_standard_args(Sphinx
                                  DEFAULT_MSG
                                  SPHINX_EXECUTABLE)

mark_as_advanced(SPHINX_EXECUTABLE)