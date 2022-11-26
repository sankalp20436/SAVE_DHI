### CMAKE
project( savedhi-cli C )
cmake_minimum_required( VERSION 3.0.2 )
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")


### CONFIGURATION
# Features.
option( USE_SODIUM              "Implement crypto functions with sodium (depends on libsodium)." ON )
option( USE_JSON                "Support JSON-based user configuration format (depends on libjson-c)." ON )
option( USE_COLOR               "Colorized identicon (depends on libncurses)." ON )
option( USE_XML                 "XML parsing (depends on libxml2)." ON )

option( BUILD_savedhi           "C CLI version of savedhi (needs: savedhi_sodium, optional: savedhi_color, savedhi_json)." ON )
option( BUILD_savedhi_BENCH     "C CLI savedhi benchmark utility (needs: savedhi_sodium)." OFF )
option( BUILD_savedhi_TESTS     "C savedhi algorithm test suite (needs: savedhi_sodium, savedhi_xml)." OFF )

# Default build flags.
set( CMAKE_BUILD_TYPE           Release )
set( CMAKE_C_FLAGS              "-O3" )

# Version.
find_package( Git )
if( GIT_FOUND )
    execute_process( COMMAND    "${GIT_EXECUTABLE}" describe --match *-cli* --long --dirty
                     OUTPUT_VARIABLE savedhi_version OUTPUT_STRIP_TRAILING_WHITESPACE )
endif()
if( NOT savedhi_version MATCHES "." )
    file( READ                  "VERSION" savedhi_version )
    string( STRIP               "${savedhi_version}" savedhi_version )
endif()
if( savedhi_version MATCHES "." )
    add_definitions(            "-DMP_VERSION=${savedhi_version}" )
    message( STATUS             "Current savedhi source version ${savedhi_version}..." )
else()
    message( STATUS             "Current savedhi source version unknown..." )
endif()


### DEPENDENCIES
function( use_savedhi_sodium t r )
    if( USE_SODIUM )
        set( sodium_USE_STATIC_LIBS ON )
        find_package( sodium )
        if ( sodium_FOUND )
            target_link_libraries( "${t}" PRIVATE sodium )
            target_compile_definitions( "${t}" PRIVATE -Dsavedhi_SODIUM=1 )
            message( STATUS     "${t}: USE_SODIUM is enabled." )

        elseif( r STREQUAL "required" )
            message( FATAL_ERROR "${t}: USE_SODIUM was enabled but is missing libsodium.  Please install this library before continuing." )

        else()
            message( WARNING    "${t}: USE_SODIUM was enabled but is missing libsodium.  Will continue with USE_SODIUM disabled!" )

        endif()

    elseif( r STREQUAL "required" )
        message( FATAL_ERROR    "${t}: USE_SODIUM was required but is not enabled.  Please enable the option or remove this target." )

    else()
        message( STATUS         "${t}: USE_SODIUM is supported but not enabled." )

    endif()
endfunction()

function( use_savedhi_color t )
    if( USE_COLOR )
        find_package( Curses )
        if ( CURSES_FOUND )
            target_include_directories( "${t}" PRIVATE ${CURSES_INCLUDE_DIRS} )
            target_link_libraries( "${t}" PRIVATE ${CURSES_LIBRARIES} )
            target_compile_definitions( "${t}" PRIVATE -Dsavedhi_COLOR=1 ${CURSES_CFLAGS} )
            message( STATUS     "${t}: USE_COLOR is enabled." )

        elseif( r STREQUAL "required" )
            message( FATAL_ERROR "${t}: USE_COLOR was enabled but is missing libcurses.  Please install this library before continuing." )

        else()
            message( WARNING    "${t}: USE_COLOR was enabled but is missing libcurses.  Will continue with USE_COLOR disabled!" )

        endif()

    elseif( r STREQUAL "required" )
        message( FATAL_ERROR    "${t}: USE_COLOR was required but is not enabled.  Please enable the option or remove this target." )

    else()
        message( STATUS         "${t}: USE_COLOR is supported but not enabled." )

    endif()
endfunction()

function( use_savedhi_json t )
    if( USE_JSON )
        find_package( json-c )
        if ( json-c_FOUND )
            target_link_libraries( "${t}" PRIVATE json-c::json-c-static )
            target_compile_definitions( "${t}" PRIVATE -Dsavedhi_JSON=1 )
            message( STATUS     "${t}: USE_JSON is enabled." )

        elseif( r STREQUAL "required" )
            message( FATAL_ERROR "${t}: USE_JSON was enabled but is missing libjson-c.  Please install this library before continuing." )

        else()
            message( WARNING    "${t}: USE_JSON was enabled but is missing libjson-c.  Will continue with USE_JSON disabled!" )

        endif()

    elseif( r STREQUAL "required" )
        message( FATAL_ERROR    "${t}: USE_JSON was required but is not enabled.  Please enable the option or remove this target." )

    else()
        message( STATUS         "${t}: USE_JSON is supported but not enabled." )

    endif()
endfunction()

function( use_savedhi_xml t r )
    find_package( LibXml2 )
    if( USE_XML )
        if ( LIBXML2_FOUND )
            target_link_libraries( "${t}" PRIVATE LibXml2::LibXml2 )
            target_compile_definitions( "${t}" PRIVATE -Dsavedhi_XML=1 )
            message( STATUS     "${t}: USE_XML is enabled." )

        elseif( r STREQUAL "required" )
            message( FATAL_ERROR "${t}: USE_XML was enabled but is missing libxml2.  Please install this library before continuing." )

        else()
            message( WARNING    "${t}: USE_XML was enabled but is missing libxml2.  Will continue with USE_XML disabled!" )

        endif()

    elseif( r STREQUAL "required" )
        message( FATAL_ERROR    "${t}: USE_XML was required but is not enabled.  Please enable the option or remove this target." )

    else()
        message( STATUS         "${t}: USE_XML is supported but not enabled." )

    endif()
endfunction()


### TARGET: savedhi
if( BUILD_savedhi )
    # target
    add_executable( savedhi "api/c/aes.c" "api/c/savedhi-algorithm.c"
                        "api/c/savedhi-algorithm_v0.c" "api/c/savedhi-algorithm_v1.c" "api/c/savedhi-algorithm_v2.c" "api/c/savedhi-algorithm_v3.c"
                        "api/c/savedhi-types.c" "api/c/savedhi-util.c" "api/c/savedhi-marshal-util.c" "api/c/savedhi-marshal.c"
                        "src/savedhi-cli-util.c" "src/savedhi-cli.c" )
    target_include_directories( savedhi PUBLIC api/c src )
    install( TARGETS savedhi RUNTIME DESTINATION bin )

    # dependencies
    use_savedhi_sodium( savedhi required )
    use_savedhi_color( savedhi optional )
    use_savedhi_json( savedhi optional )
endif()


### TARGET: savedhi-BENCH
if( BUILD_savedhi_BENCH )
    # target
    add_executable( savedhi-bench "api/c/aes.c" "api/c/savedhi-algorithm.c"
                              "api/c/savedhi-algorithm_v0.c" "api/c/savedhi-algorithm_v1.c" "api/c/savedhi-algorithm_v2.c" "api/c/savedhi-algorithm_v3.c"
                              "api/c/savedhi-types.c" "api/c/savedhi-util.c" "src/savedhi-bench.c" )
    target_include_directories( savedhi-bench PUBLIC api/c src )
    install( TARGETS savedhi-bench RUNTIME DESTINATION bin )

    # dependencies
    use_savedhi_sodium( savedhi-bench required )
endif()


### TARGET: savedhi-TESTS
if( BUILD_savedhi_TESTS )
    # target
    add_executable( savedhi-tests "api/c/aes.c" "api/c/savedhi-algorithm.c"
                              "api/c/savedhi-algorithm_v0.c" "api/c/savedhi-algorithm_v1.c" "api/c/savedhi-algorithm_v2.c" "api/c/savedhi-algorithm_v3.c"
                              "api/c/savedhi-types.c" "api/c/savedhi-util.c" "src/savedhi-tests-util.c" "src/savedhi-tests.c" )
    target_include_directories( savedhi-tests PUBLIC api/c src )
    install( TARGETS savedhi-tests RUNTIME DESTINATION bin )

    # dependencies
    use_savedhi_sodium( savedhi-tests required )
    use_savedhi_xml( savedhi-tests required )
endif()
