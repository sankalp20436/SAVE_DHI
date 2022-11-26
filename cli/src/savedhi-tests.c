//==============================================================================
// This file is part of savedhi.
// Copyright (c) 2011-2017, Maarten Billemont.
//
// savedhi is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// savedhi is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You can find a copy of the GNU General Public License in the
// LICENSE file.  Alternatively, see <http://www.gnu.org/licenses/>.
//==============================================================================

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sysexits.h>

#ifndef savedhi_log_do
#define savedhi_log_do(level, format, ...) ({ \
    fprintf( stderr, format "\n", ##__VA_ARGS__ ); \
    if (level == ftl_level) \
        abort(); \
})
#endif

#include "savedhi-algorithm.h"
#include "savedhi-util.h"

#include "savedhi-tests-util.h"

/** Output the program's usage documentation. */
static void usage() {

    inf( ""
            "  savedhi v%s - Tests\n"
            "--------------------------------------------------------------------------------\n"
            "      https://savedhi.app\n", stringify_def( savedhi_VERSION ) );
    inf( ""
            "\nUSAGE\n\n"
            "  savedhi-tests [-v|-q]* [-h] [test-name ...]\n" );
    inf( ""
            "  -v           Increase output verbosity (can be repeated).\n"
            "  -q           Decrease output verbosity (can be repeated).\n" );
    inf( ""
            "  -h           Show this help output instead of performing any operation.\n" );
    inf( ""
            "  test-name    Only run tests whose identifier starts with one of the these.\n" );
    exit( EX_OK );
}

int main(int argc, char *const argv[]) {

    for (int opt; (opt = getopt( argc, argv, "vqh" )) != EOF;
         optarg? savedhi_zero( optarg, strlen( optarg ) ): (void)0)
        switch (opt) {
            case 'v':
                ++savedhi_verbosity;
                break;
            case 'q':
                --savedhi_verbosity;
                break;
            case 'h':
                usage();
                break;
            case '?':
                ftl( "Unknown option: -%c", optopt );
                exit( EX_USAGE );
            default:
                ftl( "Unexpected option: %c", opt );
                exit( EX_USAGE );
        }

    int failedTests = 0;

    xmlNodePtr tests = xmlDocGetRootElement( xmlParseFile( "savedhi_tests.xml" ) );
    if (!tests) {
        ftl( "Couldn't find test case: savedhi_tests.xml" );
        abort();
    }

    for (xmlNodePtr testCase = tests->children; testCase; testCase = testCase->next) {
        if (testCase->type != XML_ELEMENT_NODE || xmlStrcmp( testCase->name, BAD_CAST "case" ) != 0)
            continue;

        // Read in the test case.
        xmlChar *id = savedhi_xmlTestCaseString( testCase, "id" );
        savedhiAlgorithm algorithm = (savedhiAlgorithm)savedhi_xmlTestCaseInteger( testCase, "algorithm" );
        xmlChar *userName = savedhi_xmlTestCaseString( testCase, "userName" );
        xmlChar *userSecret = savedhi_xmlTestCaseString( testCase, "userSecret" );
        savedhiKeyID keyID = savedhi_id_str( (char *)savedhi_xmlTestCaseString( testCase, "keyID" ) );
        xmlChar *siteName = savedhi_xmlTestCaseString( testCase, "siteName" );
        savedhiCounter keyCounter = (savedhiCounter)savedhi_xmlTestCaseInteger( testCase, "keyCounter" );
        xmlChar *resultTypeString = savedhi_xmlTestCaseString( testCase, "resultType" );
        xmlChar *resultParam = savedhi_xmlTestCaseString( testCase, "resultParam" );
        xmlChar *keyPurposeString = savedhi_xmlTestCaseString( testCase, "keyPurpose" );
        xmlChar *keyContext = savedhi_xmlTestCaseString( testCase, "keyContext" );
        xmlChar *result = savedhi_xmlTestCaseString( testCase, "result" );

        savedhiResultType resultType = savedhi_type_named( (char *)resultTypeString );
        savedhiKeyPurpose keyPurpose = savedhi_purpose_named( (char *)keyPurposeString );

        // Run the test case.
        do {
            if (optind < argc) {
                bool selected = false;
                for (int a = optind; !selected && a <= argc; ++a)
                    if (strstr((char *)id, argv[optind]) == (char *)id)
                        selected = true;
                if (!selected)
                    break;
            }

            fprintf( stdout, "test case %s... ", id );
            if (!xmlStrlen( result )) {
                fprintf( stdout, "abstract.\n" );
                break;
            }

            // 1. calculate the user key.
            const savedhiUserKey *userKey = savedhi_user_key(
                    (char *)userName, (char *)userSecret, algorithm );
            if (!userKey) {
                ftl( "Couldn't derive user key." );
                break;
            }

            // Check the user key.
            if (!savedhi_id_equals( &keyID, &userKey->keyID )) {
                ++failedTests;
                fprintf( stdout, "FAILED!  (keyID: got %s != expected %s)\n", userKey->keyID.hex, keyID.hex );
                break;
            }

            // 2. calculate the site password.
            const char *testResult = savedhi_site_result(
                    userKey, (char *)siteName, resultType, (char *)resultParam, keyCounter, keyPurpose, (char *)keyContext );
            savedhi_free( &userKey, sizeof( *userKey ) );
            if (!testResult) {
                ftl( "Couldn't derive site password." );
                break;
            }

            // Check the site result.
            if (xmlStrcmp( result, BAD_CAST testResult ) != 0) {
                ++failedTests;
                fprintf( stdout, "FAILED!  (result: got %s != expected %s)\n", testResult, result );
                savedhi_free_string( &testResult );
                break;
            }
            savedhi_free_string( &testResult );

            fprintf( stdout, "pass.\n" );
        } while(false);

        // Free test case.
        xmlFree( id );
        xmlFree( userName );
        xmlFree( userSecret );
        xmlFree( siteName );
        xmlFree( resultTypeString );
        xmlFree( resultParam );
        xmlFree( keyPurposeString );
        xmlFree( keyContext );
        xmlFree( result );
    }

    return failedTests;
}
