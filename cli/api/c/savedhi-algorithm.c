// =============================================================================
// Created by Maarten Billemont on 2014-05-05.
// Copyright (c) 2011, Maarten Billemont.
//
// This file is part of savedhi.
// savedhi is free software. You can modify it under the terms of
// the GNU General Public License, either version 3 or any later version.
// See the LICENSE file for details or consult <http://www.gnu.org/licenses/>.
//
// Note: this grant does not include any rights for use of savedhi's trademarks.
// =============================================================================

#include "savedhi-algorithm.h"
#include "savedhi-algorithm_v0.h"
#include "savedhi-algorithm_v1.h"
#include "savedhi-algorithm_v2.h"
#include "savedhi-algorithm_v3.h"
#include "savedhi-util.h"

savedhi_LIBS_BEGIN
#include <string.h>
savedhi_LIBS_END

const savedhiUserKey *savedhi_user_key(
        const char *userName, const char *userSecret, const savedhiAlgorithm algorithmVersion) {

    if (userName && !strlen( userName ))
        userName = NULL;
    if (userSecret && !strlen( userSecret ))
        userSecret = NULL;

    trc( "-- savedhi_user_key (algorithm: %u)", algorithmVersion );
    trc( "userName: %s", userName );
    trc( "userSecret.id: %s", userSecret? savedhi_id_buf( (uint8_t *)userSecret, strlen( userSecret ) ).hex: NULL );
    if (!userName) {
        err( "Missing userName" );
        return NULL;
    }
    if (!userSecret) {
        err( "Missing userSecret" );
        return NULL;
    }

    savedhiUserKey *userKey = memcpy( malloc( sizeof( savedhiUserKey ) ),
            &(savedhiUserKey){ .algorithm = algorithmVersion }, sizeof( savedhiUserKey ) );

    bool success = false;
    switch (algorithmVersion) {
        case savedhiAlgorithmV0:
            success = savedhi_user_key_v0( userKey, userName, userSecret );
            break;
        case savedhiAlgorithmV1:
            success = savedhi_user_key_v1( userKey, userName, userSecret );
            break;
        case savedhiAlgorithmV2:
            success = savedhi_user_key_v2( userKey, userName, userSecret );
            break;
        case savedhiAlgorithmV3:
            success = savedhi_user_key_v3( userKey, userName, userSecret );
            break;
        default:
            err( "Unsupported version: %d", algorithmVersion );
    }

    if (success)
        return userKey;

    savedhi_free( &userKey, sizeof( savedhiUserKey ) );
    return NULL;
}

const savedhiSiteKey *savedhi_site_key(
        const savedhiUserKey *userKey, const char *siteName,
        const savedhiCounter keyCounter, const savedhiKeyPurpose keyPurpose, const char *keyContext) {

    if (keyContext && !strlen( keyContext ))
        keyContext = NULL;
    if (!userKey) {
        err( "Missing userKey" );
        return NULL;
    }
    if (!siteName) {
        err( "Missing siteName" );
        return NULL;
    }

    trc( "-- savedhi_site_key (algorithm: %u)", userKey->algorithm );
    trc( "siteName: %s", siteName );
    trc( "keyCounter: %d", keyCounter );
    trc( "keyPurpose: %d (%s)", keyPurpose, savedhi_purpose_name( keyPurpose ) );
    trc( "keyContext: %s", keyContext );

    savedhiSiteKey *siteKey = memcpy( malloc( sizeof( savedhiSiteKey ) ),
            &(savedhiSiteKey){ .algorithm = userKey->algorithm }, sizeof( savedhiSiteKey ) );

    bool success = false;
    switch (userKey->algorithm) {
        case savedhiAlgorithmV0:
            success = savedhi_site_key_v0( siteKey, userKey, siteName, keyCounter, keyPurpose, keyContext );
            break;
        case savedhiAlgorithmV1:
            success = savedhi_site_key_v1( siteKey, userKey, siteName, keyCounter, keyPurpose, keyContext );
            break;
        case savedhiAlgorithmV2:
            success = savedhi_site_key_v2( siteKey, userKey, siteName, keyCounter, keyPurpose, keyContext );
            break;
        case savedhiAlgorithmV3:
            success = savedhi_site_key_v3( siteKey, userKey, siteName, keyCounter, keyPurpose, keyContext );
            break;
        default:
            err( "Unsupported version: %d", userKey->algorithm );
    }

    if (success)
        return siteKey;

    savedhi_free( &siteKey, sizeof( savedhiSiteKey ) );
    return NULL;
}

const char *savedhi_site_result(
        const savedhiUserKey *userKey, const char *siteName,
        const savedhiResultType resultType, const char *resultParam,
        const savedhiCounter keyCounter, const savedhiKeyPurpose keyPurpose, const char *keyContext) {

    if (keyContext && !strlen( keyContext ))
        keyContext = NULL;
    if (resultParam && !strlen( resultParam ))
        resultParam = NULL;
    if (!userKey) {
        err( "Missing userKey" );
        return NULL;
    }

    const savedhiSiteKey *siteKey = savedhi_site_key( userKey, siteName, keyCounter, keyPurpose, keyContext );
    if (!siteKey) {
        err( "Missing siteKey" );
        return NULL;
    }

    trc( "-- savedhi_site_result (algorithm: %u)", userKey->algorithm );
    trc( "resultType: %d (%s)", resultType, savedhi_type_short_name( resultType ) );
    trc( "resultParam: %s", resultParam );

    const char *result = NULL;
    if (resultType == savedhiResultNone) {
        result = NULL;
    }
    else if (resultType & savedhiResultClassTemplate) {
        switch (userKey->algorithm) {
            case savedhiAlgorithmV0:
                result = savedhi_site_template_password_v0( userKey, siteKey, resultType, resultParam );
                break;
            case savedhiAlgorithmV1:
                result = savedhi_site_template_password_v1( userKey, siteKey, resultType, resultParam );
                break;
            case savedhiAlgorithmV2:
                result = savedhi_site_template_password_v2( userKey, siteKey, resultType, resultParam );
                break;
            case savedhiAlgorithmV3:
                result = savedhi_site_template_password_v3( userKey, siteKey, resultType, resultParam );
                break;
            default:
                err( "Unsupported version: %d", userKey->algorithm );
                break;
        }
    }
    else if (resultType & savedhiResultClassStateful) {
        switch (userKey->algorithm) {
            case savedhiAlgorithmV0:
                result = savedhi_site_crypted_password_v0( userKey, siteKey, resultType, resultParam );
                break;
            case savedhiAlgorithmV1:
                result = savedhi_site_crypted_password_v1( userKey, siteKey, resultType, resultParam );
                break;
            case savedhiAlgorithmV2:
                result = savedhi_site_crypted_password_v2( userKey, siteKey, resultType, resultParam );
                break;
            case savedhiAlgorithmV3:
                result = savedhi_site_crypted_password_v3( userKey, siteKey, resultType, resultParam );
                break;
            default:
                err( "Unsupported version: %d", userKey->algorithm );
                break;
        }
    }
    else if (resultType & savedhiResultClassDerive) {
        switch (userKey->algorithm) {
            case savedhiAlgorithmV0:
                result = savedhi_site_derived_password_v0( userKey, siteKey, resultType, resultParam );
                break;
            case savedhiAlgorithmV1:
                result = savedhi_site_derived_password_v1( userKey, siteKey, resultType, resultParam );
                break;
            case savedhiAlgorithmV2:
                result = savedhi_site_derived_password_v2( userKey, siteKey, resultType, resultParam );
                break;
            case savedhiAlgorithmV3:
                result = savedhi_site_derived_password_v3( userKey, siteKey, resultType, resultParam );
                break;
            default:
                err( "Unsupported version: %d", userKey->algorithm );
                break;
        }
    }
    else {
        err( "Unsupported password type: %d", resultType );
    }

    savedhi_free( &siteKey, sizeof( savedhiSiteKey ) );
    return result;
}

const char *savedhi_site_state(
        const savedhiUserKey *userKey, const char *siteName,
        const savedhiResultType resultType, const char *resultParam,
        const savedhiCounter keyCounter, const savedhiKeyPurpose keyPurpose, const char *keyContext) {

    if (keyContext && !strlen( keyContext ))
        keyContext = NULL;
    if (resultParam && !strlen( resultParam ))
        resultParam = NULL;
    if (!userKey) {
        err( "Missing userKey" );
        return NULL;
    }
    if (!resultParam) {
        err( "Missing resultParam" );
        return NULL;
    }

    const savedhiSiteKey *siteKey = savedhi_site_key( userKey, siteName, keyCounter, keyPurpose, keyContext );
    if (!siteKey) {
        err( "Missing siteKey" );
        return NULL;
    }

    trc( "-- savedhi_site_state (algorithm: %u)", userKey->algorithm );
    trc( "resultType: %d (%s)", resultType, savedhi_type_short_name( resultType ) );
    trc( "resultParam: %zu bytes = %s", resultParam? strlen( resultParam ): 0, resultParam );

    const char *result = NULL;
    if (resultType == savedhiResultNone) {
        result = NULL;
    }
    else {
        switch (userKey->algorithm) {
            case savedhiAlgorithmV0:
                result = savedhi_site_state_v0( userKey, siteKey, resultType, resultParam );
                break;
            case savedhiAlgorithmV1:
                result = savedhi_site_state_v1( userKey, siteKey, resultType, resultParam );
                break;
            case savedhiAlgorithmV2:
                result = savedhi_site_state_v2( userKey, siteKey, resultType, resultParam );
                break;
            case savedhiAlgorithmV3:
                result = savedhi_site_state_v3( userKey, siteKey, resultType, resultParam );
                break;
            default:
                err( "Unsupported version: %d", userKey->algorithm );
                break;
        }
    }

    savedhi_free( &siteKey, sizeof( savedhiSiteKey ) );
    return result;
}

static const char *savedhi_identicon_leftArms[] = { "╔", "╚", "╰", "═" };
static const char *savedhi_identicon_bodies[] = { "█", "░", "▒", "▓", "☺", "☻" };
static const char *savedhi_identicon_rightArms[] = { "╗", "╝", "╯", "═" };
static const char *savedhi_identicon_accessories[] = {
        "◈", "◎", "◐", "◑", "◒", "◓", "☀", "☁", "☂", "☃", "☄", "★", "☆", "☎", "☏", "⎈", "⌂", "☘", "☢", "☣",
        "☕", "⌚", "⌛", "⏰", "⚡", "⛄", "⛅", "☔", "♔", "♕", "♖", "♗", "♘", "♙", "♚", "♛", "♜", "♝", "♞", "♟",
        "♨", "♩", "♪", "♫", "⚐", "⚑", "⚔", "⚖", "⚙", "⚠", "⌘", "⏎", "✄", "✆", "✈", "✉", "✌"
};

const savedhiIdenticon savedhi_identicon(
        const char *userName, const char *userSecret) {

    uint8_t seed[32] = { 0 };
    if (userName && strlen( userName ) && userSecret && strlen( userSecret ))
        if (!savedhi_hash_hmac_sha256( seed,
                (const uint8_t *)userSecret, strlen( userSecret ),
                (const uint8_t *)userName, strlen( userName ) )) {
            savedhi_zero( &seed, sizeof( seed ) );
            return savedhiIdenticonUnset;
        }

    savedhiIdenticon identicon = {
            .leftArm = savedhi_identicon_leftArms[seed[0] % (sizeof( savedhi_identicon_leftArms ) / sizeof( *savedhi_identicon_leftArms ))],
            .body = savedhi_identicon_bodies[seed[1] % (sizeof( savedhi_identicon_bodies ) / sizeof( *savedhi_identicon_bodies ))],
            .rightArm = savedhi_identicon_rightArms[seed[2] % (sizeof( savedhi_identicon_rightArms ) / sizeof( *savedhi_identicon_rightArms ))],
            .accessory = savedhi_identicon_accessories[seed[3] % (sizeof( savedhi_identicon_accessories ) / sizeof( *savedhi_identicon_accessories ))],
            .color = (savedhiIdenticonColor)(seed[4] % (savedhiIdenticonColorLast - savedhiIdenticonColorFirst + 1) + savedhiIdenticonColorFirst),
    };
    savedhi_zero( &seed, sizeof( seed ) );

    return identicon;
}

const char *savedhi_identicon_encode(
        const savedhiIdenticon identicon) {

    if (identicon.color == savedhiIdenticonColorUnset)
        return NULL;

    return savedhi_str( "%hhu:%s%s%s%s",
            identicon.color, identicon.leftArm, identicon.body, identicon.rightArm, identicon.accessory );
}

const savedhiIdenticon savedhi_identicon_encoded(
        const char *encoding) {

    savedhiIdenticon identicon = savedhiIdenticonUnset;
    if (!encoding || !strlen( encoding ))
        return identicon;

    char *string = calloc( strlen( encoding ), sizeof( *string ) ), *parser = string;
    const char *leftArm = NULL, *body = NULL, *rightArm = NULL, *accessory = NULL;
    unsigned int color;

    if (string && sscanf( encoding, "%u:%s", &color, string ) == 2) {
        if (*parser && color)
            for (unsigned int s = 0; s < sizeof( savedhi_identicon_leftArms ) / sizeof( *savedhi_identicon_leftArms ); ++s) {
                const char *limb = savedhi_identicon_leftArms[s];
                if (strncmp( parser, limb, strlen( limb ) ) == 0) {
                    leftArm = limb;
                    parser += strlen( limb );
                    break;
                }
            }
        if (*parser && leftArm)
            for (unsigned int s = 0; s < sizeof( savedhi_identicon_bodies ) / sizeof( *savedhi_identicon_bodies ); ++s) {
                const char *limb = savedhi_identicon_bodies[s];
                if (strncmp( parser, limb, strlen( limb ) ) == 0) {
                    body = limb;
                    parser += strlen( limb );
                    break;
                }
            }
        if (*parser && body)
            for (unsigned int s = 0; s < sizeof( savedhi_identicon_rightArms ) / sizeof( *savedhi_identicon_rightArms ); ++s) {
                const char *limb = savedhi_identicon_rightArms[s];
                if (strncmp( parser, limb, strlen( limb ) ) == 0) {
                    rightArm = limb;
                    parser += strlen( limb );
                    break;
                }
            }
        if (*parser && rightArm)
            for (unsigned int s = 0; s < sizeof( savedhi_identicon_accessories ) / sizeof( *savedhi_identicon_accessories ); ++s) {
                const char *limb = savedhi_identicon_accessories[s];
                if (strncmp( parser, limb, strlen( limb ) ) == 0) {
                    accessory = limb;
                    break;
                }
            }
        if (leftArm && body && rightArm && color >= savedhiIdenticonColorFirst && color <= savedhiIdenticonColorLast)
            identicon = (savedhiIdenticon){
                    .leftArm = leftArm,
                    .body = body,
                    .rightArm = rightArm,
                    .accessory = accessory,
                    .color = (savedhiIdenticonColor)color,
            };
    }

    savedhi_free_string( &string );
    return identicon;
}
