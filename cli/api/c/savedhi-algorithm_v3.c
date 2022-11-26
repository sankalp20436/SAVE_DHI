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

#include "savedhi-algorithm_v3.h"
#include "savedhi-util.h"

savedhi_LIBS_BEGIN
#include <string.h>
#include <errno.h>
savedhi_LIBS_END

#define savedhi_N                32768LU
#define savedhi_r                8U
#define savedhi_p                2U
#define savedhi_otp_window       5 * 60 /* s */

// Algorithm version overrides.
bool savedhi_user_key_v3(
        const savedhiUserKey *userKey, const char *userName, const char *userSecret) {

    const char *keyScope = savedhi_purpose_scope( savedhiKeyPurposeAuthentication );
    trc( "keyScope: %s", keyScope );

    // Calculate the user key salt.
    trc( "userKeySalt: keyScope=%s | #userName=%s | userName=%s",
            keyScope, savedhi_hex_l( (uint32_t)strlen( userName ), (char[9]){ 0 } ), userName );
    size_t userKeySaltSize = 0;
    uint8_t *userKeySalt = NULL;
    if (!(savedhi_buf_push( &userKeySalt, &userKeySaltSize, keyScope ) &&
          savedhi_buf_push( &userKeySalt, &userKeySaltSize, (uint32_t)strlen( userName ) ) &&
          savedhi_buf_push( &userKeySalt, &userKeySaltSize, userName )) || !userKeySalt) {
        savedhi_free( &userKeySalt, userKeySaltSize );
        err( "Could not allocate user key salt: %s", strerror( errno ) );
        return false;
    }
    trc( "  => userKeySalt.id: %s", savedhi_id_buf( userKeySalt, userKeySaltSize ).hex );

    // Calculate the user key.
    trc( "userKey: scrypt( userSecret, userKeySalt, N=%lu, r=%u, p=%u )", savedhi_N, savedhi_r, savedhi_p );
    bool success = savedhi_kdf_scrypt( (uint8_t *)userKey->bytes, sizeof( userKey->bytes ),
            (uint8_t *)userSecret, strlen( userSecret ), userKeySalt, userKeySaltSize, savedhi_N, savedhi_r, savedhi_p );
    savedhi_free( &userKeySalt, userKeySaltSize );

    if (!success)
        err( "Could not derive user key: %s", strerror( errno ) );
    else {
        savedhiKeyID keyID = savedhi_id_buf( userKey->bytes, sizeof( userKey->bytes ) );
        memcpy( (savedhiKeyID *)&userKey->keyID, &keyID, sizeof( userKey->keyID ) );
        trc( "  => userKey.id: %s (algorithm: %d:3)", userKey->keyID.hex, userKey->algorithm );
    }
    return success;
}

bool savedhi_site_key_v3(
        const savedhiSiteKey *siteKey, const savedhiUserKey *userKey, const char *siteName,
        savedhiCounter keyCounter, savedhiKeyPurpose keyPurpose, const char *keyContext) {

    return savedhi_site_key_v2( siteKey, userKey, siteName, keyCounter, keyPurpose, keyContext );
}

const char *savedhi_site_template_password_v3(
        const savedhiUserKey *userKey, const savedhiSiteKey *siteKey, savedhiResultType resultType, const char *resultParam) {

    return savedhi_site_template_password_v2( userKey, siteKey, resultType, resultParam );
}

const char *savedhi_site_crypted_password_v3(
        const savedhiUserKey *userKey, const savedhiSiteKey *siteKey, savedhiResultType resultType, const char *cipherText) {

    return savedhi_site_crypted_password_v2( userKey, siteKey, resultType, cipherText );
}

const char *savedhi_site_derived_password_v3(
        const savedhiUserKey *userKey, const savedhiSiteKey *siteKey, savedhiResultType resultType, const char *resultParam) {

    return savedhi_site_derived_password_v2( userKey, siteKey, resultType, resultParam );
}

const char *savedhi_site_state_v3(
        const savedhiUserKey *userKey, const savedhiSiteKey *siteKey, savedhiResultType resultType, const char *state) {

    return savedhi_site_state_v2( userKey, siteKey, resultType, state );
}
