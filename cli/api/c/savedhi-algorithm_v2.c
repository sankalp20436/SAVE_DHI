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

#include "savedhi-algorithm_v2.h"
#include "savedhi-util.h"

savedhi_LIBS_BEGIN
#include <string.h>
#include <errno.h>
#include <time.h>
savedhi_LIBS_END

#define savedhi_N                32768LU
#define savedhi_r                8U
#define savedhi_p                2U
#define savedhi_otp_window       5 * 60 /* s */

// Algorithm version overrides.
bool savedhi_user_key_v2(
        const savedhiUserKey *userKey, const char *userName, const char *userSecret) {

    return savedhi_user_key_v1( userKey, userName, userSecret );
}

bool savedhi_site_key_v2(
        const savedhiSiteKey *siteKey, const savedhiUserKey *userKey, const char *siteName,
        savedhiCounter keyCounter, savedhiKeyPurpose keyPurpose, const char *keyContext) {

    const char *keyScope = savedhi_purpose_scope( keyPurpose );
    trc( "keyScope: %s", keyScope );

    // OTP counter value.
    if (keyCounter == savedhiCounterTOTP)
        keyCounter = ((savedhiCounter)time( NULL ) / savedhi_otp_window) * savedhi_otp_window;

    // Calculate the site seed.
    trc( "siteSalt: keyScope=%s | #siteName=%s | siteName=%s | keyCounter=%s | #keyContext=%s | keyContext=%s",
            keyScope, savedhi_hex_l( (uint32_t)strlen( siteName ), (char[9]){ 0 } ), siteName, savedhi_hex_l( keyCounter, (char[9]){ 0 } ),
            keyContext? savedhi_hex_l( (uint32_t)strlen( keyContext ), (char[9]){ 0 } ): NULL, keyContext );
    size_t siteSaltSize = 0;
    uint8_t *siteSalt = NULL;
    if (!(savedhi_buf_push( &siteSalt, &siteSaltSize, keyScope ) &&
          savedhi_buf_push( &siteSalt, &siteSaltSize, (uint32_t)strlen( siteName ) ) &&
          savedhi_buf_push( &siteSalt, &siteSaltSize, siteName ) &&
          savedhi_buf_push( &siteSalt, &siteSaltSize, (uint32_t)keyCounter ) &&
          (!keyContext? true:
           savedhi_buf_push( &siteSalt, &siteSaltSize, (uint32_t)strlen( keyContext ) ) &&
           savedhi_buf_push( &siteSalt, &siteSaltSize, keyContext ))) || !siteSalt) {
        err( "Could not allocate site salt: %s", strerror( errno ) );
        return false;
    }
    trc( "  => siteSalt.id: %s", savedhi_id_buf( siteSalt, siteSaltSize ).hex );

    trc( "siteKey: hmac-sha256( userKey.id=%s, siteSalt )", userKey->keyID.hex );
    bool success = savedhi_hash_hmac_sha256( (uint8_t *)siteKey->bytes,
            userKey->bytes, sizeof( userKey->bytes ), siteSalt, siteSaltSize );
    savedhi_free( &siteSalt, siteSaltSize );

    if (!success)
        err( "Could not derive site key: %s", strerror( errno ) );
    else {
        savedhiKeyID keyID = savedhi_id_buf( siteKey->bytes, sizeof( siteKey->bytes ) );
        memcpy( (savedhiKeyID *)&siteKey->keyID, &keyID, sizeof( siteKey->keyID ) );
        trc( "  => siteKey.id: %s (algorithm: %d:2)", siteKey->keyID.hex, siteKey->algorithm );
    }
    return success;
}

const char *savedhi_site_template_password_v2(
        const savedhiUserKey *userKey, const savedhiSiteKey *siteKey, savedhiResultType resultType, const char *resultParam) {

    return savedhi_site_template_password_v1( userKey, siteKey, resultType, resultParam );
}

const char *savedhi_site_crypted_password_v2(
        const savedhiUserKey *userKey, const savedhiSiteKey *siteKey, savedhiResultType resultType, const char *cipherText) {

    return savedhi_site_crypted_password_v1( userKey, siteKey, resultType, cipherText );
}

const char *savedhi_site_derived_password_v2(
        const savedhiUserKey *userKey, const savedhiSiteKey *siteKey, savedhiResultType resultType, const char *resultParam) {

    return savedhi_site_derived_password_v1( userKey, siteKey, resultType, resultParam );
}

const char *savedhi_site_state_v2(
        const savedhiUserKey *userKey, const savedhiSiteKey *siteKey, savedhiResultType resultType, const char *state) {

    return savedhi_site_state_v1( userKey, siteKey, resultType, state );
}
