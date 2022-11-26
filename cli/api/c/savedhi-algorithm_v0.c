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

#include "savedhi-algorithm_v0.h"
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

// Algorithm version helpers.
const char *savedhi_type_template_v0(const savedhiResultType type, uint16_t templateIndex) {

    size_t count = 0;
    const char **templates = savedhi_type_templates( type, &count );
    char const *template = templates && count? templates[templateIndex % count]: NULL;
    free( templates );

    return template;
}

const char savedhi_class_character_v0(char characterClass, uint16_t classIndex) {

    const char *classCharacters = savedhi_class_characters( characterClass );
    if (!classCharacters)
        return '\0';

    return classCharacters[classIndex % strlen( classCharacters )];
}

// Algorithm version overrides.
bool savedhi_user_key_v0(
        const savedhiUserKey *userKey, const char *userName, const char *userSecret) {

    const char *keyScope = savedhi_purpose_scope( savedhiKeyPurposeAuthentication );
    trc( "keyScope: %s", keyScope );

    // Calculate the user key salt.
    trc( "userKeySalt: keyScope=%s | #userName=%s | userName=%s",
            keyScope, savedhi_hex_l( (uint32_t)savedhi_utf8_char_count( userName ), (char[9]){ 0 } ), userName );
    size_t userKeySaltSize = 0;
    uint8_t *userKeySalt = NULL;
    if (!(savedhi_buf_push( &userKeySalt, &userKeySaltSize, keyScope ) &&
          savedhi_buf_push( &userKeySalt, &userKeySaltSize, (uint32_t)savedhi_utf8_char_count( userName ) ) &&
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
        trc( "  => userKey.id: %s (algorithm: %d:0)", userKey->keyID.hex, userKey->algorithm );
    }
    return success;
}

bool savedhi_site_key_v0(
        const savedhiSiteKey *siteKey, const savedhiUserKey *userKey, const char *siteName,
        savedhiCounter keyCounter, savedhiKeyPurpose keyPurpose, const char *keyContext) {

    const char *keyScope = savedhi_purpose_scope( keyPurpose );
    trc( "keyScope: %s", keyScope );

    // OTP counter value.
    if (keyCounter == savedhiCounterTOTP)
        keyCounter = ((savedhiCounter)time( NULL ) / savedhi_otp_window) * savedhi_otp_window;

    // Calculate the site seed.
    trc( "siteSalt: keyScope=%s | #siteName=%s | siteName=%s | keyCounter=%s | #keyContext=%s | keyContext=%s",
            keyScope, savedhi_hex_l( (uint32_t)savedhi_utf8_char_count( siteName ), (char[9]){ 0 } ), siteName,
            savedhi_hex_l( keyCounter, (char[9]){ 0 } ),
            keyContext? savedhi_hex_l( (uint32_t)savedhi_utf8_char_count( keyContext ), (char[9]){ 0 } ): NULL, keyContext );
    size_t siteSaltSize = 0;
    uint8_t *siteSalt = NULL;
    if (!(savedhi_buf_push( &siteSalt, &siteSaltSize, keyScope ) &&
          savedhi_buf_push( &siteSalt, &siteSaltSize, (uint32_t)savedhi_utf8_char_count( siteName ) ) &&
          savedhi_buf_push( &siteSalt, &siteSaltSize, siteName ) &&
          savedhi_buf_push( &siteSalt, &siteSaltSize, (uint32_t)keyCounter ) &&
          (!keyContext? true:
           savedhi_buf_push( &siteSalt, &siteSaltSize, (uint32_t)savedhi_utf8_char_count( keyContext ) ) &&
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
        trc( "  => siteKey.id: %s (algorithm: %d:0)", siteKey->keyID.hex, siteKey->algorithm );
    }
    return success;
}

const char *savedhi_site_template_password_v0(
        __unused const savedhiUserKey *userKey, const savedhiSiteKey *siteKey, savedhiResultType resultType, __unused const char *resultParam) {

    const char *_siteKey = (const char *)siteKey->bytes;

    // Determine the template.
    uint16_t seedByte;
    savedhi_uint16( (uint16_t)_siteKey[0], (uint8_t *)&seedByte );
    const char *template = savedhi_type_template_v0( resultType, seedByte );
    trc( "template: %u => %s", seedByte, template );
    if (!template)
        return NULL;
    if (strlen( template ) > sizeof( siteKey->bytes ) - 1) {
        err( "Template too long for password seed: %zu", strlen( template ) );
        return NULL;
    }

    // Encode the password from the seed using the template.
    char *const sitePassword = calloc( strlen( template ) + 1, sizeof( char ) );
    for (size_t c = 0; c < strlen( template ); ++c) {
        savedhi_uint16( (uint16_t)_siteKey[c + 1], (uint8_t *)&seedByte );
        sitePassword[c] = savedhi_class_character_v0( template[c], seedByte );
        trc( "  - class: %c, index: %5u (0x%.2hX) => character: %c",
                template[c], seedByte, seedByte, sitePassword[c] );
    }
    trc( "  => password: %s", sitePassword );

    return sitePassword;
}

const char *savedhi_site_crypted_password_v0(
        const savedhiUserKey *userKey, __unused const savedhiSiteKey *siteKey, __unused savedhiResultType resultType, const char *cipherText) {

    if (!cipherText) {
        err( "Missing encrypted state." );
        return NULL;
    }
    size_t cipherLength = strlen( cipherText );
    if (cipherLength % 4 != 0) {
        wrn( "Malformed encrypted state, not base64." );
        // This can happen if state was stored in a non-encrypted form, eg. login in old mpsites.
        return savedhi_strdup( cipherText );
    }

    // Base64-decode
    char *hex = NULL;
    uint8_t *cipherBuf = calloc( 1, savedhi_base64_decode_max( cipherLength ) );
    size_t bufSize = savedhi_base64_decode( cipherText, cipherBuf ), cipherBufSize = bufSize, hexSize = 0;
    if ((int)bufSize < 0) {
        err( "Base64 decoding error." );
        savedhi_free( &cipherBuf, savedhi_base64_decode_max( cipherLength ) );
        return NULL;
    }
    trc( "b64 decoded: %zu bytes = %s", bufSize, hex = savedhi_hex( cipherBuf, bufSize, hex, &hexSize ) );

    // Decrypt
    const uint8_t *plainBytes = savedhi_aes_decrypt( userKey->bytes, sizeof( userKey->bytes ), cipherBuf, &bufSize );
    savedhi_free( &cipherBuf, cipherBufSize );
    const char *plainText = savedhi_strndup( (char *)plainBytes, bufSize );
    if (!plainText)
        err( "AES decryption error: %s", strerror( errno ) );
    else if (!savedhi_utf8_char_count( plainText ))
        trc( "decrypted -> plainText: %zu chars = (illegal UTF-8) :: %zu bytes = %s",
                strlen( plainText ), bufSize, hex = savedhi_hex( plainBytes, bufSize, hex, &hexSize ) );
    else
        trc( "decrypted -> plainText: %zu chars = %s :: %zu bytes = %s",
                strlen( plainText ), plainText, bufSize, hex = savedhi_hex( plainBytes, bufSize, hex, &hexSize ) );
    savedhi_free( &plainBytes, bufSize );
    savedhi_free_string( &hex );

    return plainText;
}

const char *savedhi_site_derived_password_v0(
        __unused const savedhiUserKey *userKey, const savedhiSiteKey *siteKey, savedhiResultType resultType, const char *resultParam) {

    switch (resultType) {
        case savedhiResultDeriveKey: {
            if (!resultParam) {
                err( "Missing key size parameter." );
                return NULL;
            }
            long parameter = strtol( resultParam, NULL, 10 );
            if (!parameter)
                parameter = 512;
            if (parameter < 128 || parameter > 512 || parameter % 8 != 0) {
                err( "Parameter is not a valid key size (should be 128 - 512): %s", resultParam );
                return NULL;
            }

            // Derive key
            uint8_t resultKey[parameter / 8];
            trc( "keySize: %u", sizeof( resultKey ) );
            if (!savedhi_kdf_blake2b( resultKey, sizeof( resultKey ), siteKey->bytes, sizeof( siteKey->bytes ), NULL, 0, 0, NULL )) {
                err( "Could not derive result key: %s", strerror( errno ) );
                return NULL;
            }

            // Base64-encode
            char *b64Key = calloc( 1, savedhi_base64_encode_max( sizeof( resultKey ) ) );
            if (savedhi_base64_encode( resultKey, sizeof( resultKey ), b64Key ) < 0) {
                err( "Base64 encoding error." );
                savedhi_free_string( &b64Key );
            }
            else
                trc( "b64 encoded -> key: %s", b64Key );
            savedhi_zero( &resultKey, sizeof( resultKey ) );

            return b64Key;
        }
        default:
            err( "Unsupported derived password type: %d", resultType );
            return NULL;
    }
}

const char *savedhi_site_state_v0(
        const savedhiUserKey *userKey, __unused const savedhiSiteKey *siteKey, __unused savedhiResultType resultType, const char *plainText) {

    // Encrypt
    char *hex = NULL;
    size_t bufSize = strlen( plainText ), hexSize = 0;
    const uint8_t *cipherBuf = savedhi_aes_encrypt( userKey->bytes, sizeof( userKey->bytes ), (const uint8_t *)plainText, &bufSize );
    if (!cipherBuf) {
        err( "AES encryption error: %s", strerror( errno ) );
        return NULL;
    }
    trc( "cipherBuf: %zu bytes = %s", bufSize, hex = savedhi_hex( cipherBuf, bufSize, hex, &hexSize ) );

    // Base64-encode
    char *cipherText = calloc( 1, savedhi_base64_encode_max( bufSize ) );
    if (savedhi_base64_encode( cipherBuf, bufSize, cipherText ) < 0) {
        err( "Base64 encoding error." );
        savedhi_free_string( &cipherText );
    }
    else
        trc( "b64 encoded -> cipherText: %s", cipherText );
    savedhi_free( &cipherBuf, bufSize );
    savedhi_free_string( &hex );

    return cipherText;
}
