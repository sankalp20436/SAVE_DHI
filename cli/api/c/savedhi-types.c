// =============================================================================
// Created by Maarten Billemont on 2012-01-04.
// Copyright (c) 2011, Maarten Billemont.
//
// This file is part of savedhi.
// savedhi is free software. You can modify it under the terms of
// the GNU General Public License, either version 3 or any later version.
// See the LICENSE file for details or consult <http://www.gnu.org/licenses/>.
//
// Note: this grant does not include any rights for use of savedhi's trademarks.
// =============================================================================

#include "savedhi-types.h"
#include "savedhi-util.h"

savedhi_LIBS_BEGIN
#include <string.h>
#include <ctype.h>

#if savedhi_CPERCIVA
#include <scrypt/crypto_scrypt.h>
#include <scrypt/sha256.h>
#elif savedhi_SODIUM
#include "sodium.h"
#endif
savedhi_LIBS_END

const savedhiKeyID savedhiKeyIDUnset = { .hex = "" };

const savedhiIdenticon savedhiIdenticonUnset = {
        .leftArm = "",
        .body = "",
        .rightArm = "",
        .accessory = "",
        .color = savedhiIdenticonColorUnset,
};

bool savedhi_id_valid(const savedhiKeyID *id) {

    return id && strlen( id->hex ) + 1 == sizeof( id->hex );
}

bool savedhi_id_equals(const savedhiKeyID *id1, const savedhiKeyID *id2) {

    if (!id1 || !id2)
        return !id1 && !id2;

    return memcmp( id1->bytes, id2->bytes, sizeof( id1->bytes ) ) == OK;
}

const savedhiKeyID savedhi_id_buf(const uint8_t *buf, const size_t size) {

    savedhiKeyID keyID = savedhiKeyIDUnset;

    if (!buf)
        return keyID;

#if savedhi_CPERCIVA
    SHA256_Buf( buf, size, keyID.bytes );
#elif savedhi_SODIUM
    crypto_hash_sha256( keyID.bytes, buf, size );
#else
#error No crypto support for savedhi_id_buf.
#endif

    size_t hexSize = sizeof( keyID.hex );
    if (savedhi_hex( keyID.bytes, sizeof( keyID.bytes ), keyID.hex, &hexSize ) != keyID.hex)
        err( "KeyID string pointer mismatch." );

    return keyID;
}

const savedhiKeyID savedhi_id_str(const char hex[static 65]) {

    savedhiKeyID keyID = savedhiKeyIDUnset;

    size_t hexSize = 0;
    const uint8_t *hexBytes = savedhi_unhex( hex, &hexSize );
    if (hexSize != sizeof( keyID.bytes ))
        wrn( "Not a valid key ID: %s", hex );

    else {
        memcpy( keyID.bytes, hexBytes, sizeof( keyID.bytes ) );
        savedhi_hex( keyID.bytes, sizeof( keyID.bytes ), keyID.hex, &((size_t){ sizeof( keyID.hex ) }) );
    }

    savedhi_free( &hexBytes, hexSize );
    return keyID;
}

const savedhiResultType savedhi_type_named(const char *typeName) {

    // Find what password type is represented by the type letter.
    if (strlen( typeName ) == 1) {
        if ('0' == typeName[0])
            return savedhiResultNone;
        if ('x' == typeName[0])
            return savedhiResultTemplateMaximum;
        if ('l' == typeName[0])
            return savedhiResultTemplateLong;
        if ('m' == typeName[0])
            return savedhiResultTemplateMedium;
        if ('b' == typeName[0])
            return savedhiResultTemplateBasic;
        if ('s' == typeName[0])
            return savedhiResultTemplateShort;
        if ('i' == typeName[0])
            return savedhiResultTemplatePIN;
        if ('n' == typeName[0])
            return savedhiResultTemplateName;
        if ('p' == typeName[0])
            return savedhiResultTemplatePhrase;
        if ('P' == typeName[0])
            return savedhiResultStatePersonal;
        if ('D' == typeName[0])
            return savedhiResultStateDevice;
        if ('K' == typeName[0])
            return savedhiResultDeriveKey;
    }

    // Find what password type is represented by the type name.
    if (savedhi_strncasecmp( savedhi_type_short_name( savedhiResultNone ), typeName, strlen( typeName ) ) == OK)
        return savedhiResultNone;
    if (savedhi_strncasecmp( savedhi_type_short_name( savedhiResultTemplateMaximum ), typeName, strlen( typeName ) ) == OK)
        return savedhiResultTemplateMaximum;
    if (savedhi_strncasecmp( savedhi_type_short_name( savedhiResultTemplateLong ), typeName, strlen( typeName ) ) == OK)
        return savedhiResultTemplateLong;
    if (savedhi_strncasecmp( savedhi_type_short_name( savedhiResultTemplateMedium ), typeName, strlen( typeName ) ) == OK)
        return savedhiResultTemplateMedium;
    if (savedhi_strncasecmp( savedhi_type_short_name( savedhiResultTemplateBasic ), typeName, strlen( typeName ) ) == OK)
        return savedhiResultTemplateBasic;
    if (savedhi_strncasecmp( savedhi_type_short_name( savedhiResultTemplateShort ), typeName, strlen( typeName ) ) == OK)
        return savedhiResultTemplateShort;
    if (savedhi_strncasecmp( savedhi_type_short_name( savedhiResultTemplatePIN ), typeName, strlen( typeName ) ) == OK)
        return savedhiResultTemplatePIN;
    if (savedhi_strncasecmp( savedhi_type_short_name( savedhiResultTemplateName ), typeName, strlen( typeName ) ) == OK)
        return savedhiResultTemplateName;
    if (savedhi_strncasecmp( savedhi_type_short_name( savedhiResultTemplatePhrase ), typeName, strlen( typeName ) ) == OK)
        return savedhiResultTemplatePhrase;
    if (savedhi_strncasecmp( savedhi_type_short_name( savedhiResultStatePersonal ), typeName, strlen( typeName ) ) == OK)
        return savedhiResultStatePersonal;
    if (savedhi_strncasecmp( savedhi_type_short_name( savedhiResultStateDevice ), typeName, strlen( typeName ) ) == OK)
        return savedhiResultStateDevice;
    if (savedhi_strncasecmp( savedhi_type_short_name( savedhiResultDeriveKey ), typeName, strlen( typeName ) ) == OK)
        return savedhiResultDeriveKey;

    wrn( "Not a generated type name: %s", typeName );
    return (savedhiResultType)ERR;
}

const char *savedhi_type_abbreviation(const savedhiResultType resultType) {

    switch (resultType) {
        case savedhiResultNone:
            return "no";
        case savedhiResultTemplateMaximum:
            return "max";
        case savedhiResultTemplateLong:
            return "long";
        case savedhiResultTemplateMedium:
            return "med";
        case savedhiResultTemplateBasic:
            return "basic";
        case savedhiResultTemplateShort:
            return "short";
        case savedhiResultTemplatePIN:
            return "pin";
        case savedhiResultTemplateName:
            return "name";
        case savedhiResultTemplatePhrase:
            return "phrase";
        case savedhiResultStatePersonal:
            return "own";
        case savedhiResultStateDevice:
            return "device";
        case savedhiResultDeriveKey:
            return "key";
        default: {
            wrn( "Unknown password type: %d", resultType );
            return NULL;
        }
    }
}

const char *savedhi_type_short_name(const savedhiResultType resultType) {

    switch (resultType) {
        case savedhiResultNone:
            return "none";
        case savedhiResultTemplateMaximum:
            return "maximum";
        case savedhiResultTemplateLong:
            return "long";
        case savedhiResultTemplateMedium:
            return "medium";
        case savedhiResultTemplateBasic:
            return "basic";
        case savedhiResultTemplateShort:
            return "short";
        case savedhiResultTemplatePIN:
            return "pin";
        case savedhiResultTemplateName:
            return "name";
        case savedhiResultTemplatePhrase:
            return "phrase";
        case savedhiResultStatePersonal:
            return "personal";
        case savedhiResultStateDevice:
            return "device";
        case savedhiResultDeriveKey:
            return "key";
        default: {
            wrn( "Unknown password type: %d", resultType );
            return NULL;
        }
    }
}

const char *savedhi_type_long_name(const savedhiResultType resultType) {

    switch (resultType) {
        case savedhiResultNone:
            return "None";
        case savedhiResultTemplateMaximum:
            return "Maximum Security Password";
        case savedhiResultTemplateLong:
            return "Long Password";
        case savedhiResultTemplateMedium:
            return "Medium Password";
        case savedhiResultTemplateBasic:
            return "Basic Password";
        case savedhiResultTemplateShort:
            return "Short Password";
        case savedhiResultTemplatePIN:
            return "PIN";
        case savedhiResultTemplateName:
            return "Name";
        case savedhiResultTemplatePhrase:
            return "Phrase";
        case savedhiResultStatePersonal:
            return "Personal Password";
        case savedhiResultStateDevice:
            return "Device Private Password";
        case savedhiResultDeriveKey:
            return "Crypto Key";
        default: {
            wrn( "Unknown password type: %d", resultType );
            return NULL;
        }
    }
}

const char **savedhi_type_templates(const savedhiResultType type, size_t *count) {

    *count = 0;
    if (!(type & savedhiResultClassTemplate)) {
        wrn( "Not a generated type: %d", type );
        return NULL;
    }

    switch (type) {
        case savedhiResultTemplateMaximum:
            return savedhi_strings( count,
                    "anoxxxxxxxxxxxxxxxxx", "axxxxxxxxxxxxxxxxxno", NULL );
        case savedhiResultTemplateLong:
            return savedhi_strings( count,
                    "CvcvnoCvcvCvcv", "CvcvCvcvnoCvcv", "CvcvCvcvCvcvno",
                    "CvccnoCvcvCvcv", "CvccCvcvnoCvcv", "CvccCvcvCvcvno",
                    "CvcvnoCvccCvcv", "CvcvCvccnoCvcv", "CvcvCvccCvcvno",
                    "CvcvnoCvcvCvcc", "CvcvCvcvnoCvcc", "CvcvCvcvCvccno",
                    "CvccnoCvccCvcv", "CvccCvccnoCvcv", "CvccCvccCvcvno",
                    "CvcvnoCvccCvcc", "CvcvCvccnoCvcc", "CvcvCvccCvccno",
                    "CvccnoCvcvCvcc", "CvccCvcvnoCvcc", "CvccCvcvCvccno", NULL );
        case savedhiResultTemplateMedium:
            return savedhi_strings( count,
                    "CvcnoCvc", "CvcCvcno", NULL );
        case savedhiResultTemplateShort:
            return savedhi_strings( count,
                    "Cvcn", NULL );
        case savedhiResultTemplateBasic:
            return savedhi_strings( count,
                    "aaanaaan", "aannaaan", "aaannaaa", NULL );
        case savedhiResultTemplatePIN:
            return savedhi_strings( count,
                    "nnnn", NULL );
        case savedhiResultTemplateName:
            return savedhi_strings( count,
                    "cvccvcvcv", NULL );
        case savedhiResultTemplatePhrase:
            return savedhi_strings( count,
                    "cvcc cvc cvccvcv cvc", "cvc cvccvcvcv cvcv", "cv cvccv cvc cvcvccv", NULL );
        default: {
            wrn( "Unknown generated type: %d", type );
            return NULL;
        }
    }
}

const char *savedhi_type_template(const savedhiResultType type, const uint8_t templateIndex) {

    size_t count = 0;
    const char **templates = savedhi_type_templates( type, &count );
    char const *template = templates && count? templates[templateIndex % count]: NULL;
    free( templates );

    return template;
}

const char *savedhi_algorithm_short_name(const savedhiAlgorithm algorithm) {

    switch (algorithm) {
        case savedhiAlgorithmV0:
            return "v0";
        case savedhiAlgorithmV1:
            return "v1";
        case savedhiAlgorithmV2:
            return "v2";
        case savedhiAlgorithmV3:
            return "v3";
        default: {
            wrn( "Unknown algorithm: %d", algorithm );
            return NULL;
        }
    }
}

const char *savedhi_algorithm_long_name(const savedhiAlgorithm algorithm) {

    switch (algorithm) {
        case savedhiAlgorithmV0:
            return "v0 (2012-03)";
        case savedhiAlgorithmV1:
            return "v1 (2012-07)";
        case savedhiAlgorithmV2:
            return "v2 (2014-09)";
        case savedhiAlgorithmV3:
            return "v3 (2015-01)";
        default: {
            wrn( "Unknown algorithm: %d", algorithm );
            return NULL;
        }
    }
}

const savedhiKeyPurpose savedhi_purpose_named(const char *purposeName) {

    if (savedhi_strncasecmp( savedhi_purpose_name( savedhiKeyPurposeAuthentication ), purposeName, strlen( purposeName ) ) == OK)
        return savedhiKeyPurposeAuthentication;
    if (savedhi_strncasecmp( savedhi_purpose_name( savedhiKeyPurposeIdentification ), purposeName, strlen( purposeName ) ) == OK)
        return savedhiKeyPurposeIdentification;
    if (savedhi_strncasecmp( savedhi_purpose_name( savedhiKeyPurposeRecovery ), purposeName, strlen( purposeName ) ) == OK)
        return savedhiKeyPurposeRecovery;

    wrn( "Not a purpose name: %s", purposeName );
    return (savedhiKeyPurpose)ERR;
}

const char *savedhi_purpose_name(const savedhiKeyPurpose purpose) {

    switch (purpose) {
        case savedhiKeyPurposeAuthentication:
            return "authentication";
        case savedhiKeyPurposeIdentification:
            return "identification";
        case savedhiKeyPurposeRecovery:
            return "recovery";
        default: {
            wrn( "Unknown purpose: %d", purpose );
            return NULL;
        }
    }
}

const char *savedhi_purpose_scope(const savedhiKeyPurpose purpose) {

    switch (purpose) {
        case savedhiKeyPurposeAuthentication:
            return "com.lyndir.masterpassword";
        case savedhiKeyPurposeIdentification:
            return "com.lyndir.masterpassword.login";
        case savedhiKeyPurposeRecovery:
            return "com.lyndir.masterpassword.answer";
        default: {
            wrn( "Unknown purpose: %d", purpose );
            return NULL;
        }
    }
}

const char *savedhi_class_characters(const char characterClass) {

    switch (characterClass) {
        case 'V':
            return "AEIOU";
        case 'C':
            return "BCDFGHJKLMNPQRSTVWXYZ";
        case 'v':
            return "aeiou";
        case 'c':
            return "bcdfghjklmnpqrstvwxyz";
        case 'A':
            return "AEIOUBCDFGHJKLMNPQRSTVWXYZ";
        case 'a':
            return "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz";
        case 'n':
            return "0123456789";
        case 'o':
            return "@&%?,=[]_:-+*$#!'^~;()/.";
        case 'x':
            return "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz0123456789!@#$%^&*()";
        case ' ':
            return " ";
        default: {
            wrn( "Unknown character class: %c", characterClass );
            return NULL;
        }
    }
}

const char savedhi_class_character(const char characterClass, const uint8_t seedByte) {

    const char *classCharacters = savedhi_class_characters( characterClass );
    if (!classCharacters || !strlen( classCharacters ))
        return '\0';

    return classCharacters[seedByte % strlen( classCharacters )];
}
