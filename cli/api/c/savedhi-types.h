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

#ifndef _savedhi_TYPES_H
#define _savedhi_TYPES_H

#ifndef savedhi_LIBS_BEGIN
#define savedhi_LIBS_BEGIN
#define savedhi_LIBS_END
#endif

savedhi_LIBS_BEGIN
#define __STDC_WANT_LIB_EXT1__ 1
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
savedhi_LIBS_END

#ifndef __unused
#define __unused
#endif

#ifndef __has_feature
#define __has_feature(x) 0
#endif

#ifdef NS_ENUM
#define savedhi_enum(_type, _name) NS_ENUM(_type, _name)
#elif __clang__ || __has_feature( c_fixed_enum ) || __has_feature( objc_fixed_enum ) || __has_feature( cxx_fixed_enum )
#define savedhi_enum(_type, _name) _type _name; enum _name : _type
#else
#define savedhi_enum(_type, _name) _type _name; enum _name
#endif

#ifdef NS_OPTIONS
#define savedhi_opts(_type, _name) NS_OPTIONS(_type, _name)
#elif __clang__ || __has_feature( c_fixed_enum ) || __has_feature( objc_fixed_enum ) || __has_feature( cxx_fixed_enum )
#define savedhi_opts(_type, _name) _type _name; enum _name : _type
#else
#define savedhi_opts(_type, _name) _type _name; enum _name
#endif

//// Types.

typedef savedhi_enum( unsigned int, savedhiAlgorithm ) {
    /** (2012-03-05) V0 incorrectly performed host-endian math with bytes translated into 16-bit network-endian. */
    savedhiAlgorithmV0,
    /** (2012-07-17) V1 incorrectly sized site name fields by character count rather than byte count. */
    savedhiAlgorithmV1,
    /** (2014-09-24) V2 incorrectly sized user name fields by character count rather than byte count. */
    savedhiAlgorithmV2,
    /** (2015-01-15) V3 is the current version. */
    savedhiAlgorithmV3,

    savedhiAlgorithmCurrent = savedhiAlgorithmV3,
    savedhiAlgorithmFirst = savedhiAlgorithmV0,
    savedhiAlgorithmLast = savedhiAlgorithmV3,
};

typedef struct {
    /** SHA-256-sized hash */
    uint8_t bytes[256 / 8]; // SHA-256
    /** Hex c-string of the hash */
    char hex[2 * (256 / 8) + 1];
} savedhiKeyID;
extern const savedhiKeyID savedhiKeyIDUnset;

typedef struct {
    /** The cryptographic key */
    const uint8_t bytes[512 / 8];
    /** The key's identity */
    const savedhiKeyID keyID;
    /** The algorithm the key was made by & for */
    const savedhiAlgorithm algorithm;
} savedhiUserKey;

typedef struct {
    /** The cryptographic key */
    const uint8_t bytes[256 / 8]; // HMAC-SHA-256
    /** The key's identity */
    const savedhiKeyID keyID;
    /** The algorithm the key was made by & for */
    const savedhiAlgorithm algorithm;
} savedhiSiteKey;

typedef savedhi_enum( uint8_t, savedhiKeyPurpose ) {
    /** Generate a key for authentication. */
    savedhiKeyPurposeAuthentication,
    /** Generate a name for identification. */
    savedhiKeyPurposeIdentification,
    /** Generate a recovery token. */
    savedhiKeyPurposeRecovery,
};

// bit 4 - 9
typedef savedhi_opts( uint16_t, savedhiResultClass ) {
    /** Use the site key to generate a result from a template. */
    savedhiResultClassTemplate = 1 << 4,
    /** Use the site key to encrypt and decrypt a stateful entity. */
    savedhiResultClassStateful = 1 << 5,
    /** Use the site key to derive a site-specific object. */
    savedhiResultClassDerive = 1 << 6,
};

// bit 10 - 15
typedef savedhi_opts( uint16_t, savedhiResultFeature ) {
    savedhiResultFeatureNone = 0,
    /** Export the key-protected content data. */
    savedhiResultFeatureExportContent = 1 << 10,
    /** Never export content. */
    savedhiResultFeatureDevicePrivate = 1 << 11,
    /** Don't use this as the primary authentication result type. */
    savedhiResultFeatureAlternate = 1 << 12,
};

// bit 0-3 | savedhiResultClass | savedhiResultFeature
typedef savedhi_enum( uint32_t, savedhiResultType ) {
    /** 0: Don't produce a result */
    savedhiResultNone = 0,

    /** 16: pg^VMAUBk5x3p%HP%i4= */
    savedhiResultTemplateMaximum = 0x0 | savedhiResultClassTemplate | savedhiResultFeatureNone,
    /** 17: BiroYena8:Kixa */
    savedhiResultTemplateLong = 0x1 | savedhiResultClassTemplate | savedhiResultFeatureNone,
    /** 18: BirSuj0- */
    savedhiResultTemplateMedium = 0x2 | savedhiResultClassTemplate | savedhiResultFeatureNone,
    /** 19: Bir8 */
    savedhiResultTemplateShort = 0x3 | savedhiResultClassTemplate | savedhiResultFeatureNone,
    /** 20: pO98MoD0 */
    savedhiResultTemplateBasic = 0x4 | savedhiResultClassTemplate | savedhiResultFeatureNone,
    /** 21: 2798 */
    savedhiResultTemplatePIN = 0x5 | savedhiResultClassTemplate | savedhiResultFeatureNone,
    /** 30: birsujano */
    savedhiResultTemplateName = 0xE | savedhiResultClassTemplate | savedhiResultFeatureNone,
    /** 31: bir yennoquce fefi */
    savedhiResultTemplatePhrase = 0xF | savedhiResultClassTemplate | savedhiResultFeatureNone,

    /** 1056: Custom saved result. */
    savedhiResultStatePersonal = 0x0 | savedhiResultClassStateful | savedhiResultFeatureExportContent,
    /** 2081: Custom saved result that should not be exported from the device. */
    savedhiResultStateDevice = 0x1 | savedhiResultClassStateful | savedhiResultFeatureDevicePrivate,

    /** 4160: Derive a unique binary key. */
    savedhiResultDeriveKey = 0x0 | savedhiResultClassDerive | savedhiResultFeatureAlternate,

    savedhiResultDefaultResult = savedhiResultTemplateLong,
    savedhiResultDefaultLogin = savedhiResultTemplateName,
};

typedef savedhi_enum( uint32_t, savedhiCounter ) {
    /** Use a time-based counter value, resulting in a TOTP generator. */
    savedhiCounterTOTP = 0,
    /** The initial value for a site's counter. */
    savedhiCounterInitial = 1,

    savedhiCounterDefault = savedhiCounterInitial,
    savedhiCounterFirst = savedhiCounterTOTP,
    savedhiCounterLast = UINT32_MAX,
};

/** These colours are compatible with the original ANSI SGR. */
typedef savedhi_enum( uint8_t, savedhiIdenticonColor ) {
    savedhiIdenticonColorUnset,
    savedhiIdenticonColorRed,
    savedhiIdenticonColorGreen,
    savedhiIdenticonColorYellow,
    savedhiIdenticonColorBlue,
    savedhiIdenticonColorMagenta,
    savedhiIdenticonColorCyan,
    savedhiIdenticonColorMono,

    savedhiIdenticonColorFirst = savedhiIdenticonColorRed,
    savedhiIdenticonColorLast = savedhiIdenticonColorMono,
};

typedef struct {
    const char *leftArm;
    const char *body;
    const char *rightArm;
    const char *accessory;
    savedhiIdenticonColor color;
} savedhiIdenticon;
extern const savedhiIdenticon savedhiIdenticonUnset;

//// Type utilities.

/** Check whether the fingerprint is valid.
 * @return true if the fingerprints represents a fully complete print for a buffer. */
bool savedhi_id_valid(const savedhiKeyID *id1);
/** Compare two fingerprints for equality.
 * @return true if the buffers represent identical fingerprints or are both NULL. */
bool savedhi_id_equals(const savedhiKeyID *id1, const savedhiKeyID *id2);
/** Encode a fingerprint for a buffer. */
const savedhiKeyID savedhi_id_buf(const uint8_t *buf, const size_t size);
/** Reconstruct a fingerprint from its hexadecimal string representation. */
const savedhiKeyID savedhi_id_str(const char hex[static 65]);

/**
 * @return The standard identifying name (static) for the given algorithm or NULL if the algorithm is not known.
 */
const char *savedhi_algorithm_short_name(const savedhiAlgorithm algorithm);
/**
 * @return The descriptive name (static) for the given algorithm or NULL if the algorithm is not known.
 */
const char *savedhi_algorithm_long_name(const savedhiAlgorithm algorithm);

/**
 * @return The purpose represented by the given name or ERR if the name does not represent a known purpose.
 */
const savedhiKeyPurpose savedhi_purpose_named(const char *purposeName);
/**
 * @return The standard name (static) for the given purpose or NULL if the purpose is not known.
 */
const char *savedhi_purpose_name(const savedhiKeyPurpose purpose);
/**
 * @return The scope identifier (static) to apply when encoding for the given purpose or NULL if the purpose is not known.
 */
const char *savedhi_purpose_scope(const savedhiKeyPurpose purpose);

/**
 * @return The result type represented by the given name or ERR if the name does not represent a known type.
 */
const savedhiResultType savedhi_type_named(const char *typeName);
/**
 * @return The standard identifying name (static) for the given result type or NULL if the type is not known.
 */
const char *savedhi_type_abbreviation(const savedhiResultType resultType);
/**
 * @return The standard identifying name (static) for the given result type or NULL if the type is not known.
 */
const char *savedhi_type_short_name(const savedhiResultType resultType);
/**
 * @return The descriptive name (static) for the given result type or NULL if the type is not known.
 */
const char *savedhi_type_long_name(const savedhiResultType resultType);

/**
 * @return An array (allocated, count) of strings (static) that express the templates to use for the given type.
 *         NULL if the type is not known or is not a savedhiResultClassTemplate.
 */
const char **savedhi_type_templates(const savedhiResultType type, size_t *count);
/**
 * @return A C-string (static) that contains the result encoding template of the given type for a seed that starts with the given byte.
 *         NULL if the type is not known or is not a savedhiResultClassTemplate.
 */
const char *savedhi_type_template(const savedhiResultType type, const uint8_t templateIndex);

/**
 * @return A C-string (static) with all the characters in the given character class or NULL if the character class is not known.
 */
const char *savedhi_class_characters(const char characterClass);
/**
 * @return A character from given character class that encodes the given byte or NUL if the character class is not known or is empty.
 */
const char savedhi_class_character(const char characterClass, const uint8_t seedByte);

#endif // _savedhi_TYPES_H
