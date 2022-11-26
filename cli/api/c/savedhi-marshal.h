// =============================================================================
// Created by Maarten Billemont on 2017-07-15.
// Copyright (c) 2011, Maarten Billemont.
//
// This file is part of savedhi.
// savedhi is free software. You can modify it under the terms of
// the GNU General Public License, either version 3 or any later version.
// See the LICENSE file for details or consult <http://www.gnu.org/licenses/>.
//
// Note: this grant does not include any rights for use of savedhi's trademarks.
// =============================================================================

#ifndef _savedhi_MARSHAL_H
#define _savedhi_MARSHAL_H

#include "savedhi-algorithm.h"

savedhi_LIBS_BEGIN
#include <time.h>
#include <stdarg.h>
savedhi_LIBS_END

//// Types.

typedef savedhi_enum( unsigned int, savedhiFormat ) {
    /** Do not marshal. */
    savedhiFormatNone,
    /** Marshal using the line-based plain-text format. */
    savedhiFormatFlat,
    /** Marshal using the JSON structured format. */
    savedhiFormatJSON,

#if savedhi_JSON
    savedhiFormatDefault = savedhiFormatJSON,
#else
    savedhiFormatDefault = savedhiFormatFlat,
#endif
    savedhiFormatFirst = savedhiFormatFlat,
    savedhiFormatLast = savedhiFormatJSON,
};

typedef savedhi_enum( unsigned int, savedhiMarshalErrorType ) {
    /** The marshalling operation completed successfully. */
    savedhiMarshalSuccess,
    /** An error in the structure of the marshall file interrupted marshalling. */
    savedhiMarshalErrorStructure,
    /** The marshall file uses an unsupported format version. */
    savedhiMarshalErrorFormat,
    /** A required value is missing or not specified. */
    savedhiMarshalErrorMissing,
    /** The given user secret is not valid. */
    savedhiMarshalErrorUserSecret,
    /** An illegal value was specified. */
    savedhiMarshalErrorIllegal,
    /** An internal system error interrupted marshalling. */
    savedhiMarshalErrorInternal,
};

typedef struct savedhiMarshalError {
    /** The status of the most recent processing operation. */
    savedhiMarshalErrorType type;
    /** An explanation of the situation that caused the current status type. */
    const char *message;
} savedhiMarshalError;

/** A function that can resolve a user key of the given algorithm for the user with the given name.
 * @return A user key (allocated), or NULL if the key could not be resolved. */
typedef const savedhiUserKey *(*savedhiKeyProvider)(
        savedhiAlgorithm algorithm, const char *userName);
/** A function that updates the currentKey with the userKey of the given algorithm for the user with the given name.
 * @param currentKey A pointer to where the current userKey (allocated) can be found and a new one can be placed.
 *                   Free the old value if you update it. If NULL, the proxy is invalidated and should free any state it holds.
 * @param currentAlgorithm A pointer to where the algorithm of the current userKey is found and can be updated.
 * @param algorithm The algorithm of the userKey that should be placed in currentKey.
 * @param userName The name of the user whose userKey should be placed in currentKey.
 * @return false if not able to resolve the requested userKey. */
typedef bool (*savedhiKeyProviderProxy)(
        const savedhiUserKey **currentKey, savedhiAlgorithm *currentAlgorithm, savedhiAlgorithm algorithm, const char *userName);

/** Create a key provider which handles key generation by proxying the given function.
 * The proxy function receives the currently cached key and its algorithm.  If those are NULL, the proxy function should clean up its state. */
savedhiKeyProvider savedhi_proxy_provider_set(
        const savedhiKeyProviderProxy proxy);
/** Create a key provider that computes a user key for the given user secret. */
savedhiKeyProvider savedhi_proxy_provider_set_secret(
        const char *userSecret);

/** Unset the active proxy and free the proxy provider. */
void savedhi_proxy_provider_unset(void);

/** Free the key provider's internal state. */
void savedhi_key_provider_free(
        savedhiKeyProvider keyProvider);

typedef struct savedhiMarshalledData {
    /** If the parent is an object, this holds the key by which this data value is referenced. */
    const char *obj_key;
    /** If the parent is an array, this holds the index at which this data value is referenced. */
    size_t arr_index;

    /** Whether this data value represents a null value (true). */
    bool is_null;
    /** Whether this data value represents a boolean value (true). */
    bool is_bool;
    /** The textual value of this data if it holds a C-string. */
    const char *str_value;
    /** The numerical value of this data if it holds a number or a boolean. */
    double num_value;

    /** Amount of data values references under this value if it represents an object or an array. */
    size_t children_count;
    /** Array of data values referenced under this value. */
    struct savedhiMarshalledData *children;
} savedhiMarshalledData;

typedef struct savedhiMarshalledInfo {
    /** The data format used for serializing the file and user data into a byte stream. */
    savedhiFormat format;
    /** Date of when the file was previously serialized. */
    time_t exportDate;
    /** Whether secrets and state should be visible in clear-text (false) when serialized. */
    bool redacted;

    /** Algorithm version to use for user operations (eg. key ID operations). */
    savedhiAlgorithm algorithm;
    /** A number identifying the avatar to display for the user in this file. */
    unsigned int avatar;
    /** Unique name for this file's user, preferably the user's full legal name. */
    const char *userName;
    /** User metadata: The identicon that was generated to represent this file's user identity. */
    savedhiIdenticon identicon;
    /** A unique identifier (hex) for the user key, primarily for authentication/verification. */
    savedhiKeyID keyID;
    /** User metadata: Date of the most recent action taken by this user. */
    time_t lastUsed;
} savedhiMarshalledInfo;

typedef struct savedhiMarshalledQuestion {
    /** Unique name for the security question, preferably a single key word from the question sentence. */
    const char *keyword;
    /** The result type to use for generating an answer. */
    savedhiResultType type;
    /** State data (base64), if any, necessary for generating the question's answer. */
    const char *state;
} savedhiMarshalledQuestion;

typedef struct savedhiMarshalledSite {
    /** Unique name for this site. */
    const char *siteName;
    /** Algorithm version to use for all site operations (eg. result, login, question operations). */
    savedhiAlgorithm algorithm;

    /** The counter value of the site result to generate. */
    savedhiCounter counter;
    /** The result type to use for generating a site result. */
    savedhiResultType resultType;
    /** State data (base64), if any, necessary for generating the site result. */
    const char *resultState;

    /** The result type to use for generating a site login. */
    savedhiResultType loginType;
    /** State data (base64), if any, necessary for generating the site login. */
    const char *loginState;

    /** Site metadata: URL location where the site can be accessed. */
    const char *url;
    /** Site metadata: Amount of times an action has been taken for this site. */
    unsigned int uses;
    /** Site metadata: Date of the most recent action taken on this site. */
    time_t lastUsed;

    /** Amount of security questions associated with this site. */
    size_t questions_count;
    /** Array of security questions associated with this site. */
    savedhiMarshalledQuestion *questions;
} savedhiMarshalledSite;

typedef struct savedhiMarshalledUser {
    savedhiKeyProvider userKeyProvider;
    bool redacted;

    /** A number identifying the avatar to display for this user. */
    unsigned int avatar;
    /** Unique name for this user, preferably the user's full legal name. */
    const char *userName;
    /** User metadata: The identicon that was generated to represent this user's identity. */
    savedhiIdenticon identicon;
    /** Algorithm version to use for user operations (eg. key ID operations). */
    savedhiAlgorithm algorithm;
    /** A unique identifier (hex) for the user key, primarily for authentication/verification. */
    savedhiKeyID keyID;
    /** The initial result type to use for new sites created by the user. */
    savedhiResultType defaultType;
    /** The result type to use for generating the user's standard login. */
    savedhiResultType loginType;
    /** State data (base64), if any, necessary for generating the user's standard login. */
    const char *loginState;
    /** User metadata: Date of the most recent action taken by this user. */
    time_t lastUsed;

    /** Amount of sites associated to this user. */
    size_t sites_count;
    /** Array of sites associated to this user. */
    savedhiMarshalledSite *sites;
} savedhiMarshalledUser;

typedef struct savedhiMarshalledFile {
    /** Metadata from the file that holds user data, available without the need for user authentication. */
    savedhiMarshalledInfo *info;
    /** All data in the file, including extensions and other data present, even if not used by this library. */
    savedhiMarshalledData *data;
    /** Status of parsing the file and any errors that might have occurred during the process. */
    savedhiMarshalError error;
} savedhiMarshalledFile;

//// Marshalling.

/** Write the user and all associated data out using the given marshalling format.
 * @param file A pointer to the original file object to update with the user's data or to NULL to make a new.
 *             File object will be updated with state or new (allocated).  May be NULL if not interested in a file object.
 * @return A C-string (allocated), or NULL if the file is missing, format is unrecognized, does not support marshalling or a format error occurred. */
const char *savedhi_marshal_write(
        const savedhiFormat outFormat, savedhiMarshalledFile **file, savedhiMarshalledUser *user);
/** Parse the user configuration in the input buffer.  Fields that could not be parsed remain at their type's initial value.
 * @return The updated file object or a new one (allocated) if none was provided; NULL if a file object could not be allocated. */
savedhiMarshalledFile *savedhi_marshal_read(
        savedhiMarshalledFile *file, const char *in);
/** Authenticate as the user identified by the given marshalled file.
 * @note This object stores a reference to the given key provider.
 * @return A user object (allocated), or NULL if the file format provides no marshalling or a format error occurred. */
savedhiMarshalledUser *savedhi_marshal_auth(
        savedhiMarshalledFile *file, const savedhiKeyProvider userKeyProvider);

//// Creating.

/** Create a new user object ready for marshalling.
 * @note This object stores copies of the strings assigned to it and manages their deallocation internally.
 * @return A user object (allocated), or NULL if the userName is missing or the marshalled user couldn't be allocated. */
savedhiMarshalledUser *savedhi_marshal_user(
        const char *userName, const savedhiKeyProvider userKeyProvider, const savedhiAlgorithm algorithmVersion);
/** Create a new site attached to the given user object, ready for marshalling.
 * @note This object stores copies of the strings assigned to it and manages their deallocation internally.
 * @return A site object (allocated), or NULL if the siteName is missing or the marshalled site couldn't be allocated. */
savedhiMarshalledSite *savedhi_marshal_site(
        savedhiMarshalledUser *user,
        const char *siteName, const savedhiResultType resultType, const savedhiCounter keyCounter, const savedhiAlgorithm algorithmVersion);
/** Create a new question attached to the given site object, ready for marshalling.
 * @note This object stores copies of the strings assigned to it and manages their deallocation internally.
 * @return A question object (allocated), or NULL if the marshalled question couldn't be allocated. */
savedhiMarshalledQuestion *savedhi_marshal_question(
        savedhiMarshalledSite *site, const char *keyword);
/** Create or update a marshal file descriptor.
 * @param file If NULL, a new file will be allocated.  Otherwise, the given file will be updated and the updated file returned.
 * @param info If NULL, the file's info will be left as-is, otherwise it will be replaced by the given one.  The file will manage the info's deallocation.
 * @param data If NULL, the file's data will be left as-is, otherwise it will be replaced by the given one.  The file will manage the data's deallocation.
 * @return The given file or new (allocated) if file is NULL; or NULL if the user is missing or the file couldn't be allocated. */
savedhiMarshalledFile *savedhi_marshal_file(
        savedhiMarshalledFile *file, savedhiMarshalledInfo *info, savedhiMarshalledData *data);
/** Record a marshal error.
 * @return The given file or new (allocated) if file is NULL; or NULL if the file couldn't be allocated. */
savedhiMarshalledFile *savedhi_marshal_error(
        savedhiMarshalledFile *file, savedhiMarshalErrorType type, const char *format, ...);

//// Disposing.

/** Free the given user object and all associated data. */
#define savedhi_marshal_free(object) _Generic( (object), \
        savedhiMarshalledInfo**: savedhi_marshal_info_free,   \
        savedhiMarshalledUser**: savedhi_marshal_user_free,   \
        savedhiMarshalledData**: savedhi_marshal_data_free,   \
        savedhiMarshalledFile**: savedhi_marshal_file_free)   \
        (object)
void savedhi_marshal_info_free(
        savedhiMarshalledInfo **info);
void savedhi_marshal_user_free(
        savedhiMarshalledUser **user);
void savedhi_marshal_data_free(
        savedhiMarshalledData **data);
void savedhi_marshal_file_free(
        savedhiMarshalledFile **file);

//// Exploring.

/** Create a null value.
 * @return A new data value (allocated), initialized to a null value, or NULL if the value couldn't be allocated. */
savedhiMarshalledData *savedhi_marshal_data_new(void);
/** Get or create a value for the given path in the data store.
 * @return The value at this path (shared), or NULL if the value didn't exist and couldn't be created. */
savedhiMarshalledData *savedhi_marshal_data_get(
        savedhiMarshalledData *data, ...);
savedhiMarshalledData *savedhi_marshal_data_vget(
        savedhiMarshalledData *data, va_list nodes);
/** Look up the value at the given path in the data store.
 * @return The value at this path (shared), or NULL if there is no value at this path. */
const savedhiMarshalledData *savedhi_marshal_data_find(
        const savedhiMarshalledData *data, ...);
const savedhiMarshalledData *savedhi_marshal_data_vfind(
        const savedhiMarshalledData *data, va_list nodes);
/** Check if the data represents a NULL value.
 * @return true if the value at this path is null or is missing, false if it is a non-null type. */
bool savedhi_marshal_data_is_null(
        const savedhiMarshalledData *data, ...);
bool savedhi_marshal_data_vis_null(
        const savedhiMarshalledData *data, va_list nodes);
/** Set a null value at the given path in the data store.
 * @return true if the object was successfully modified. */
bool savedhi_marshal_data_set_null(
        savedhiMarshalledData *data, ...);
bool savedhi_marshal_data_vset_null(
        savedhiMarshalledData *data, va_list nodes);
/** Look up the boolean value at the given path in the data store.
 * @return true if the value at this path is true, false if it is not or there is no boolean value at this path. */
bool savedhi_marshal_data_get_bool(
        const savedhiMarshalledData *data, ...);
bool savedhi_marshal_data_vget_bool(
        const savedhiMarshalledData *data, va_list nodes);
/** Set a boolean value at the given path in the data store.
 * @return true if the object was successfully modified. */
bool savedhi_marshal_data_set_bool(
        const bool value, savedhiMarshalledData *data, ...);
bool savedhi_marshal_data_vset_bool(
        const bool value, savedhiMarshalledData *data, va_list nodes);
/** Look up the numeric value at the given path in the data store.
 * @return A number or NAN if there is no numeric value at this path. */
double savedhi_marshal_data_get_num(
        const savedhiMarshalledData *data, ...);
double savedhi_marshal_data_vget_num(
        const savedhiMarshalledData *data, va_list nodes);
bool savedhi_marshal_data_set_num(
        const double value, savedhiMarshalledData *data, ...);
bool savedhi_marshal_data_vset_num(
        const double value, savedhiMarshalledData *data, va_list nodes);
/** Look up string value at the given path in the data store.
 * @return The string value (shared) or string representation of the number at this path; NULL if there is no such value at this path. */
const char *savedhi_marshal_data_get_str(
        const savedhiMarshalledData *data, ...);
const char *savedhi_marshal_data_vget_str(
        const savedhiMarshalledData *data, va_list nodes);
/** Save a C-string value at the given path into the data store.
 * @param value The string value to save into the data store.  The data store will hold a copy of this object.
 * @return true if the value has been saved into the data store.  false if a node at the path didn't exist and couldn't be created or initialized. */
bool savedhi_marshal_data_set_str(
        const char *value, savedhiMarshalledData *data, ...);
bool savedhi_marshal_data_vset_str(
        const char *value, savedhiMarshalledData *data, va_list nodes);
/** Keep only the data children that pass the filter test. */
void savedhi_marshal_data_filter(
        savedhiMarshalledData *data, bool (*filter)(savedhiMarshalledData *child, void *args), void *args);
bool savedhi_marshal_data_filter_empty(
        savedhiMarshalledData *child, void *args);

//// Format.

/**
 * @return The purpose represented by the given name or ERR if the format was not recognized.
 */
const savedhiFormat savedhi_format_named(
        const char *formatName);
/**
 * @return The standard name (static) for the given purpose or NULL if the format was not recognized.
 */
const char *savedhi_format_name(
        const savedhiFormat format);
/**
 * @return The file extension (static) that's recommended and currently used for output files,
 *         or NULL if the format was not recognized or does not support marshalling.
 */
const char *savedhi_format_extension(
        const savedhiFormat format);
/**
 * @return An array (allocated, count) of filename extensions (static) that are used for files of this format,
 *         the first being the currently preferred/output extension.
 *         NULL if the format is unrecognized or does not support marshalling.
 */
const char **savedhi_format_extensions(
        const savedhiFormat format, size_t *count);

#endif // _savedhi_MARSHAL_H
