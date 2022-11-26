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


#include "savedhi-marshal.h"
#include "savedhi-util.h"
#include "savedhi-marshal-util.h"

savedhi_LIBS_BEGIN
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
savedhi_LIBS_END

static savedhiKeyProviderProxy __savedhi_proxy_provider_current = NULL;
static const savedhiUserKey *__savedhi_proxy_provider_current_key = NULL;
static savedhiAlgorithm __savedhi_proxy_provider_current_algorithm = (savedhiAlgorithm)ERR;
static const char *__savedhi_proxy_provider_current_secret = NULL;

static bool __savedhi_proxy_provider_secret(const savedhiUserKey **currentKey, savedhiAlgorithm *currentAlgorithm,
        savedhiAlgorithm algorithm, const char *userName) {

    if (!currentKey)
        return savedhi_free_string( &__savedhi_proxy_provider_current_secret );

    return savedhi_update_user_key( currentKey, currentAlgorithm, algorithm, userName, __savedhi_proxy_provider_current_secret );
}

static const savedhiUserKey *__savedhi_proxy_provider(savedhiAlgorithm algorithm, const char *userName) {

    if (!__savedhi_proxy_provider_current)
        return NULL;
    if (!__savedhi_proxy_provider_current(
            &__savedhi_proxy_provider_current_key, &__savedhi_proxy_provider_current_algorithm, algorithm, userName ))
        return NULL;

    return savedhi_memdup( __savedhi_proxy_provider_current_key, sizeof( *__savedhi_proxy_provider_current_key ) );
}

savedhiKeyProvider savedhi_proxy_provider_set_secret(const char *userSecret) {

    savedhi_proxy_provider_unset();
    __savedhi_proxy_provider_current_secret = savedhi_strdup( userSecret );
    return savedhi_proxy_provider_set( __savedhi_proxy_provider_secret );
}

savedhiKeyProvider savedhi_proxy_provider_set(const savedhiKeyProviderProxy proxy) {

    savedhi_proxy_provider_unset();
    __savedhi_proxy_provider_current = proxy;
    return __savedhi_proxy_provider;
}

void savedhi_proxy_provider_unset() {

    savedhi_free( &__savedhi_proxy_provider_current_key, sizeof( *__savedhi_proxy_provider_current_key ) );
    __savedhi_proxy_provider_current_algorithm = (savedhiAlgorithm)ERR;
    if (__savedhi_proxy_provider_current) {
        __savedhi_proxy_provider_current( NULL, NULL, (savedhiAlgorithm)ERR, NULL );
        __savedhi_proxy_provider_current = NULL;
    }
}

void savedhi_key_provider_free(savedhiKeyProvider keyProvider) {

    if (keyProvider)
        keyProvider( (savedhiAlgorithm)ERR, NULL );
}

savedhiMarshalledUser *savedhi_marshal_user(
        const char *userName, savedhiKeyProvider userKeyProvider, const savedhiAlgorithm algorithmVersion) {

    savedhiMarshalledUser *user;
    if (!userName || !(user = malloc( sizeof( savedhiMarshalledUser ) )))
        return NULL;

    *user = (savedhiMarshalledUser){
            .userKeyProvider = userKeyProvider,
            .algorithm = algorithmVersion,
            .redacted = true,

            .avatar = 0,
            .userName = savedhi_strdup( userName ),
            .identicon = savedhiIdenticonUnset,
            .keyID = savedhiKeyIDUnset,
            .defaultType = savedhiResultDefaultResult,
            .loginType = savedhiResultDefaultLogin,
            .loginState = NULL,
            .lastUsed = 0,

            .sites_count = 0,
            .sites = NULL,
    };
    return user;
}

savedhiMarshalledSite *savedhi_marshal_site(
        savedhiMarshalledUser *user, const char *siteName, const savedhiResultType resultType,
        const savedhiCounter keyCounter, const savedhiAlgorithm algorithmVersion) {

    if (!siteName)
        return NULL;
    if (!savedhi_realloc( &user->sites, NULL, savedhiMarshalledSite, ++user->sites_count )) {
        user->sites_count--;
        return NULL;
    }

    savedhiMarshalledSite *site = &user->sites[user->sites_count - 1];
    *site = (savedhiMarshalledSite){
            .siteName = savedhi_strdup( siteName ),
            .algorithm = algorithmVersion,
            .counter = keyCounter,

            .resultType = resultType,
            .resultState = NULL,

            .loginType = savedhiResultNone,
            .loginState = NULL,

            .url = NULL,
            .uses = 0,
            .lastUsed = 0,

            .questions_count = 0,
            .questions = NULL,
    };
    return site;
}

savedhiMarshalledQuestion *savedhi_marshal_question(
        savedhiMarshalledSite *site, const char *keyword) {

    if (!savedhi_realloc( &site->questions, NULL, savedhiMarshalledQuestion, ++site->questions_count )) {
        site->questions_count--;
        return NULL;
    }
    if (!keyword)
        keyword = "";

    savedhiMarshalledQuestion *question = &site->questions[site->questions_count - 1];
    *question = (savedhiMarshalledQuestion){
            .keyword = savedhi_strdup( keyword ),
            .type = savedhiResultTemplatePhrase,
            .state = NULL,
    };
    return question;
}

savedhiMarshalledFile *savedhi_marshal_file(
        savedhiMarshalledFile *file, savedhiMarshalledInfo *info, savedhiMarshalledData *data) {

    if (!file) {
        if (!(file = malloc( sizeof( savedhiMarshalledFile ) )))
            return NULL;

        *file = (savedhiMarshalledFile){
                .info = NULL, .data = NULL, .error = (savedhiMarshalError){ .type = savedhiMarshalSuccess, .message = NULL }
        };
    }

    if (data && data != file->data) {
        savedhi_marshal_free( &file->data );
        file->data = data;
    }
    if (info && info != file->info) {
        savedhi_marshal_free( &file->info );
        file->info = info;
    }

    return file;
}

savedhiMarshalledFile *savedhi_marshal_error(
        savedhiMarshalledFile *file, savedhiMarshalErrorType type, const char *format, ...) {

    file = savedhi_marshal_file( file, NULL, NULL );
    if (!file)
        return NULL;

    va_list args;
    va_start( args, format );
    file->error = (savedhiMarshalError){ type, savedhi_vstr( format, args ) };
    va_end( args );

    return file;
}

void savedhi_marshal_info_free(
        savedhiMarshalledInfo **info) {

    if (!info || !*info)
        return;

    savedhi_free_strings( &(*info)->userName, NULL );
    savedhi_free( info, sizeof( savedhiMarshalledInfo ) );
}

void savedhi_marshal_user_free(
        savedhiMarshalledUser **user) {

    if (!user || !*user)
        return;

    savedhi_free_strings( &(*user)->userName, NULL );

    for (size_t s = 0; s < (*user)->sites_count; ++s) {
        savedhiMarshalledSite *site = &(*user)->sites[s];
        savedhi_free_strings( &site->siteName, &site->resultState, &site->loginState, &site->url, NULL );

        for (size_t q = 0; q < site->questions_count; ++q) {
            savedhiMarshalledQuestion *question = &site->questions[q];
            savedhi_free_strings( &question->keyword, &question->state, NULL );
        }
        savedhi_free( &site->questions, sizeof( savedhiMarshalledQuestion ) * site->questions_count );
    }

    savedhi_free( &(*user)->sites, sizeof( savedhiMarshalledSite ) * (*user)->sites_count );
    savedhi_free( user, sizeof( savedhiMarshalledUser ) );
}

void savedhi_marshal_data_free(
        savedhiMarshalledData **data) {

    if (!data || !*data)
        return;

    savedhi_marshal_data_set_null( *data, NULL );
    savedhi_free_string( &(*data)->obj_key );
    savedhi_free( data, sizeof( savedhiMarshalledData ) );
}

void savedhi_marshal_file_free(
        savedhiMarshalledFile **file) {

    if (!file || !*file)
        return;

    savedhi_marshal_free( &(*file)->info );
    savedhi_marshal_free( &(*file)->data );
    savedhi_free_string( &(*file)->error.message );
    savedhi_free( file, sizeof( savedhiMarshalledFile ) );
}

savedhiMarshalledData *savedhi_marshal_data_new() {

    savedhiMarshalledData *data = malloc( sizeof( savedhiMarshalledData ) );
    *data = (savedhiMarshalledData){ 0 };
    savedhi_marshal_data_set_null( data, NULL );
    data->is_null = false;
    return data;
}

savedhiMarshalledData *savedhi_marshal_data_vget(
        savedhiMarshalledData *data, va_list nodes) {

    savedhiMarshalledData *parent = data, *child = parent;
    for (const char *node; parent && (node = va_arg( nodes, const char * )); parent = child) {
        child = NULL;

        for (size_t c = 0; c < parent->children_count; ++c) {
            const char *key = parent->children[c].obj_key;
            if (key && strcmp( node, key ) == OK) {
                child = &parent->children[c];
                break;
            }
        }

        if (!child) {
            if (!savedhi_realloc( &parent->children, NULL, savedhiMarshalledData, ++parent->children_count )) {
                --parent->children_count;
                break;
            }
            *(child = &parent->children[parent->children_count - 1]) = (savedhiMarshalledData){ .obj_key = savedhi_strdup( node ) };
            savedhi_marshal_data_set_null( child, NULL );
            child->is_null = false;
        }
    }

    return child;
}

savedhiMarshalledData *savedhi_marshal_data_get(
        savedhiMarshalledData *data, ...) {

    va_list nodes;
    va_start( nodes, data );
    savedhiMarshalledData *child = savedhi_marshal_data_vget( data, nodes );
    va_end( nodes );

    return child;
}

const savedhiMarshalledData *savedhi_marshal_data_vfind(
        const savedhiMarshalledData *data, va_list nodes) {

    const savedhiMarshalledData *parent = data, *child = parent;
    for (const char *node; parent && (node = va_arg( nodes, const char * )); parent = child) {
        child = NULL;

        for (size_t c = 0; c < parent->children_count; ++c) {
            const char *key = parent->children[c].obj_key;
            if (key && strcmp( node, key ) == OK) {
                child = &parent->children[c];
                break;
            }
        }

        if (!child)
            break;
    }

    return child;
}

const savedhiMarshalledData *savedhi_marshal_data_find(
        const savedhiMarshalledData *data, ...) {

    va_list nodes;
    va_start( nodes, data );
    const savedhiMarshalledData *child = savedhi_marshal_data_vfind( data, nodes );
    va_end( nodes );

    return child;
}

bool savedhi_marshal_data_vis_null(
        const savedhiMarshalledData *data, va_list nodes) {

    const savedhiMarshalledData *child = savedhi_marshal_data_vfind( data, nodes );
    return !child || child->is_null;
}

bool savedhi_marshal_data_is_null(
        const savedhiMarshalledData *data, ...) {

    va_list nodes;
    va_start( nodes, data );
    bool value = savedhi_marshal_data_vis_null( data, nodes );
    va_end( nodes );

    return value;
}

bool savedhi_marshal_data_vset_null(
        savedhiMarshalledData *data, va_list nodes) {

    savedhiMarshalledData *child = savedhi_marshal_data_vget( data, nodes );
    if (!child)
        return false;

    savedhi_free_string( &child->str_value );
    for (unsigned int c = 0; c < child->children_count; ++c) {
        savedhi_marshal_data_set_null( &child->children[c], NULL );
        savedhi_free_string( &child->children[c].obj_key );
    }
    savedhi_free( &child->children, sizeof( savedhiMarshalledData ) * child->children_count );
    child->children_count = 0;
    child->num_value = NAN;
    child->is_bool = false;
    child->is_null = true;
    return true;
}

bool savedhi_marshal_data_set_null(
        savedhiMarshalledData *data, ...) {

    va_list nodes;
    va_start( nodes, data );
    bool success = savedhi_marshal_data_vset_null( data, nodes );
    va_end( nodes );

    return success;
}

bool savedhi_marshal_data_vget_bool(
        const savedhiMarshalledData *data, va_list nodes) {

    const savedhiMarshalledData *child = savedhi_marshal_data_vfind( data, nodes );
    return child && child->is_bool && child->num_value != false;
}

bool savedhi_marshal_data_get_bool(
        const savedhiMarshalledData *data, ...) {

    va_list nodes;
    va_start( nodes, data );
    bool value = savedhi_marshal_data_vget_bool( data, nodes );
    va_end( nodes );

    return value;
}

bool savedhi_marshal_data_vset_bool(
        const bool value, savedhiMarshalledData *data, va_list nodes) {

    savedhiMarshalledData *child = savedhi_marshal_data_vget( data, nodes );
    if (!child || !savedhi_marshal_data_set_null( child, NULL ))
        return false;

    child->is_null = false;
    child->is_bool = true;
    child->num_value = value != false;
    return true;
}

bool savedhi_marshal_data_set_bool(
        const bool value, savedhiMarshalledData *data, ...) {

    va_list nodes;
    va_start( nodes, data );
    bool success = savedhi_marshal_data_vset_bool( value, data, nodes );
    va_end( nodes );

    return success;
}

double savedhi_marshal_data_vget_num(
        const savedhiMarshalledData *data, va_list nodes) {

    const savedhiMarshalledData *child = savedhi_marshal_data_vfind( data, nodes );
    return child == NULL? NAN: child->num_value;
}

double savedhi_marshal_data_get_num(
        const savedhiMarshalledData *data, ...) {

    va_list nodes;
    va_start( nodes, data );
    double value = savedhi_marshal_data_vget_num( data, nodes );
    va_end( nodes );

    return value;
}

bool savedhi_marshal_data_vset_num(
        const double value, savedhiMarshalledData *data, va_list nodes) {

    savedhiMarshalledData *child = savedhi_marshal_data_vget( data, nodes );
    if (!child || !savedhi_marshal_data_set_null( child, NULL ))
        return false;

    child->is_null = false;
    child->num_value = value;
    child->str_value = savedhi_str( "%g", value );
    return true;
}

bool savedhi_marshal_data_set_num(
        const double value, savedhiMarshalledData *data, ...) {

    va_list nodes;
    va_start( nodes, data );
    bool success = savedhi_marshal_data_vset_num( value, data, nodes );
    va_end( nodes );

    return success;
}

const char *savedhi_marshal_data_vget_str(
        const savedhiMarshalledData *data, va_list nodes) {

    const savedhiMarshalledData *child = savedhi_marshal_data_vfind( data, nodes );
    return child == NULL? NULL: child->str_value;
}

const char *savedhi_marshal_data_get_str(
        const savedhiMarshalledData *data, ...) {

    va_list nodes;
    va_start( nodes, data );
    const char *value = savedhi_marshal_data_vget_str( data, nodes );
    va_end( nodes );

    return value;
}

bool savedhi_marshal_data_vset_str(
        const char *value, savedhiMarshalledData *data, va_list nodes) {

    savedhiMarshalledData *child = savedhi_marshal_data_vget( data, nodes );
    if (!child || !savedhi_marshal_data_set_null( child, NULL ))
        return false;

    if (value) {
        child->is_null = false;
        child->str_value = savedhi_strdup( value );
    }

    return true;
}

bool savedhi_marshal_data_set_str(
        const char *value, savedhiMarshalledData *data, ...) {

    va_list nodes;
    va_start( nodes, data );
    bool success = savedhi_marshal_data_vset_str( value, data, nodes );
    va_end( nodes );

    return success;
}

void savedhi_marshal_data_filter(
        savedhiMarshalledData *data, bool (*filter)(savedhiMarshalledData *, void *), void *args) {

    size_t children_count = 0;
    savedhiMarshalledData *children = NULL;

    for (size_t c = 0; c < data->children_count; ++c) {
        savedhiMarshalledData *child = &data->children[c];
        if (filter( child, args )) {
            // Valid child in this object, keep it.
            ++children_count;

            if (children) {
                if (!savedhi_realloc( &children, NULL, savedhiMarshalledData, children_count )) {
                    --children_count;
                    continue;
                }
                child->arr_index = children_count - 1;
                children[child->arr_index] = *child;
            }
        }
        else {
            // Not a valid child in this object, remove it.
            savedhi_marshal_data_set_null( child, NULL );
            savedhi_free_string( &child->obj_key );

            if (!children)
                children = savedhi_memdup( data->children, sizeof( savedhiMarshalledData ) * children_count );
        }
    }

    if (children) {
        savedhi_free( &data->children, sizeof( savedhiMarshalledData ) * data->children_count );
        data->children = children;
        data->children_count = children_count;
    }
}

bool savedhi_marshal_data_filter_empty(
        __unused savedhiMarshalledData *child, __unused void *args) {

    return false;
}

static const char *savedhi_marshal_write_flat(
        savedhiMarshalledFile *file) {

    const savedhiMarshalledData *data = file->data;
    if (!data) {
        savedhi_marshal_error( file, savedhiMarshalErrorMissing,
                "Missing data." );
        return NULL;
    }

    char *out = NULL;
    savedhi_string_pushf( &out, "# savedhi site export\n" );
    savedhi_string_pushf( &out, savedhi_marshal_data_get_bool( data, "export", "redacted", NULL )?
                                "#     Export of site names and stored passwords (unless device-private) encrypted with the user key.\n":
                                "#     Export of site names and passwords in clear-text.\n" );
    savedhi_string_pushf( &out, "# \n" );
    savedhi_string_pushf( &out, "##\n" );
    savedhi_string_pushf( &out, "# Format: %d\n", 1 );

    const char *out_date = savedhi_default( "", savedhi_marshal_data_get_str( data, "export", "date", NULL ) );
    const char *out_fullName = savedhi_default( "", savedhi_marshal_data_get_str( data, "user", "full_name", NULL ) );
    unsigned int out_avatar = (unsigned int)savedhi_marshal_data_get_num( data, "user", "avatar", NULL );
    const char *out_identicon = savedhi_default( "", savedhi_marshal_data_get_str( data, "user", "identicon", NULL ) );
    const char *out_keyID = savedhi_default( "", savedhi_marshal_data_get_str( data, "user", "key_id", NULL ) );
    savedhiAlgorithm out_algorithm = (savedhiAlgorithm)savedhi_marshal_data_get_num( data, "user", "algorithm", NULL );
    savedhiResultType out_defaultType = (savedhiResultType)savedhi_marshal_data_get_num( data, "user", "default_type", NULL );
    bool out_redacted = savedhi_marshal_data_get_bool( data, "export", "redacted", NULL );

    savedhi_string_pushf( &out, "# Date: %s\n", out_date );
    savedhi_string_pushf( &out, "# User Name: %s\n", out_fullName );
    savedhi_string_pushf( &out, "# Full Name: %s\n", out_fullName );
    savedhi_string_pushf( &out, "# Avatar: %u\n", out_avatar );
    savedhi_string_pushf( &out, "# Identicon: %s\n", out_identicon );
    savedhi_string_pushf( &out, "# Key ID: %s\n", out_keyID );
    savedhi_string_pushf( &out, "# Algorithm: %d\n", out_algorithm );
    savedhi_string_pushf( &out, "# Default Type: %d\n", out_defaultType );
    savedhi_string_pushf( &out, "# Passwords: %s\n", out_redacted? "PROTECTED": "VISIBLE" );
    savedhi_string_pushf( &out, "##\n" );
    savedhi_string_pushf( &out, "#\n" );
    savedhi_string_pushf( &out, "#%19s  %8s  %8s  %25s\t%25s\t%s\n", "Last", "Times", "Password", "Login", "Site", "Site" );
    savedhi_string_pushf( &out, "#%19s  %8s  %8s  %25s\t%25s\t%s\n", "used", "used", "type", "name", "name", "password" );

    // Sites.
    const char *typeString;
    const savedhiMarshalledData *sites = savedhi_marshal_data_find( data, "sites", NULL );
    for (size_t s = 0; s < (sites? sites->children_count: 0); ++s) {
        const savedhiMarshalledData *site = &sites->children[s];
        savedhi_string_pushf( &out, "%s  %8ld  %8s  %25s\t%25s\t%s\n",
                savedhi_default( "", savedhi_marshal_data_get_str( site, "last_used", NULL ) ),
                (long)savedhi_marshal_data_get_num( site, "uses", NULL ),
                typeString = savedhi_str( "%lu:%lu:%lu",
                        (long)savedhi_marshal_data_get_num( site, "type", NULL ),
                        (long)savedhi_marshal_data_get_num( site, "algorithm", NULL ),
                        (long)savedhi_marshal_data_get_num( site, "counter", NULL ) ),
                savedhi_default( "", savedhi_marshal_data_get_str( site, "login_name", NULL ) ),
                site->obj_key,
                savedhi_default( "", savedhi_marshal_data_get_str( site, "password", NULL ) ) );
        savedhi_free_string( &typeString );
    }

    if (!out)
        savedhi_marshal_error( file, savedhiMarshalErrorFormat,
                "Couldn't encode JSON." );
    else
        savedhi_marshal_error( file, savedhiMarshalSuccess, NULL );

    return out;
}

#if savedhi_JSON

static json_object *savedhi_get_json_data(
        const savedhiMarshalledData *data) {

    if (!data || data->is_null)
        return NULL;
    if (data->is_bool)
        return json_object_new_boolean( data->num_value != false );
    if (!isnan( data->num_value )) {
        if (data->str_value)
            return json_object_new_double_s( data->num_value, data->str_value );
        else
            return json_object_new_double( data->num_value );
    }
    if (data->str_value)
        return json_object_new_string( data->str_value );

    json_object *obj = NULL;
    for (size_t c = 0; c < data->children_count; ++c) {
        savedhiMarshalledData *child = &data->children[c];
        if (!obj) {
            if (child->obj_key)
                obj = json_object_new_object();
            else
                obj = json_object_new_array();
        }

        json_object *child_obj = savedhi_get_json_data( child );
        if (json_object_is_type( obj, json_type_array ))
            json_object_array_add( obj, child_obj );
        else if (child_obj && !(json_object_is_type( child_obj, json_type_object ) && json_object_object_length( child_obj ) == 0))
            // We omit keys that map to null or empty object values.
            json_object_object_add( obj, child->obj_key, child_obj );
        else
            json_object_put( child_obj );
    }

    return obj;
}

static const char *savedhi_marshal_write_json(
        savedhiMarshalledFile *file) {

    json_object *json_file = savedhi_get_json_data( file->data );
    if (!json_file) {
        savedhi_marshal_error( file, savedhiMarshalErrorFormat,
                "Couldn't serialize export data." );
        return NULL;
    }

    json_object *json_export = savedhi_get_json_object( json_file, "export", true );
    json_object_object_add( json_export, "format", json_object_new_int( 2 ) );

    const char *out = savedhi_strdup( json_object_to_json_string_ext( json_file,
            JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_NOSLASHESCAPE ) );
    json_object_put( json_file );

    if (!out)
        savedhi_marshal_error( file, savedhiMarshalErrorFormat,
                "Couldn't encode JSON." );
    else
        savedhi_marshal_error( file, savedhiMarshalSuccess, NULL );

    return out;
}

#endif

static bool savedhi_marshal_data_filter_site_exists(
        savedhiMarshalledData *child, void *args) {

    savedhiMarshalledUser *user = args;

    for (size_t s = 0; s < user->sites_count; ++s) {
        if (strcmp( (&user->sites[s])->siteName, child->obj_key ) == OK)
            return true;
    }

    return false;
}

static bool savedhi_marshal_data_filter_question_exists(
        savedhiMarshalledData *child, void *args) {

    savedhiMarshalledSite *site = args;

    for (size_t s = 0; s < site->questions_count; ++s) {
        if (strcmp( (&site->questions[s])->keyword, child->obj_key ) == OK)
            return true;
    }

    return false;
}

const char *savedhi_marshal_write(
        const savedhiFormat outFormat, savedhiMarshalledFile **file_, savedhiMarshalledUser *user) {

    savedhiMarshalledFile *file = file_? *file_: NULL;
    file = savedhi_marshal_file( file, NULL, file && file->data? file->data: savedhi_marshal_data_new() );
    if (file_)
        *file_ = file;
    if (!file)
        return NULL;
    if (!file->data) {
        if (!file_)
            savedhi_marshal_free( &file );
        else
            savedhi_marshal_error( file, savedhiMarshalErrorInternal,
                    "Couldn't allocate data." );
        return NULL;
    }
    savedhi_marshal_error( file, savedhiMarshalSuccess, NULL );

    if (user) {
        if (!user->userName || !strlen( user->userName )) {
            if (!file_)
                savedhi_marshal_free( &file );
            else
                savedhi_marshal_error( file, savedhiMarshalErrorMissing,
                        "Missing user name." );
            return NULL;
        }

        const savedhiUserKey *userKey = NULL;
        if (user->userKeyProvider)
            userKey = user->userKeyProvider( user->algorithm, user->userName );

        // Section: "export"
        savedhiMarshalledData *data_export = savedhi_marshal_data_get( file->data, "export", NULL );
        char dateString[21];
        time_t now = time( NULL );
        if (strftime( dateString, sizeof( dateString ), "%FT%TZ", gmtime( &now ) ))
            savedhi_marshal_data_set_str( dateString, data_export, "date", NULL );
        savedhi_marshal_data_set_bool( user->redacted, data_export, "redacted", NULL );

        // Section: "user"
        const char *loginState = NULL;
        if (!user->redacted) {
            // Clear Text
            savedhi_free( &userKey, sizeof( *userKey ) );
            if (!user->userKeyProvider || !(userKey = user->userKeyProvider( user->algorithm, user->userName ))) {
                if (!file_)
                    savedhi_marshal_free( &file );
                else
                    savedhi_marshal_error( file, savedhiMarshalErrorInternal,
                            "Couldn't derive user key." );
                return NULL;
            }

            loginState = savedhi_site_result( userKey, user->userName, user->loginType, user->loginState,
                    savedhiCounterInitial, savedhiKeyPurposeIdentification, NULL );
        }
        else {
            // Redacted
            if (user->loginType & savedhiResultFeatureExportContent && user->loginState && strlen( user->loginState ))
                loginState = savedhi_strdup( user->loginState );
        }

        const char *identiconString = savedhi_identicon_encode( user->identicon );
        savedhiMarshalledData *data_user = savedhi_marshal_data_get( file->data, "user", NULL );
        savedhi_marshal_data_set_num( user->avatar, data_user, "avatar", NULL );
        savedhi_marshal_data_set_str( user->userName, data_user, "full_name", NULL );
        savedhi_marshal_data_set_str( identiconString, data_user, "identicon", NULL );
        savedhi_marshal_data_set_num( user->algorithm, data_user, "algorithm", NULL );
        savedhi_marshal_data_set_str( user->keyID.hex, data_user, "key_id", NULL );
        savedhi_marshal_data_set_num( user->defaultType, data_user, "default_type", NULL );
        savedhi_marshal_data_set_num( user->loginType, data_user, "login_type", NULL );
        savedhi_marshal_data_set_str( loginState, data_user, "login_name", NULL );
        if (strftime( dateString, sizeof( dateString ), "%FT%TZ", gmtime( &user->lastUsed ) ))
            savedhi_marshal_data_set_str( dateString, data_user, "last_used", NULL );
        savedhi_free_strings( &identiconString, &loginState, NULL );

        // Section "sites"
        savedhiMarshalledData *data_sites = savedhi_marshal_data_get( file->data, "sites", NULL );
        savedhi_marshal_data_filter( data_sites, savedhi_marshal_data_filter_site_exists, user );
        for (size_t s = 0; s < user->sites_count; ++s) {
            savedhiMarshalledSite *site = &user->sites[s];
            if (!site->siteName || !strlen( site->siteName ))
                continue;

            const char *resultState = NULL;
            if (!user->redacted) {
                // Clear Text
                savedhi_free( &userKey, sizeof( *userKey ) );
                if (!user->userKeyProvider || !(userKey = user->userKeyProvider( site->algorithm, user->userName ))) {
                    if (!file_)
                        savedhi_marshal_free( &file );
                    else
                        savedhi_marshal_error( file, savedhiMarshalErrorInternal,
                                "Couldn't derive user key." );
                    return NULL;
                }

                resultState = savedhi_site_result( userKey, site->siteName,
                        site->resultType, site->resultState, site->counter, savedhiKeyPurposeAuthentication, NULL );
                loginState = savedhi_site_result( userKey, site->siteName,
                        site->loginType, site->loginState, savedhiCounterInitial, savedhiKeyPurposeIdentification, NULL );
            }
            else {
                // Redacted
                if (site->resultType & savedhiResultFeatureExportContent && site->resultState && strlen( site->resultState ))
                    resultState = savedhi_strdup( site->resultState );
                if (site->loginType & savedhiResultFeatureExportContent && site->loginState && strlen( site->loginState ))
                    loginState = savedhi_strdup( site->loginState );
            }

            savedhi_marshal_data_set_num( site->counter, data_sites, site->siteName, "counter", NULL );
            savedhi_marshal_data_set_num( site->algorithm, data_sites, site->siteName, "algorithm", NULL );
            savedhi_marshal_data_set_num( site->resultType, data_sites, site->siteName, "type", NULL );
            savedhi_marshal_data_set_str( resultState, data_sites, site->siteName, "password", NULL );
            savedhi_marshal_data_set_num( site->loginType, data_sites, site->siteName, "login_type", NULL );
            savedhi_marshal_data_set_str( loginState, data_sites, site->siteName, "login_name", NULL );
            savedhi_marshal_data_set_num( site->uses, data_sites, site->siteName, "uses", NULL );
            if (strftime( dateString, sizeof( dateString ), "%FT%TZ", gmtime( &site->lastUsed ) ))
                savedhi_marshal_data_set_str( dateString, data_sites, site->siteName, "last_used", NULL );

            savedhiMarshalledData *data_questions = savedhi_marshal_data_get( file->data, "sites", site->siteName, "questions", NULL );
            savedhi_marshal_data_filter( data_questions, savedhi_marshal_data_filter_question_exists, site );
            for (size_t q = 0; q < site->questions_count; ++q) {
                savedhiMarshalledQuestion *question = &site->questions[q];
                if (!question->keyword)
                    continue;

                const char *answer = NULL;
                if (!user->redacted) {
                    // Clear Text
                    answer = savedhi_site_result( userKey, site->siteName,
                            question->type, question->state, savedhiCounterInitial, savedhiKeyPurposeRecovery, question->keyword );
                }
                else {
                    // Redacted
                    if (question->state && strlen( question->state ) && site->resultType & savedhiResultFeatureExportContent)
                        answer = savedhi_strdup( question->state );
                }

                savedhi_marshal_data_set_num( question->type, data_questions, question->keyword, "type", NULL );
                savedhi_marshal_data_set_str( answer, data_questions, question->keyword, "answer", NULL );
                savedhi_free_strings( &answer, NULL );
            }

            savedhi_marshal_data_set_str( site->url, data_sites, site->siteName, "_ext_savedhi", "url", NULL );
            savedhi_free_strings( &resultState, &loginState, NULL );
        }
    }

    const char *out = NULL;
    switch (outFormat) {
        case savedhiFormatNone:
            savedhi_marshal_error( file, savedhiMarshalSuccess, NULL );
            break;
        case savedhiFormatFlat:
            out = savedhi_marshal_write_flat( file );
            break;
#if savedhi_JSON
        case savedhiFormatJSON:
            out = savedhi_marshal_write_json( file );
            break;
#endif
        default:
            savedhi_marshal_error( file, savedhiMarshalErrorFormat,
                    "Unsupported output format: %u", outFormat );
            break;
    }
    if (out && file->error.type == savedhiMarshalSuccess)
        file = savedhi_marshal_read( file, out );
    if (file_)
        *file_ = file;
    else
        savedhi_marshal_free( &file );

    return out;
}

static void savedhi_marshal_read_flat(
        savedhiMarshalledFile *file, const char *in) {

    if (!file)
        return;

    savedhi_marshal_file( file, NULL, savedhi_marshal_data_new() );
    if (!file->data) {
        savedhi_marshal_error( file, savedhiMarshalErrorInternal,
                "Couldn't allocate data." );
        return;
    }

    // Parse import data.
    unsigned int format = 0, avatar = 0;
    const char *userName = NULL, *keyID = NULL;
    savedhiAlgorithm algorithm = savedhiAlgorithmCurrent;
    savedhiIdenticon identicon = savedhiIdenticonUnset;
    savedhiResultType defaultType = savedhiResultDefaultResult;
    time_t exportDate = 0;
    bool headerStarted = false, headerEnded = false, importRedacted = false;
    for (const char *endOfLine, *positionInLine = in; (endOfLine = strstr( positionInLine, "\n" )); positionInLine = endOfLine + 1) {

        // Comment or header
        if (*positionInLine == '#') {
            ++positionInLine;

            if (!headerStarted) {
                if (*positionInLine == '#')
                    // ## starts header
                    headerStarted = true;
                // Comment before header
                continue;
            }
            if (headerEnded)
                // Comment after header
                continue;
            if (*positionInLine == '#') {
                // ## ends header
                headerEnded = true;

                char dateString[21];
                const char *identiconString = savedhi_identicon_encode( identicon );

                if (strftime( dateString, sizeof( dateString ), "%FT%TZ", gmtime( &exportDate ) )) {
                    savedhi_marshal_data_set_str( dateString, file->data, "export", "date", NULL );
                    savedhi_marshal_data_set_str( dateString, file->data, "user", "last_used", NULL );
                }
                savedhi_marshal_data_set_num( algorithm, file->data, "user", "algorithm", NULL );
                savedhi_marshal_data_set_bool( importRedacted, file->data, "export", "redacted", NULL );
                savedhi_marshal_data_set_num( avatar, file->data, "user", "avatar", NULL );
                savedhi_marshal_data_set_str( userName, file->data, "user", "full_name", NULL );
                savedhi_marshal_data_set_str( identiconString, file->data, "user", "identicon", NULL );
                savedhi_marshal_data_set_str( keyID, file->data, "user", "key_id", NULL );
                savedhi_marshal_data_set_num( defaultType, file->data, "user", "default_type", NULL );
                savedhi_free_string( &identiconString );
                continue;
            }

            // Header
            const char *line = positionInLine;
            const char *headerName = savedhi_get_token( &positionInLine, endOfLine, ":\n" );
            const char *headerValue = savedhi_get_token( &positionInLine, endOfLine, "\n" );
            if (!headerName || !headerValue) {
                savedhi_marshal_error( file, savedhiMarshalErrorStructure,
                        "Invalid header: %s", savedhi_strndup( line, (size_t)(endOfLine - line) ) );
                savedhi_free_strings( &headerName, &headerValue, NULL );
                continue;
            }

            if (savedhi_strcasecmp( headerName, "Format" ) == OK)
                format = (unsigned int)strtoul( headerValue, NULL, 10 );
            if (savedhi_strcasecmp( headerName, "Date" ) == OK)
                exportDate = savedhi_get_timegm( headerValue );
            if (savedhi_strcasecmp( headerName, "Passwords" ) == OK)
                importRedacted = savedhi_strcasecmp( headerValue, "VISIBLE" ) != OK;
            if (savedhi_strcasecmp( headerName, "Algorithm" ) == OK) {
                unsigned long value = strtoul( headerValue, NULL, 10 );
                if (value < savedhiAlgorithmFirst || value > savedhiAlgorithmLast)
                    savedhi_marshal_error( file, savedhiMarshalErrorIllegal,
                            "Invalid user algorithm version: %s", headerValue );
                else
                    algorithm = (savedhiAlgorithm)value;
            }
            if (savedhi_strcasecmp( headerName, "Avatar" ) == OK)
                avatar = (unsigned int)strtoul( headerValue, NULL, 10 );
            if (savedhi_strcasecmp( headerName, "Full Name" ) == OK || savedhi_strcasecmp( headerName, "User Name" ) == OK)
                userName = savedhi_strdup( headerValue );
            if (savedhi_strcasecmp( headerName, "Identicon" ) == OK)
                identicon = savedhi_identicon_encoded( headerValue );
            if (savedhi_strcasecmp( headerName, "Key ID" ) == OK)
                keyID = savedhi_strdup( headerValue );
            if (savedhi_strcasecmp( headerName, "Default Type" ) == OK) {
                unsigned long value = strtoul( headerValue, NULL, 10 );
                if (!savedhi_type_short_name( (savedhiResultType)value ))
                    savedhi_marshal_error( file, savedhiMarshalErrorIllegal,
                            "Invalid user default type: %s", headerValue );
                else
                    defaultType = (savedhiResultType)value;
            }

            savedhi_free_strings( &headerName, &headerValue, NULL );
            continue;
        }
        if (!headerEnded)
            continue;
        if (!userName)
            savedhi_marshal_error( file, savedhiMarshalErrorMissing,
                    "Missing header: Full Name" );
        if (positionInLine >= endOfLine)
            continue;

        // Site
        const char *siteName = NULL, *siteResultState = NULL, *siteLoginState = NULL;
        const char *str_lastUsed = NULL, *str_uses = NULL, *str_type = NULL, *str_algorithm = NULL, *str_counter = NULL;
        switch (format) {
            case 0: {
                str_lastUsed = savedhi_get_token( &positionInLine, endOfLine, " \t\n" );
                str_uses = savedhi_get_token( &positionInLine, endOfLine, " \t\n" );
                char *typeAndVersion = (char *)savedhi_get_token( &positionInLine, endOfLine, " \t\n" );
                if (typeAndVersion) {
                    str_type = savedhi_strdup( strtok( typeAndVersion, ":" ) );
                    str_algorithm = savedhi_strdup( strtok( NULL, "" ) );
                    savedhi_free_string( &typeAndVersion );
                }
                str_counter = savedhi_str( "%u", savedhiCounterDefault );
                siteLoginState = NULL;
                siteName = savedhi_get_token( &positionInLine, endOfLine, "\t\n" );
                siteResultState = savedhi_get_token( &positionInLine, endOfLine, "\n" );
                break;
            }
            case 1: {
                str_lastUsed = savedhi_get_token( &positionInLine, endOfLine, " \t\n" );
                str_uses = savedhi_get_token( &positionInLine, endOfLine, " \t\n" );
                char *typeAndVersionAndCounter = (char *)savedhi_get_token( &positionInLine, endOfLine, " \t\n" );
                if (typeAndVersionAndCounter) {
                    str_type = savedhi_strdup( strtok( typeAndVersionAndCounter, ":" ) );
                    str_algorithm = savedhi_strdup( strtok( NULL, ":" ) );
                    str_counter = savedhi_strdup( strtok( NULL, "" ) );
                    savedhi_free_string( &typeAndVersionAndCounter );
                }
                siteLoginState = savedhi_get_token( &positionInLine, endOfLine, "\t\n" );
                siteName = savedhi_get_token( &positionInLine, endOfLine, "\t\n" );
                siteResultState = savedhi_get_token( &positionInLine, endOfLine, "\n" );
                break;
            }
            default: {
                savedhi_marshal_error( file, savedhiMarshalErrorFormat,
                        "Unexpected import format: %u", format );
                continue;
            }
        }

        if (siteName && str_type && str_counter && str_algorithm && str_uses && str_lastUsed) {
            savedhiResultType siteResultType = (savedhiResultType)strtoul( str_type, NULL, 10 );
            if (!savedhi_type_short_name( siteResultType )) {
                savedhi_marshal_error( file, savedhiMarshalErrorIllegal,
                        "Invalid site type: %s: %s", siteName, str_type );
                continue;
            }
            long long int value = strtoll( str_counter, NULL, 10 );
            if (value < savedhiCounterFirst || value > savedhiCounterLast) {
                savedhi_marshal_error( file, savedhiMarshalErrorIllegal,
                        "Invalid site counter: %s: %s", siteName, str_counter );
                continue;
            }
            savedhiCounter siteKeyCounter = (savedhiCounter)value;
            value = strtoll( str_algorithm, NULL, 0 );
            if (value < savedhiAlgorithmFirst || value > savedhiAlgorithmLast) {
                savedhi_marshal_error( file, savedhiMarshalErrorIllegal,
                        "Invalid site algorithm: %s: %s", siteName, str_algorithm );
                continue;
            }
            savedhiAlgorithm siteAlgorithm = (savedhiAlgorithm)value;
            time_t siteLastUsed = savedhi_get_timegm( str_lastUsed );
            if (!siteLastUsed) {
                savedhi_marshal_error( file, savedhiMarshalErrorIllegal,
                        "Invalid site last used: %s: %s", siteName, str_lastUsed );
                continue;
            }
            savedhiResultType siteLoginType = siteLoginState && *siteLoginState? savedhiResultStatePersonal: savedhiResultNone;

            char dateString[21];
            savedhi_marshal_data_set_num( siteAlgorithm, file->data, "sites", siteName, "algorithm", NULL );
            savedhi_marshal_data_set_num( siteKeyCounter, file->data, "sites", siteName, "counter", NULL );
            savedhi_marshal_data_set_num( siteResultType, file->data, "sites", siteName, "type", NULL );
            savedhi_marshal_data_set_str( siteResultState, file->data, "sites", siteName, "password", NULL );
            savedhi_marshal_data_set_num( siteLoginType, file->data, "sites", siteName, "login_type", NULL );
            savedhi_marshal_data_set_str( siteLoginState, file->data, "sites", siteName, "login_name", NULL );
            savedhi_marshal_data_set_num( strtol( str_uses, NULL, 10 ), file->data, "sites", siteName, "uses", NULL );
            if (strftime( dateString, sizeof( dateString ), "%FT%TZ", gmtime( &siteLastUsed ) ))
                savedhi_marshal_data_set_str( dateString, file->data, "sites", siteName, "last_used", NULL );
        }
        else {
            savedhi_marshal_error( file, savedhiMarshalErrorMissing,
                    "Missing one of: lastUsed=%s, uses=%s, type=%s, version=%s, counter=%s, loginName=%s, siteName=%s",
                    str_lastUsed, str_uses, str_type, str_algorithm, str_counter, siteLoginState, siteName );
            continue;
        }

        savedhi_free_strings( &str_lastUsed, &str_uses, &str_type, &str_algorithm, &str_counter, NULL );
        savedhi_free_strings( &siteLoginState, &siteName, &siteResultState, NULL );
    }
    savedhi_free_strings( &userName, &keyID, NULL );
}

#if savedhi_JSON

static void savedhi_marshal_read_json(
        savedhiMarshalledFile *file, const char *in) {

    if (!file)
        return;

    savedhi_marshal_file( file, NULL, savedhi_marshal_data_new() );
    if (!file->data) {
        savedhi_marshal_error( file, savedhiMarshalErrorInternal,
                "Couldn't allocate data." );
        return;
    }

    // Parse import data.
    enum json_tokener_error json_error = json_tokener_success;
    json_object *json_file = json_tokener_parse_verbose( in, &json_error );
    if (!json_file || json_error != json_tokener_success) {
        savedhi_marshal_error( file, savedhiMarshalErrorFormat,
                "Couldn't parse JSON: %s", json_tokener_error_desc( json_error ) );
        return;
    }

    savedhi_set_json_data( file->data, json_file );
    json_object_put( json_file );

    // version 1 fixes:
    if (savedhi_marshal_data_get_num( file->data, "export", "format", NULL ) == 1) {
        savedhiMarshalledData *sites = (savedhiMarshalledData *)savedhi_marshal_data_find( file->data, "sites", NULL );

        // - default login_type "name" written to file, preventing adoption of user-level standard login_type.
        for (size_t s = 0; s < (sites? sites->children_count: 0); ++s) {
            savedhiMarshalledData *site = &sites->children[s];
            if (savedhi_marshal_data_get_num( site, "login_type", NULL ) == savedhiResultTemplateName)
                savedhi_marshal_data_set_null( site, "login_type", NULL );
        }
    }

    return;
}

#endif

savedhiMarshalledFile *savedhi_marshal_read(
        savedhiMarshalledFile *file, const char *in) {

    savedhiMarshalledInfo *info = malloc( sizeof( savedhiMarshalledInfo ) );
    file = savedhi_marshal_file( file, info, NULL );
    if (!file)
        return NULL;

    savedhi_marshal_error( file, savedhiMarshalSuccess, NULL );
    if (!info) {
        savedhi_marshal_error( file, savedhiMarshalErrorInternal,
                "Couldn't allocate info." );
        return file;
    }

    *info = (savedhiMarshalledInfo){ .format = savedhiFormatNone, .identicon = savedhiIdenticonUnset };
    if (in && strlen( in )) {
        if (in[0] == '#') {
            info->format = savedhiFormatFlat;
            savedhi_marshal_read_flat( file, in );
        }
        else if (in[0] == '{') {
            info->format = savedhiFormatJSON;
#if savedhi_JSON
            savedhi_marshal_read_json( file, in );
#else
            savedhi_marshal_error( file, savedhiMarshalErrorFormat,
                    "JSON support is not enabled." );
#endif
        }
    }

    // Section: "export"
    info->exportDate = savedhi_get_timegm( savedhi_marshal_data_get_str( file->data, "export", "date", NULL ) );
    info->redacted = savedhi_marshal_data_get_bool( file->data, "export", "redacted", NULL )
                     || savedhi_marshal_data_is_null( file->data, "export", "redacted", NULL );

    // Section: "user"
    info->algorithm = savedhi_default_num( savedhiAlgorithmCurrent, savedhi_marshal_data_get_num( file->data, "user", "algorithm", NULL ) );
    info->avatar = savedhi_default_num( 0U, savedhi_marshal_data_get_num( file->data, "user", "avatar", NULL ) );
    info->userName = savedhi_strdup( savedhi_marshal_data_get_str( file->data, "user", "full_name", NULL ) );
    info->identicon = savedhi_identicon_encoded( savedhi_marshal_data_get_str( file->data, "user", "identicon", NULL ) );
    info->keyID = savedhi_id_str( savedhi_marshal_data_get_str( file->data, "user", "key_id", NULL ) );
    info->lastUsed = savedhi_get_timegm( savedhi_marshal_data_get_str( file->data, "user", "last_used", NULL ) );

    return file;
}

savedhiMarshalledUser *savedhi_marshal_auth(
        savedhiMarshalledFile *file, const savedhiKeyProvider userKeyProvider) {

    if (!file)
        return NULL;

    savedhi_marshal_error( file, savedhiMarshalSuccess, NULL );
    if (!file->info) {
        savedhi_marshal_error( file, savedhiMarshalErrorMissing,
                "File wasn't parsed yet." );
        return NULL;
    }
    if (!file->data) {
        savedhi_marshal_error( file, savedhiMarshalErrorMissing,
                "No input data." );
        return NULL;
    }
    const savedhiMarshalledData *userData = savedhi_marshal_data_find( file->data, "user", NULL );
    if (!userData) {
        savedhi_marshal_error( file, savedhiMarshalErrorMissing,
                "Missing user data." );
        return NULL;
    }

    // Section: "user"
    bool fileRedacted = savedhi_marshal_data_get_bool( file->data, "export", "redacted", NULL )
                        || savedhi_marshal_data_is_null( file->data, "export", "redacted", NULL );

    savedhiAlgorithm algorithm = savedhi_default_num( savedhiAlgorithmCurrent,
            savedhi_marshal_data_get_num( userData, "algorithm", NULL ) );
    if (algorithm < savedhiAlgorithmFirst || algorithm > savedhiAlgorithmLast) {
        savedhi_marshal_error( file, savedhiMarshalErrorIllegal,
                "Invalid user algorithm: %u", algorithm );
        return NULL;
    }

    unsigned int avatar = savedhi_default_num( 0U,
            savedhi_marshal_data_get_num( userData, "avatar", NULL ) );

    const char *userName = savedhi_marshal_data_get_str( userData, "full_name", NULL );
    if (!userName || !strlen( userName )) {
        savedhi_marshal_error( file, savedhiMarshalErrorMissing,
                "Missing value for user name." );
        return NULL;
    }

    savedhiIdenticon identicon = savedhi_identicon_encoded( savedhi_marshal_data_get_str( userData, "identicon", NULL ) );

    savedhiKeyID keyID = savedhi_id_str( savedhi_marshal_data_get_str( userData, "key_id", NULL ) );

    savedhiResultType defaultType = savedhi_default_num( savedhiResultDefaultResult,
            savedhi_marshal_data_get_num( userData, "default_type", NULL ) );
    if (!savedhi_type_short_name( defaultType )) {
        savedhi_marshal_error( file, savedhiMarshalErrorIllegal,
                "Invalid user default type: %u", defaultType );
        return NULL;
    }

    savedhiResultType loginType = savedhi_default_num( savedhiResultDefaultLogin,
            savedhi_marshal_data_get_num( userData, "login_type", NULL ) );
    if (!savedhi_type_short_name( loginType )) {
        savedhi_marshal_error( file, savedhiMarshalErrorIllegal,
                "Invalid user login type: %u", loginType );
        return NULL;
    }

    const char *loginState = savedhi_marshal_data_get_str( userData, "login_name", NULL );

    const char *str_lastUsed = savedhi_marshal_data_get_str( userData, "last_used", NULL );

    time_t lastUsed = savedhi_get_timegm( str_lastUsed );
    if (!lastUsed) {
        savedhi_marshal_error( file, savedhiMarshalErrorIllegal,
                "Invalid user last used: %s", str_lastUsed );
        return NULL;
    }

    const savedhiUserKey *userKey = NULL;
    if (userKeyProvider && !(userKey = userKeyProvider( algorithm, userName ))) {
        savedhi_marshal_error( file, savedhiMarshalErrorInternal,
                "Couldn't derive user key." );
        return NULL;
    }
    if (userKey && !savedhi_id_equals( &keyID, &userKey->keyID )) {
        savedhi_marshal_error( file, savedhiMarshalErrorUserSecret,
                "User key: %s, doesn't match keyID: %s.", userKey->keyID.hex, keyID.hex );
        savedhi_free( &userKey, sizeof( *userKey ) );
        return NULL;
    }

    savedhiMarshalledUser *user = NULL;
    if (!(user = savedhi_marshal_user( userName, userKeyProvider, algorithm ))) {
        savedhi_marshal_error( file, savedhiMarshalErrorInternal,
                "Couldn't allocate a new user." );
        savedhi_free( &userKey, sizeof( *userKey ) );
        savedhi_marshal_free( &user );
        return NULL;
    }

    user->redacted = fileRedacted;
    user->avatar = avatar;
    user->identicon = identicon;
    user->keyID = keyID;
    user->defaultType = defaultType;
    user->loginType = loginType;
    user->lastUsed = lastUsed;

    if (!user->redacted) {
        // Clear Text
        savedhi_free( &userKey, sizeof( *userKey ) );
        if (!userKeyProvider || !(userKey = userKeyProvider( user->algorithm, user->userName ))) {
            savedhi_marshal_error( file, savedhiMarshalErrorInternal,
                    "Couldn't derive user key." );
            savedhi_free( &userKey, sizeof( *userKey ) );
            savedhi_marshal_free( &user );
            return NULL;
        }

        if (loginState && strlen( loginState ) && userKey)
            user->loginState = savedhi_site_state( userKey, user->userName, user->loginType, loginState,
                    savedhiCounterInitial, savedhiKeyPurposeIdentification, NULL );
    }
    else {
        // Redacted
        if (loginState && strlen( loginState ))
            user->loginState = savedhi_strdup( loginState );
    }

    // Section "sites"
    const savedhiMarshalledData *sitesData = savedhi_marshal_data_find( file->data, "sites", NULL );
    for (size_t s = 0; s < (sitesData? sitesData->children_count: 0); ++s) {
        const savedhiMarshalledData *siteData = &sitesData->children[s];
        const char *siteName = siteData->obj_key;

        algorithm = savedhi_default_num( user->algorithm,
                savedhi_marshal_data_get_num( siteData, "algorithm", NULL ) );
        if (algorithm < savedhiAlgorithmFirst || algorithm > savedhiAlgorithmLast) {
            savedhi_marshal_error( file, savedhiMarshalErrorIllegal,
                    "Invalid site algorithm: %s: %u", siteName, algorithm );
            savedhi_free( &userKey, sizeof( *userKey ) );
            savedhi_marshal_free( &user );
            return NULL;
        }
        savedhiCounter siteCounter = savedhi_default_num( savedhiCounterDefault,
                savedhi_marshal_data_get_num( siteData, "counter", NULL ) );
        if (siteCounter < savedhiCounterFirst || siteCounter > savedhiCounterLast) {
            savedhi_marshal_error( file, savedhiMarshalErrorIllegal,
                    "Invalid site result counter: %s: %d", siteName, siteCounter );
            savedhi_free( &userKey, sizeof( *userKey ) );
            savedhi_marshal_free( &user );
            return NULL;
        }
        savedhiResultType siteResultType = savedhi_default_num( user->defaultType,
                savedhi_marshal_data_get_num( siteData, "type", NULL ) );
        if (!savedhi_type_short_name( siteResultType )) {
            savedhi_marshal_error( file, savedhiMarshalErrorIllegal,
                    "Invalid site result type: %s: %u", siteName, siteResultType );
            savedhi_free( &userKey, sizeof( *userKey ) );
            savedhi_marshal_free( &user );
            return NULL;
        }
        const char *siteResultState = savedhi_marshal_data_get_str( siteData, "password", NULL );
        savedhiResultType siteLoginType = savedhi_default_num( savedhiResultNone,
                savedhi_marshal_data_get_num( siteData, "login_type", NULL ) );
        if (!savedhi_type_short_name( siteLoginType )) {
            savedhi_marshal_error( file, savedhiMarshalErrorIllegal,
                    "Invalid site login type: %s: %u", siteName, siteLoginType );
            savedhi_free( &userKey, sizeof( *userKey ) );
            savedhi_marshal_free( &user );
            return NULL;
        }
        const char *siteLoginState = savedhi_marshal_data_get_str( siteData, "login_name", NULL );
        unsigned int siteUses = savedhi_default_num( 0U,
                savedhi_marshal_data_get_num( siteData, "uses", NULL ) );
        str_lastUsed = savedhi_marshal_data_get_str( siteData, "last_used", NULL );
        time_t siteLastUsed = savedhi_get_timegm( str_lastUsed );
        if (!siteLastUsed) {
            savedhi_marshal_error( file, savedhiMarshalErrorIllegal,
                    "Invalid site last used: %s: %s", siteName, str_lastUsed );
            savedhi_free( &userKey, sizeof( *userKey ) );
            savedhi_marshal_free( &user );
            return NULL;
        }

        const char *siteURL = savedhi_marshal_data_get_str( siteData, "_ext_savedhi", "url", NULL );

        savedhiMarshalledSite *site = savedhi_marshal_site( user, siteName, siteResultType, siteCounter, algorithm );
        if (!site) {
            savedhi_marshal_error( file, savedhiMarshalErrorInternal,
                    "Couldn't allocate a new site." );
            savedhi_free( &userKey, sizeof( *userKey ) );
            savedhi_marshal_free( &user );
            return NULL;
        }

        site->loginType = siteLoginType;
        site->url = siteURL? savedhi_strdup( siteURL ): NULL;
        site->uses = siteUses;
        site->lastUsed = siteLastUsed;
        if (!user->redacted) {
            // Clear Text
            savedhi_free( &userKey, sizeof( *userKey ) );
            if (!userKeyProvider || !(userKey = userKeyProvider( site->algorithm, user->userName ))) {
                savedhi_marshal_error( file, savedhiMarshalErrorInternal,
                        "Couldn't derive user key." );
                savedhi_free( &userKey, sizeof( *userKey ) );
                savedhi_marshal_free( &user );
                return NULL;
            }

            if (siteResultState && strlen( siteResultState ) && userKey)
                site->resultState = savedhi_site_state( userKey, site->siteName,
                        site->resultType, siteResultState, site->counter, savedhiKeyPurposeAuthentication, NULL );
            if (siteLoginState && strlen( siteLoginState ) && userKey)
                site->loginState = savedhi_site_state( userKey, site->siteName,
                        site->loginType, siteLoginState, savedhiCounterInitial, savedhiKeyPurposeIdentification, NULL );
        }
        else {
            // Redacted
            if (siteResultState && strlen( siteResultState ))
                site->resultState = savedhi_strdup( siteResultState );
            if (siteLoginState && strlen( siteLoginState ))
                site->loginState = savedhi_strdup( siteLoginState );
        }

        const savedhiMarshalledData *questions = savedhi_marshal_data_find( siteData, "questions", NULL );
        for (size_t q = 0; q < (questions? questions->children_count: 0); ++q) {
            const savedhiMarshalledData *questionData = &questions->children[q];
            savedhiMarshalledQuestion *question = savedhi_marshal_question( site, questionData->obj_key );
            const char *answerState = savedhi_marshal_data_get_str( questionData, "answer", NULL );
            question->type = savedhi_default_num( savedhiResultTemplatePhrase,
                    savedhi_marshal_data_get_num( questionData, "type", NULL ) );

            if (!user->redacted) {
                // Clear Text
                if (answerState && strlen( answerState ) && userKey)
                    question->state = savedhi_site_state( userKey, site->siteName,
                            question->type, answerState, savedhiCounterInitial, savedhiKeyPurposeRecovery, question->keyword );
            }
            else {
                // Redacted
                if (answerState && strlen( answerState ))
                    question->state = savedhi_strdup( answerState );
            }
        }
    }
    savedhi_free( &userKey, sizeof( *userKey ) );

    return user;
}

const savedhiFormat savedhi_format_named(
        const char *formatName) {

    if (!formatName || !strlen( formatName ))
        return savedhiFormatNone;

    if (savedhi_strncasecmp( savedhi_format_name( savedhiFormatNone ), formatName, strlen( formatName ) ) == OK)
        return savedhiFormatNone;
    if (savedhi_strncasecmp( savedhi_format_name( savedhiFormatFlat ), formatName, strlen( formatName ) ) == OK)
        return savedhiFormatFlat;
    if (savedhi_strncasecmp( savedhi_format_name( savedhiFormatJSON ), formatName, strlen( formatName ) ) == OK)
        return savedhiFormatJSON;

    wrn( "Not a format name: %s", formatName );
    return (savedhiFormat)ERR;
}

const char *savedhi_format_name(
        const savedhiFormat format) {

    switch (format) {
        case savedhiFormatNone:
            return "none";
        case savedhiFormatFlat:
            return "flat";
        case savedhiFormatJSON:
            return "json";
        default: {
            wrn( "Unknown format: %d", format );
            return NULL;
        }
    }
}

const char *savedhi_format_extension(
        const savedhiFormat format) {

    switch (format) {
        case savedhiFormatNone:
            return NULL;
        case savedhiFormatFlat:
            return "mpsites";
        case savedhiFormatJSON:
            return "mpjson";
        default: {
            wrn( "Unknown format: %d", format );
            return NULL;
        }
    }
}

const char **savedhi_format_extensions(
        const savedhiFormat format, size_t *count) {

    *count = 0;
    switch (format) {
        case savedhiFormatNone:
            return NULL;
        case savedhiFormatFlat:
            return savedhi_strings( count,
                    savedhi_format_extension( format ), "mpsites.txt", "txt", NULL );
        case savedhiFormatJSON:
            return savedhi_strings( count,
                    savedhi_format_extension( format ), "mpsites.json", "json", NULL );
        default: {
            wrn( "Unknown format: %d", format );
            return NULL;
        }
    }
}
