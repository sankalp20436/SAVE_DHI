// =============================================================================
// Created by Maarten Billemont on 2019-11-27.
// Copyright (c) 2011, Maarten Billemont.
//
// This file is part of savedhi.
// savedhi is free software. You can modify it under the terms of
// the GNU General Public License, either version 3 or any later version.
// See the LICENSE file for details or consult <http://www.gnu.org/licenses/>.
//
// Note: this grant does not include any rights for use of savedhi's trademarks.
// =============================================================================

#ifndef _savedhi_ALGORITHM_V3_H
#define _savedhi_ALGORITHM_V3_H

#include "savedhi-algorithm_v2.h"

const char *savedhi_type_template_v3(
        savedhiResultType type, uint16_t templateIndex);
const char savedhi_class_character_v3(
        char characterClass, uint16_t classIndex);
bool savedhi_user_key_v3(
        const savedhiUserKey *userKey, const char *userName, const char *userSecret);
bool savedhi_site_key_v3(
        const savedhiSiteKey *siteKey, const savedhiUserKey *userKey, const char *siteName,
        savedhiCounter keyCounter, savedhiKeyPurpose keyPurpose, const char *keyContext);
const char *savedhi_site_template_password_v3(
        const savedhiUserKey *userKey, const savedhiSiteKey *siteKey, savedhiResultType resultType, const char *resultParam);
const char *savedhi_site_crypted_password_v3(
        const savedhiUserKey *userKey, const savedhiSiteKey *siteKey, savedhiResultType resultType, const char *cipherText);
const char *savedhi_site_derived_password_v3(
        const savedhiUserKey *userKey, const savedhiSiteKey *siteKey, savedhiResultType resultType, const char *resultParam);
const char *savedhi_site_state_v3(
        const savedhiUserKey *userKey, const savedhiSiteKey *siteKey, savedhiResultType resultType, const char *plainText);

#endif // _savedhi_ALGORITHM_V3_H
