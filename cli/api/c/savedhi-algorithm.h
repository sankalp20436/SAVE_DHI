// =============================================================================
// Created by Maarten Billemont on 2014-12-19.
// Copyright (c) 2011, Maarten Billemont.
//
// This file is part of savedhi.
// savedhi is free software. You can modify it under the terms of
// the GNU General Public License, either version 3 or any later version.
// See the LICENSE file for details or consult <http://www.gnu.org/licenses/>.
//
// Note: this grant does not include any rights for use of savedhi's trademarks.
// =============================================================================

#ifndef _savedhi_ALGORITHM_H
#define _savedhi_ALGORITHM_H

#include "savedhi-types.h"

/** Derive the user key for a user based on their name and user secret.
 * @return A savedhiUserKey value (allocated) or NULL if the userName or userSecret is missing, the algorithm is unknown, or an algorithm error occurred. */
const savedhiUserKey *savedhi_user_key(
        const char *userName, const char *userSecret, const savedhiAlgorithm algorithmVersion);

/** Generate a result token for a user from the user's user key and result parameters.
 * @param resultParam A parameter for the resultType.  For stateful result types, the output of savedhi_site_state.
 * @return A C-string (allocated) or NULL if the userKey or siteName is missing, the algorithm is unknown, or an algorithm error occurred. */
const char *savedhi_site_result(
        const savedhiUserKey *userKey, const char *siteName,
        const savedhiResultType resultType, const char *resultParam,
        const savedhiCounter keyCounter, const savedhiKeyPurpose keyPurpose, const char *keyContext);

/** Encrypt a result token for stateful persistence.
 * @param resultParam A parameter for the resultType.  For stateful result types, the desired savedhi_site_result.
 * @return A C-string (allocated) or NULL if the userKey, siteName or resultType's resultParam is missing, the algorithm is unknown, or an algorithm error occurred. */
const char *savedhi_site_state(
        const savedhiUserKey *userKey, const char *siteName,
        const savedhiResultType resultType, const char *resultParam,
        const savedhiCounter keyCounter, const savedhiKeyPurpose keyPurpose, const char *keyContext);

/** Derive the result key for a user from the user's user key and result parameters.
 * @return An savedhiSiteKey value (allocated) or NULL if the userKey or siteName is missing, the algorithm is unknown, or an algorithm error occurred. */
const savedhiSiteKey *savedhi_site_key(
        const savedhiUserKey *userKey, const char *siteName,
        const savedhiCounter keyCounter, const savedhiKeyPurpose keyPurpose, const char *keyContext);

/** @return An identicon (static) that represents the user's identity. */
const savedhiIdenticon savedhi_identicon(
        const char *userName, const char *userSecret);
/** @return A C-string encoded representation (allocated) of the given identicon or NULL if the identicon is unset. */
const char *savedhi_identicon_encode(
        const savedhiIdenticon identicon);
/** @return An identicon (static) decoded from the given encoded identicon representation or an identicon with empty fields if the identicon could not be parsed. */
const savedhiIdenticon savedhi_identicon_encoded(
        const char *encoding);

#endif // _savedhi_ALGORITHM_H
