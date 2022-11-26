//==============================================================================
// This file is part of savedhi.
// Copyright (c) 2011-2017, Maarten Billemont.
//
// savedhi is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// savedhi is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You can find a copy of the GNU General Public License in the
// LICENSE file.  Alternatively, see <http://www.gnu.org/licenses/>.
//==============================================================================

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include "savedhi-types.h"

#ifndef savedhi_VERSION
#define savedhi_VERSION ?
#endif

#define savedhi_ENV_userName     "savedhi_USERNAME"
#define savedhi_ENV_algorithm    "savedhi_ALGORITHM"
#define savedhi_ENV_format       "savedhi_FORMAT"
#define savedhi_ENV_askpass      "savedhi_ASKPASS"

/** Read the value of an environment variable.
  * @return A newly allocated string or NULL if the variable doesn't exist. */
const char *savedhi_getenv(const char *variableName);

/** Use the askpass program to prompt the user.
  * @return A newly allocated string or NULL if askpass is not enabled or could not be executed. */
const char *savedhi_askpass(const char *prompt);

/** Ask the user a question.
  * @return A newly allocated string or NULL if an error occurred trying to read from the user. */
const char *savedhi_getline(const char *prompt);

/** Ask the user for a password.
  * @return A newly allocated string or NULL if an error occurred trying to read from the user. */
const char *savedhi_getpass(const char *prompt);

/** Get the absolute path to the savedhi configuration file with the given prefix name and file extension.
  * Resolves the file <prefix.extension> as located in the <.savedhi.d> directory inside the user's home directory
  * or current directory if it couldn't be resolved.
  * @return A newly allocated string or NULL if the prefix or extension is missing or the path could not be allocated. */
const char *savedhi_path(const char *prefix, const char *extension);

/** mkdir all the directories up to the directory of the given file path.
  * @return true if the file's path exists. */
bool savedhi_mkdirs(const char *filePath);

/** Read until EOF from the given file descriptor.
  * @return A newly allocated string or NULL if the an IO error occurred or the read buffer couldn't be allocated. */
const char *savedhi_read_fd(int fd);

/** Read the file contents of a given file.
  * @return A newly allocated string or NULL if the file is missing, an IO error occurred or the read buffer couldn't be allocated. */
const char *savedhi_read_file(FILE *file);

/** Encode a visual fingerprint for a user.
  * @return A newly allocated string or NULL if the identicon couldn't be allocated. */
const char *savedhi_identicon_render(savedhiIdenticon identicon);
