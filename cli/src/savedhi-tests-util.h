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

//
//  savedhi-tests-util.h
//  savedhi
//
//  Created by Maarten Billemont on 2014-12-21.
//  Copyright (c) 2014 Lyndir. All rights reserved.
//

#include <libxml/parser.h>

xmlNodePtr savedhi_xmlTestCaseNode(
        xmlNodePtr testCaseNode, const char *nodeName);
xmlChar *savedhi_xmlTestCaseString(
        xmlNodePtr context, const char *nodeName);
uint32_t savedhi_xmlTestCaseInteger(
        xmlNodePtr context, const char *nodeName);
