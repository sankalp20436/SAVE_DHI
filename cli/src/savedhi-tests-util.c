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
//  savedhi-tests-util.c
//  savedhi
//
//  Created by Maarten Billemont on 2014-12-21.
//  Copyright (c) 2014 Lyndir. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "savedhi-util.h"

#include "savedhi-tests-util.h"

xmlNodePtr savedhi_xmlTestCaseNode(xmlNodePtr testCaseNode, const char *nodeName) {

    if (!nodeName)
        return NULL;

    // Try to find an attribute node.
    for (xmlAttrPtr child = testCaseNode->properties; child; child = child->next)
        if (xmlStrcmp( child->name, BAD_CAST nodeName ) == OK)
            return (xmlNodePtr)child;

    // Try to find an element node.
    for (xmlNodePtr child = testCaseNode->children; child; child = child->next)
        if (xmlStrcmp( child->name, BAD_CAST nodeName ) == OK)
            return child;

    // Missing content, try to find parent case.
    if (strcmp( nodeName, "parent" ) == OK)
        // Was just searching for testCaseNode's parent, none found.
        return NULL;
    xmlChar *parentId = savedhi_xmlTestCaseString( testCaseNode, "parent" );
    if (!parentId)
        // testCaseNode has no parent, give up.
        return NULL;

    for (xmlNodePtr otherTestCaseNode = testCaseNode->parent->children; otherTestCaseNode; otherTestCaseNode = otherTestCaseNode->next) {
        xmlChar *id = savedhi_xmlTestCaseString( otherTestCaseNode, "id" );
        int foundParent = id && xmlStrcmp( id, parentId ) == OK;
        xmlFree( id );

        if (foundParent) {
            xmlFree( parentId );
            return savedhi_xmlTestCaseNode( otherTestCaseNode, nodeName );
        }
    }

    err( "Missing parent: %s, for case: %s", parentId, savedhi_xmlTestCaseString( testCaseNode, "id" ) );
    return NULL;
}

xmlChar *savedhi_xmlTestCaseString(xmlNodePtr context, const char *nodeName) {

    if (!nodeName)
        return NULL;

    xmlNodePtr child = savedhi_xmlTestCaseNode( context, nodeName );
    return child? xmlNodeGetContent( child ): NULL;
}

uint32_t savedhi_xmlTestCaseInteger(xmlNodePtr context, const char *nodeName) {

    if (!nodeName)
        return 0;

    xmlChar *string = savedhi_xmlTestCaseString( context, nodeName );
    uint32_t integer = string? (uint32_t)strtoul( (char *)string, NULL, 10 ): 0;
    xmlFree( string );

    return integer;
}
