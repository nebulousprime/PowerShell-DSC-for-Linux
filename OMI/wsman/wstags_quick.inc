/*
**==============================================================================
**
** DO NOT EDIT THIS FILE!!! IT WAS AUTOMATICALLY GENERATED
**
**==============================================================================
*/

#include "wstags.h"

int HashStr(HASHSTR_CHAR c, const HASHSTR_CHAR* s, size_t n)
{

    switch (n)
    {
    case 2:
            if (c == 'a' && HASHSTR_STRCMP(s, HASHSTR_T("To")) == 0)
                return WSMANTAG_TO;
    break;
    case 4:
        switch (s[0])
        {
        case 78:
            if (HASHSTR_STRCMP(s, HASHSTR_T("None")) == 0)
                return WSMANTAG_ENUM_POLYMORPHISM_MODE_NONE;
        break;
        case 80:
            if (c == 'n' && HASHSTR_STRCMP(s, HASHSTR_T("Pull")) == 0)
                return WSMANTAG_ENUM_PULL;
        break;
        }

    break;
    case 6:
        switch (s[0])
        {
        case 65:
            if (c == 'a' && HASHSTR_STRCMP(s, HASHSTR_T("Action")) == 0)
                return WSMANTAG_ACTION;
        break;
        case 70:
            if (c == 'w' && HASHSTR_STRCMP(s, HASHSTR_T("Filter")) == 0)
                return WSMANTAG_ENUM_FILTER;
        break;
        case 72:
            if (c == 's' && HASHSTR_STRCMP(s, HASHSTR_T("Header")) == 0)
                return WSMANTAG_HEADER;
        break;
        case 79:
            if (c == 'w' && HASHSTR_STRCMP(s, HASHSTR_T("Option")) == 0)
                return WSMANTAG_OPTION;
        break;
        }

    break;
    case 7:
        switch (s[0])
        {
        case 65:
            if (c == 'a' && HASHSTR_STRCMP(s, HASHSTR_T("Address")) == 0)
                return WSMANTAG_ADDRESS;
        break;
        case 68:
            if (HASHSTR_STRCMP(s, HASHSTR_T("Dialect")) == 0)
                return WSMANTAG_ENUM_DIALIECT;
        break;
        case 69:
            if (c == 'e' && HASHSTR_STRCMP(s, HASHSTR_T("Expires")) == 0)
                return WSMANTAG_EXPIRES;
        break;
        case 77:
            if (c == 'n' && HASHSTR_STRCMP(s, HASHSTR_T("MaxTime")) == 0)
                return WSMANTAG_MAX_TIME;
        break;
        case 82:
            if (c == 'a' && HASHSTR_STRCMP(s, HASHSTR_T("ReplyTo")) == 0)
                return WSMANTAG_REPLY_TO;
            if (c == 'n' && HASHSTR_STRCMP(s, HASHSTR_T("Release")) == 0)
                return WSMANTAG_ENUM_RELEASE;
        break;
        }

    break;
    case 8:
        switch (s[0])
        {
        case 66:
            if (c == 'w' && HASHSTR_STRCMP(s, HASHSTR_T("Bookmark")) == 0)
                return WSMANTAG_BOOKMARK;
        break;
        case 68:
            if (c == 'e' && HASHSTR_STRCMP(s, HASHSTR_T("Delivery")) == 0)
                return WSMANTAG_SUBSCRIBE_DELIVER;
        break;
        case 73:
            if (c == 'i' && HASHSTR_STRCMP(s, HASHSTR_T("Identify")) == 0)
                return WSMANTAG_IDENTIFY;
        break;
        case 83:
            if (c == 'w' && HASHSTR_STRCMP(s, HASHSTR_T("Selector")) == 0)
                return WSMANTAG_SELECTOR;
        break;
        }

    break;
    case 9:
        switch (s[0])
        {
        case 69:
            if (c == 'n' && HASHSTR_STRCMP(s, HASHSTR_T("Enumerate")) == 0)
                return WSMANTAG_ENUM_ENUMERATE;
        break;
        case 77:
            if (c == 'a' && HASHSTR_STRCMP(s, HASHSTR_T("MessageID")) == 0)
                return WSMANTAG_MESSAGE_ID;
        break;
        case 79:
            if (c == 'w' && HASHSTR_STRCMP(s, HASHSTR_T("OptionSet")) == 0)
                return WSMANTAG_OPTION_SET;
        break;
        }

    break;
    case 10:
        switch (s[0])
        {
        case 72:
            if (c == 'w' && HASHSTR_STRCMP(s, HASHSTR_T("Heartbeats")) == 0)
                return WSMANTAG_SUBSCRIBE_HEARTBEATS;
        break;
        case 73:
            if (c == 'e' && HASHSTR_STRCMP(s, HASHSTR_T("Identifier")) == 0)
                return WSMANTAG_SUBSCRIBE_IDENTIFIER;
        break;
        }

    break;
    case 11:
        switch (s[0])
        {
        case 77:
            if (c == 'n' && HASHSTR_STRCMP(s, HASHSTR_T("MaxElements")) == 0)
                return WSMANTAG_PULL_MAX_ELEMENTS;
            if (c == 'w' && HASHSTR_STRCMP(s, HASHSTR_T("MaxElements")) == 0)
                return WSMANTAG_ENUM_MAX_ELEMENTS;
        break;
        case 82:
            if (c == 'w' && HASHSTR_STRCMP(s, HASHSTR_T("ResourceURI")) == 0)
                return WSMANTAG_RESOURCE_URI;
        break;
        case 83:
            if (c == 'w' && HASHSTR_STRCMP(s, HASHSTR_T("SelectorSet")) == 0)
                return WSMANTAG_SELECTOR_SET;
        break;
        }

    break;
    case 12:
            if (HASHSTR_STRCMP(s, HASHSTR_T("EnumerateEPR")) == 0)
                return WSMANTAG_ENUM_MODE_EPR;
    break;
    case 13:
        switch (s[0])
        {
        case 77:
            if (c == 'n' && HASHSTR_STRCMP(s, HASHSTR_T("MaxCharacters")) == 0)
                return WSMANTAG_MAX_CHARACTERS;
        break;
        case 83:
            if (c == 'w' && HASHSTR_STRCMP(s, HASHSTR_T("SendBookmarks")) == 0)
                return WSMANTAG_SEND_BOOKMARKS;
        break;
        }

    break;
    case 15:
        switch (s[3])
        {
        case 69:
            if (c == 'w' && HASHSTR_STRCMP(s, HASHSTR_T("MaxEnvelopeSize")) == 0)
                return WSMANTAG_MAX_ENVELOPE_SIZE;
        break;
        case 109:
            if (HASHSTR_STRCMP(s, HASHSTR_T("EnumerateObject")) == 0)
                return WSMANTAG_ENUM_MODE_OBJECT;
            if (c == 'w' && HASHSTR_STRCMP(s, HASHSTR_T("EnumerationMode")) == 0)
                return WSMANTAG_ENUM_MODE;
        break;
        case 110:
            if (c == 'w' && HASHSTR_STRCMP(s, HASHSTR_T("ConnectionRetry")) == 0)
                return WSMANTAG_SUBSCRIBE_CONNECTION_RETRY;
            if (c == 'w' && HASHSTR_STRCMP(s, HASHSTR_T("ConnectionRetry")) == 0)
                return WSMANTAG_CONNECTION_RETRY;
        break;
        case 116:
            if (c == 'w' && HASHSTR_STRCMP(s, HASHSTR_T("ContentEncoding")) == 0)
                return WSMANTAG_SUBSCRIBE_CONTENTENCODING;
        break;
        }

    break;
    case 16:
        switch (s[0])
        {
        case 79:
            if (c == 'w' && HASHSTR_STRCMP(s, HASHSTR_T("OperationTimeout")) == 0)
                return WSMANTAG_OPERATION_TIMEOUT;
        break;
        case 80:
            if (c == 'b' && HASHSTR_STRCMP(s, HASHSTR_T("PolymorphismMode")) == 0)
                return WSMANTAG_ENUM_POLYMORPHISM_MODE;
        break;
        }

    break;
    case 17:
            if (HASHSTR_STRCMP(s, HASHSTR_T("IncludeQualifiers")) == 0)
                return WSMAN_OPTION_INCLUDE_QUALIFIERS;
    break;
    case 18:
        switch (s[0])
        {
        case 69:
            if (c == 'n' && HASHSTR_STRCMP(s, HASHSTR_T("EnumerationContext")) == 0)
                return WSMANTAG_PULL_ENUMERATION_CONTEXT;
        break;
        case 73:
            if (HASHSTR_STRCMP(s, HASHSTR_T("IncludeClassOrigin")) == 0)
                return WSMAN_OPTION_INCLUDE_CLASS_ORIGIN;
        break;
        }

    break;
    case 19:
            if (c == 'w' && HASHSTR_STRCMP(s, HASHSTR_T("OptimizeEnumeration")) == 0)
                return WSMANTAG_ENUM_OPTIMIZE_ENUMERATION;
    break;
    case 21:
        switch (s[0])
        {
        case 69:
            if (HASHSTR_STRCMP(s, HASHSTR_T("EnumerateObjectAndEPR")) == 0)
                return WSMANTAG_ENUM_MODE_OBJECT_AND_EPR;
        break;
        case 119:
            if (HASHSTR_STRCMP(s, HASHSTR_T("wmi:IncludeQualifiers")) == 0)
                return WSMAN_OPTION_WMI_INCLUDE_QUALIFIERS;
        break;
        }

    break;
    case 22:
            if (HASHSTR_STRCMP(s, HASHSTR_T("wmi:IncludeClassOrigin")) == 0)
                return WSMAN_OPTION_WMI_INCLUDE_CLASS_ORIGIN;
    break;
    case 24:
            if (HASHSTR_STRCMP(s, HASHSTR_T("IncludeInheritedElements")) == 0)
                return WSMAN_OPTION_INCLUDE_INHERITED_ELEMENTS;
    break;
    case 25:
        switch (s[0])
        {
        case 69:
            if (HASHSTR_STRCMP(s, HASHSTR_T("ExcludeSubClassProperties")) == 0)
                return WSMANTAG_ENUM_POLYMORPHISM_MODE_EXCLUDE_PROPS;
        break;
        case 73:
            if (HASHSTR_STRCMP(s, HASHSTR_T("IncludeSubClassProperties")) == 0)
                return WSMANTAG_ENUM_POLYMORPHISM_MODE_INCLUDE_PROPS;
        break;
        }

    break;
    case 26:
            if (HASHSTR_STRCMP(s, HASHSTR_T("msftwinrm:UsePreciseArrays")) == 0)
                return WSMAN_OPTION_MSFTWINRM_USE_PRECISE_ARRAYS;
    break;
    case 27:
            if (HASHSTR_STRCMP(s, HASHSTR_T("IncludeInheritanceHierarchy")) == 0)
                return WSMAN_OPTION_INCLUDE_INHERITANCE_HIERARCHY;
    break;
    case 28:
            if (HASHSTR_STRCMP(s, HASHSTR_T("wmi:IncludeInheritedElements")) == 0)
                return WSMAN_OPTION_WMI_INCLUDE_INHERITED_ELEMENTS;
    break;
    case 31:
            if (HASHSTR_STRCMP(s, HASHSTR_T("wmi:IncludeInheritanceHierarchy")) == 0)
                return WSMAN_OPTION_WMI_INCLUDE_INHERITANCE_HIERARCHY;
    break;
    case 47:
            if (HASHSTR_STRCMP(s, HASHSTR_T("http://schemas.dmtf.org/wbem/wsman/1/wsman/Pull")) == 0)
                return WSMAN_DELIVERY_MODE_PULL;
    break;
    case 49:
            if (HASHSTR_STRCMP(s, HASHSTR_T("http://schemas.dmtf.org/wbem/wsman/1/wsman/Events")) == 0)
                return WSMAN_DELIVERY_MODE_EVENTS;
    break;
    case 50:
        switch (s[47])
        {
        case 71:
            if (HASHSTR_STRCMP(s, HASHSTR_T("http://schemas.xmlsoap.org/ws/2004/09/transfer/Get")) == 0)
                return WSMANTAG_ACTION_GET;
        break;
        case 80:
            if (HASHSTR_STRCMP(s, HASHSTR_T("http://schemas.xmlsoap.org/ws/2004/09/transfer/Put")) == 0)
                return WSMANTAG_ACTION_PUT;
        break;
        }

    break;
    case 52:
        switch (s[15])
        {
        case 100:
            if (HASHSTR_STRCMP(s, HASHSTR_T("http://schemas.dmtf.org/wbem/ws-cim/1/cim-schema/2/*")) == 0)
                return WSMAN_RESOURCE_URI_WS_CIM_SCHEMA;
        break;
        case 120:
            if (HASHSTR_STRCMP(s, HASHSTR_T("http://schemas.xmlsoap.org/ws/2004/08/eventing/Renew")) == 0)
                return WSMANTAG_ACTION_RENEW;
        break;
        }

    break;
    case 53:
        switch (s[47])
        {
        case 67:
            if (HASHSTR_STRCMP(s, HASHSTR_T("http://schemas.xmlsoap.org/ws/2004/09/transfer/Create")) == 0)
                return WSMANTAG_ACTION_CREATE;
        break;
        case 68:
            if (HASHSTR_STRCMP(s, HASHSTR_T("http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete")) == 0)
                return WSMANTAG_ACTION_DELETE;
        break;
        case 109:
            if (HASHSTR_STRCMP(s, HASHSTR_T("http://schemas.dmtf.org/wbem/cim-xml/2/cim-schema/2/*")) == 0)
                return WSMAN_RESOURCE_URI_CIM_XML_SCHEMA;
        break;
        }

    break;
    case 54:
        switch (s[15])
        {
        case 100:
            if (HASHSTR_STRCMP(s, HASHSTR_T("http://schemas.dmtf.org/wbem/wsman/1/wsman/PushWithAck")) == 0)
                return WSMAN_DELIVERY_MODE_PUSH_WITH_ACK;
        break;
        case 120:
            if (HASHSTR_STRCMP(s, HASHSTR_T("http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull")) == 0)
                return WSMANTAG_ACTION_PULL;
        break;
        }

    break;
    case 56:
        switch (s[47])
        {
        case 71:
            if (HASHSTR_STRCMP(s, HASHSTR_T("http://schemas.xmlsoap.org/ws/2004/08/eventing/GetStatus")) == 0)
                return WSMANTAG_ACTION_GETSTATUS;
        break;
        case 83:
            if (HASHSTR_STRCMP(s, HASHSTR_T("http://schemas.xmlsoap.org/ws/2004/08/eventing/Subscribe")) == 0)
                return WSMANTAG_ACTION_SUBSCRIBE;
        break;
        }

    break;
    case 57:
            if (HASHSTR_STRCMP(s, HASHSTR_T("http://schemas.xmlsoap.org/ws/2004/09/enumeration/Release")) == 0)
                return WSMANTAG_ACTION_RELEASE;
    break;
    case 58:
            if (HASHSTR_STRCMP(s, HASHSTR_T("http://schemas.xmlsoap.org/ws/2004/08/eventing/Unsubscribe")) == 0)
                return WSMANTAG_ACTION_UNSUBSCRIBE;
    break;
    case 59:
            if (HASHSTR_STRCMP(s, HASHSTR_T("http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate")) == 0)
                return WSMANTAG_ACTION_ENUMERATE;
    break;
    case 65:
            if (HASHSTR_STRCMP(s, HASHSTR_T("http://schemas.xmlsoap.org/ws/2004/08/eventing/DeliveryModes/Push")) == 0)
                return WSMAN_DELIVERY_MODE_PUSH;
    break;
    }
    /* Not found */
    return 0;
}