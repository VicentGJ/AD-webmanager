from libs.ldap_func import (
    LDAP_AD_USERACCOUNTCONTROL_VALUES, LDAP_AP_PRIMRARY_GROUP_ID_VALUES
)


def multiple_entries_fields_cleaning(function):
    def wrapper(*args, **kwargs):

        result = function(*args, **kwargs)
        if result is not None:
            for entry in result:
                fields_cleaning(entry)
            return result

    return wrapper


def single_entry_fields_cleaning(function):
    def wrapper(*args, **kwargs):

        result = function(*args, **kwargs)
        fields_cleaning(result)
        return result

    return wrapper


def fields_cleaning(entry):
    for attribute, value in entry.items():
        if attribute == "userAccountControl":
            for key, flag in (LDAP_AD_USERACCOUNTCONTROL_VALUES.items()):
                if flag[1] and key == value:
                    entry[attribute] = flag[0]
                    break

        if attribute == "lastLogon" or \
            attribute == "lastLogonTimestamp" or \
                attribute == "pwdLastSet":
            entry[attribute] = convert_adtimestamp_to_milliseconds(
                int(entry[attribute])
            )
        if attribute == "primaryGroupID":
            for key, flag in (LDAP_AP_PRIMRARY_GROUP_ID_VALUES.items()):
                if key == int(value):
                    entry[attribute] = flag
                    break


def multiple_entry_only_selected_fields(fields, entries):
    if fields is not None:
        fields_list = fields.split(",")
        newEntries = [
            {
                key: entry[key]
                for key in entry
                if key in fields_list
            } for entry in entries
        ]
        newEntries = list(filter(lambda x: len(x) > 0, newEntries))
    else:
        newEntries = entries
    return newEntries


def single_entry_only_selected_fields(fields, entry):

    if fields is not None:
        fields_list = fields.split(",")
        newEntry = {
                key: entry[key]
                for key in entry
                if key in fields_list
            }
    else:
        newEntry = entry
    return newEntry


def convert_adtimestamp_to_milliseconds(timestamp: int):
    """
        This function takes a 18 digit AD timestamp
        and returns the corresponding in milliseconds
    """
    milliseconds = timestamp
    if milliseconds > 0:
        unix_timestamp = (timestamp / 10000000) - 11644473600
        milliseconds = unix_timestamp*1000
    return milliseconds