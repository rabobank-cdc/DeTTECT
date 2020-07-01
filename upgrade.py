from constants import *
import simplejson
from io import StringIO
import os


def _load_techniques(yaml_file_lines):
    """
    Loads the techniques (including detection and visibility properties) from the given YAML file.
    :param yaml_file_lines: list with the YAML file lines containing the techniques administration
    :return: dictionary with techniques (incl. properties)
    """
    from generic import add_entry_to_list_in_dictionary, init_yaml, set_yaml_dv_comments

    my_techniques = {}
    _yaml = init_yaml()
    yaml_content = _yaml.load(''.join(yaml_file_lines))
    for d in yaml_content['techniques']:
        # Add detection items
        if isinstance(d['detection'], dict):  # There is just one detection entry
            d['detection'] = set_yaml_dv_comments(d['detection'])
            add_entry_to_list_in_dictionary(my_techniques, d['technique_id'], 'detection', d['detection'])
        elif isinstance(d['detection'], list):  # There are multiple detection entries
            for de in d['detection']:
                de = set_yaml_dv_comments(de)
                add_entry_to_list_in_dictionary(my_techniques, d['technique_id'], 'detection', de)

        # Add visibility items
        if isinstance(d['visibility'], dict):  # There is just one visibility entry
            d['visibility'] = set_yaml_dv_comments(d['visibility'])
            add_entry_to_list_in_dictionary(my_techniques, d['technique_id'], 'visibility', d['visibility'])
        elif isinstance(d['visibility'], list):  # There are multiple visibility entries
            for de in d['visibility']:
                de = set_yaml_dv_comments(de)
                add_entry_to_list_in_dictionary(my_techniques, d['technique_id'], 'visibility', de)

    return my_techniques


def _create_upgrade_text(file_type, file_version):
    """
    Create text on the upgrades to be performed on the YAML file.
    :param file_type: YAML file type
    :param file_version: version of the YAML file
    :return: upgrade text to be displayed in the console
    """
    if file_type == FILE_TYPE_TECHNIQUE_ADMINISTRATION:
        text = 'You are using an old version of the YAML file.\n' \
               'The following upgrades will be performed on the techniques administration file:\n'
        for version in FILE_TYPE_TECHNIQUE_ADMINISTRATION_UPGRADE_TEXT:
            if file_version < version:
                text += '- Version: ' + str(version) + '\n'
                text += FILE_TYPE_TECHNIQUE_ADMINISTRATION_UPGRADE_TEXT[version] + '\n'

        return text


def _get_indent_chars(file_lines):
    """
    Identify and return the characters that are used to indent the YAML file
    :param file_lines: List of lines in the YAML file
    :return: indent characters
    """
    indent_chars = '  '

    for l in file_lines:
        if REGEX_YAML_TECHNIQUE_ID.match(l):
            indent_chars = REGEX_YAML_INDENT_CHARS.search(l).groups()[0]
            indent_chars = len(indent_chars) * ' '
            break

    return indent_chars


# noinspection PyDictCreation
def upgrade_yaml_file(filename, file_type, file_version, attack_tech_data):
    """
    Main function to upgrade the YAML file to a new version
    :param filename: YAML administration file
    :param file_type: YAML file type
    :param file_version: version of the YAML file
    :param attack_tech_data: ATT&CK data on techniques
    :return:
    """
    from generic import ask_yes_no, backup_file

    is_upgraded = False
    tech_upgrade_func = {}
    tech_upgrade_func[1.1] = _upgrade_technique_yaml_10_to_11
    tech_upgrade_func[1.2] = _upgrade_technique_yaml_11_to_12

    with open(filename, 'r') as file:
        file_new_lines = file.readlines()

    if file_type == FILE_TYPE_TECHNIQUE_ADMINISTRATION:
        if file_version < FILE_TYPE_TECHNIQUE_ADMINISTRATION_VERSION:
            upgrade_text = _create_upgrade_text(file_type, file_version)
            print(upgrade_text)
            upgrade_question = 'Do you want to upgrade the below file. A backup will be created of the current file.\n' + \
                               '[!] Not upgrading the file will brake functionality within DeTT&CT.\n' + \
                               ' - ' + filename
            if ask_yes_no(upgrade_question):
                is_upgraded = True
                # create backup of the non-upgraded file
                backup_file(filename)

                for tech_f in tech_upgrade_func.keys():
                    if file_version < tech_f:
                        file_new_lines = tech_upgrade_func[tech_f](file_new_lines, attack_tech_data)
            else:
                print('Upgrade cancelled\n')
                print('-' * 80)
                return

    if is_upgraded:
        # write the upgraded file to disk
        with open(filename, 'w') as f:
            f.writelines(file_new_lines)
            print('Written upgraded file: ' + filename)

        print('\nUpgrade complete')
        print('-' * 80)


def _upgrade_technique_yaml_10_to_11(file_lines, attack_tech_data):
    """
    Upgrade the YAML technique administration file from 1.0 to 1.1.
    :param file_lines: list containing the lines within the tech. admin. file
    :param attack_tech_data: ATT&CK data on techniques
    :return: array with new lines to be written to disk
    """
    from generic import get_technique

    # identify the indent characters used
    indent_chars = _get_indent_chars(file_lines)

    file_new_lines = []
    x = 0
    for l in file_lines:
        if REGEX_YAML_VERSION_10.match(l):
            file_new_lines.append(l.replace('1.0', '1.1'))
        elif REGEX_YAML_TECHNIQUE_ID.match(l):
            file_new_lines.append(l)
            tech_id = REGEX_YAML_TECHNIQUE_ID_GROUP.search(l).group(1)
            tech_name = get_technique(attack_tech_data, tech_id)['name']
            file_new_lines.append(indent_chars + 'technique_name: ' + tech_name + '\n')
        elif REGEX_YAML_DETECTION.match(l):
            file_new_lines.append(l)
            file_new_lines.append((indent_chars * 2) + "applicable_to: ['all']\n")
        elif REGEX_YAML_VISIBILITY.match(l):
            file_new_lines.append(l)
            file_new_lines.append((indent_chars * 2) + "applicable_to: ['all']\n")
        else:
            file_new_lines.append(l)
        x += 1

    return file_new_lines


def _print_error_msg(msg):
    print(msg)
    return True


def _check_yaml_file_health_v11(file_lines):
    """
    Check on error in the provided YAML file version 1.1
    :param file_lines: YAML file lines
    :return: True for a healthy file, and False when encountering health issues.
    """
    from generic import init_yaml
    has_error = False

    # check for duplicate tech IDs
    _yaml = init_yaml()
    yaml_content = _yaml.load(''.join(file_lines))

    tech_ids = list(map(lambda x: x['technique_id'], yaml_content['techniques']))
    tech_dup = []
    for tech in tech_ids:
        if tech not in tech_dup:
            tech_dup.append(tech)
        else:
            has_error = _print_error_msg('[!] Duplicate technique ID: ' + tech)

    # checks on:
    # - empty key-value pairs: 'date_implemented', 'location', 'applicable_to', 'score'
    # - invalid date format for: 'date_implemented'
    # - detection or visibility score out-of-range
    # - missing key-value pairs: 'applicable_to', 'date_implemented', 'score', 'location', 'comment'
    # - check on 'applicable_to' values which are very similar

    dict_yaml_techniques = _load_techniques(file_lines)
    all_applicable_to = set()
    for tech, v in dict_yaml_techniques.items():
        for key in ['detection', 'visibility']:
            if key not in v:
                has_error = _print_error_msg('[!] Technique ID: ' + tech + ' is MISSING ' + key)
            elif 'applicable_to' in v:
                # create at set containing all values for 'applicable_to'
                all_applicable_to.update([a for v in v[key] for a in v['applicable_to']])

        for detection in v['detection']:
            for key in ['applicable_to', 'date_implemented', 'score', 'location', 'comment']:
                if key not in detection:
                    has_error = _print_error_msg('[!] Technique ID: ' + tech + ' is MISSING the key-value pair in detection: ' + key)

            try:
                # noinspection PyChainedComparisons
                if detection['score'] is None:
                    has_error = _print_error_msg('[!] Technique ID: ' + tech + ' has an EMPTY key-value pair in detection: score')

                elif not (detection['score'] >= -1 and detection['score'] <= 5):
                    has_error = _print_error_msg('[!] Technique ID: ' + tech + ' has an INVALID detection score: '
                                                 + str(detection['score']) + ' (should be between -1 and 5)')

                elif detection['score'] > -1:
                    if not detection['date_implemented']:
                        has_error = _print_error_msg('[!] Technique ID: ' + tech + ' has an EMPTY key-value pair in detection: ' + 'date_implemented')
                        break
                    try:
                        # noinspection PyStatementEffect
                        detection['date_implemented'].year
                        # noinspection PyStatementEffect
                        detection['date_implemented'].month
                        # noinspection PyStatementEffect
                        detection['date_implemented'].day
                    except AttributeError:
                        has_error = _print_error_msg('[!] Technique ID: ' + tech +
                                                     ' has an INVALID data format for the key-value pair in detection: ' +
                                                     'date_implemented (should be YYYY-MM-DD)')
                for key in ['location', 'applicable_to']:
                    if not isinstance(detection[key], list):
                        has_error = _print_error_msg('[!] Technique ID: ' + tech + ' has for the key-value pair \''
                                                     + key + '\' a string value assigned (should be a list)')
                    else:
                        try:
                            if detection[key][0] is None:
                                has_error = _print_error_msg('[!] Technique ID: ' + tech + ' has an EMPTY key-value pair in detection: ' + key)
                        except TypeError:
                            has_error = _print_error_msg('[!] Technique ID: ' + tech + ' has an EMPTY key-value pair in detection: ' + key)
            except KeyError:
                pass

        for visibility in v['visibility']:
            for key in ['applicable_to', 'score', 'comment']:
                if key not in visibility:
                    has_error = _print_error_msg('[!] Technique ID: ' + tech + ' is MISSING the key-value pair in visibility: ' + key)

            try:
                if visibility['score'] is None:
                    has_error = _print_error_msg('[!] Technique ID: ' + tech + ' has an EMPTY key-value pair in visibility: score')
                elif not (0 <= visibility['score'] <= 4):
                    # noinspection PyUnboundLocalVariable
                    has_error = _print_error_msg('[!] Technique ID: ' + tech + ' has an INVALID visibility score: '
                                                 + str(detection['score']) + ' (should be between 0 and 4)')
            except KeyError:
                pass

    if has_error:
        print('')
        return False
    else:
        return True


def _upgrade_technique_yaml_11_to_12(file_lines, attack_tech_data):
    """
    Upgrade the YAML technique administration file from 1.1 to 1.2.
    :param file_lines: array containing the lines within the tech. admin. file
    :param attack_tech_data: Not used, but necessary to be compatible with other upgrade methods.
    :return: array with new lines to be written to disk
    """
    from generic import ask_yes_no, fix_date_and_remove_null, init_yaml

    # we will first do a health check on the tech. admin file version 1.1. Having health issues in the file could
    # result in an upgraded file with errors.
    print('Checking the health of the file before we to the upgrade from version 1.1 to 1.2')
    healthy_file = _check_yaml_file_health_v11(file_lines)
    if not healthy_file:
        print('[!] Health issues found. It is advisable first to fix the health issues before continuing the upgrade.')
        if not ask_yes_no('Are you sure that you want to continue the upgrade?'):
            print('Upgrade cancelled')
            quit()
    else:
        print(' - No health issues found. We continue the upgrade to version 1.2\n')

    keep_date_registered = ask_yes_no("Do you want to keep the key-value pair 'date_registered' in your technique "
                                      "administration file even though DeTT&CT no longer makes use of it?")

    date_for_visibility = ''
    print("Which date do you want to fill in for the visibility scores already present in the new key-value pair 'date'?")
    while not REGEX_YAML_VALID_DATE.match(date_for_visibility):
        date_for_visibility = input('  >>   YYYY-MM-DD: ')
        if not REGEX_YAML_VALID_DATE.match(date_for_visibility):
            print('  Invalid date format')
    print('')

    auto_generated = ask_yes_no('Are ALL of the current visibility scores within the technique administration file directly derived from the nr. of data sources?\n'
                                ' * Generated using the option \'-y, --yaml\' from the \'datasoure\' mode in dettect.py\n'
                                ' * Which means NONE of them have been scored manually?')

    _yaml = init_yaml()

    yaml_file = _yaml.load(''.join(file_lines))
    yaml_file['version'] = 1.2

    # upgrade to the new v1.2 tech. admin file
    for tech in yaml_file['techniques']:
        if isinstance(tech['detection'], list):
            detections = tech['detection']
        else:
            detections = [tech['detection']]

        for d in detections:
            score = d['score']
            date = d['date_implemented']
            try:
                if not keep_date_registered:
                    del d['date_registered']
                del d['date_implemented']
                del d['score']
            except KeyError:
                pass

            d['score_logbook'] = [{'date': date, 'score': score, 'comment': ''}]

        if isinstance(tech['visibility'], list):
            visibility = tech['visibility']
        else:
            visibility = [tech['visibility']]

        for v in visibility:
            score = v['score']
            try:
                del v['score']
            except KeyError:
                pass

            v['score_logbook'] = [{'date': date_for_visibility, 'score': score, 'comment': ''}]
            if auto_generated:
                v['score_logbook'][0]['auto_generated'] = True

    # remove the single quotes around the date
    new_lines = fix_date_and_remove_null(yaml_file, date_for_visibility, input_type='ruamel')

    return new_lines


def check_yaml_updated_to_sub_techniques(filename):
    """
    Checks if the YAML technique administration file is already updated to ATT&CK with sub-techniques by comparing the techniques to the the crosswalk file.
    :param filename: YAML administration file
    :return:
    """
    from generic import init_yaml, backup_file, fix_date_and_remove_null, load_attack_data, get_technique, get_technique_from_yaml, remove_technique_from_yaml

    # Open the crosswalk file from MITRE:
    conversion_table = None
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'mitre-data/subtechniques-crosswalk.json'), 'r') as f:
        conversion_table = simplejson.load(f)

    # Open the techniques YAML file:
    _yaml = init_yaml()
    with open(filename, 'r') as yaml_file:
        yaml_content = _yaml.load(yaml_file)

    # Keep track which techniques can be auto updated and which need manual updating
    auto_updatable_techniques = []
    manual_update_techniques = []
    for item in conversion_table:
        for tech in item:
            for sub_tech in item[tech]:
                # Check if technique is in YAML file:
                yaml_technique = get_technique_from_yaml(yaml_content, tech)
                if yaml_technique is None:
                    break
                else:
                    # Only check technique ID's that changed into something else (other technique or other sub-technique)
                    if sub_tech['id'] != tech:
                        # No conversion possible: Multiple techniques became one technique or one sub-technique:
                        if sub_tech['explanation'] in ["Created to consolidate behavior around encrypted C2",
                                                       "Created to consolidate behavior around encrypting and compressing collected data",
                                                       "Created to refine the idea behind Common and Uncommonly Used Port to focus the behavior on use of a non-standard port for C2 based on the protocol used",
                                                       "Existing technique that became a sub-technique. Consolidates Modify Existing Service and New Service techniques into one sub-technique"]:
                            manual_update_techniques.append(tech)

                        # No conversion: One technique became multiple sub techniques:
                        elif sub_tech['explanation'] in ["Deprecated and split into separate Bash, VBScript, and Python sub-techniques of Command and Scripting Interpreter.",
                                                         "Deprecated and split into separate Component Object Model and Distributed Component Object Model sub-techniques.",
                                                         "Deprecated and split into separate Unquoted Path, PATH Environment Variable, and Search Order Hijacking sub-techniques."]:
                            manual_update_techniques.append(tech)

                        # No conversion: Technique merged with other technique:
                        # # T1017 is also merged to T1072, unfortunatly the explanation doesn't tell this
                        elif sub_tech['explanation'] in ["Merged with and name change from Standard Non-Application Layer Protocol"] \
                                or 'Name change from Application Deployment Software' in sub_tech['explanation']:
                            manual_update_techniques.append(tech)

                        # Remove deprecated items:
                        elif sub_tech['id'] == 'N/A':
                            auto_updatable_techniques.append(tech)

                        # Technique ID's that are changed:
                        # T1070 changed to T1551
                        elif sub_tech['explanation'] == "Remains Technique":
                            auto_updatable_techniques.append(tech)

                        # Conversion from technique to sub-technique:
                        elif 'Existing technique that became a sub-technique' in sub_tech['explanation'] \
                                or 'Broken out from pre-defined behavior within Input Capture' in sub_tech['explanation'] \
                                or 'Broken out from pre-defined behavior within Process Injection' in sub_tech['explanation'] \
                                or 'Added due to manipulation of token information' in sub_tech['explanation'] \
                                or 'Added due to manipulation of tokens' in sub_tech['explanation']:
                            auto_updatable_techniques.append(tech)

    if len(auto_updatable_techniques) > 0:
        print('[!] File: \'' + filename + '\' needs to be updated to ATT&CK with sub-techniques. Use option --update-to-sub-techniques to perform the update.')
        return False
    elif len(auto_updatable_techniques) == 0 and len(manual_update_techniques) > 0:
        print('[!] File: \'' + filename +
              '\' needs some manual work to upgrade to ATT&CK with sub-techniques. See the list below on what needs to be changed.')
        print('')
        upgrade_to_sub_techniques(filename, notify_only=True)
        return False
    elif len(auto_updatable_techniques) == 0 and len(manual_update_techniques) == 0:
        return True
    else:
        return False


def upgrade_to_sub_techniques(filename, notify_only=False):
    """
    Upgrade the YAML technique administration file to ATT&CK with sub-techniques
    :param filename: YAML administration file
    :return:
    """
    from generic import init_yaml, backup_file, fix_date_and_remove_null, load_attack_data, get_technique, get_technique_from_yaml, remove_technique_from_yaml, ask_yes_no, local_stix_path

    if not notify_only and not ask_yes_no('DeTT&CT is going to update \'' + filename + '\' to ATT&CK with sub-techniques. A backup of this file will be generated. Do you want to continue:'):
        quit()

    # Open the crosswalk file from MITRE:
    conversion_table = None
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'mitre-data/subtechniques-crosswalk.json'), 'r') as f:
        conversion_table = simplejson.load(f)

    # Open the techniques YAML file:
    _yaml = init_yaml()
    with open(filename, 'r') as yaml_file:
        yaml_content = _yaml.load(yaml_file)

    # Get the MITRE ATT&CK techniques (e.g. to get the new name for renamed techniques):
    techniques = load_attack_data(DATA_TYPE_STIX_ALL_TECH_ENTERPRISE)

    # Check if STIX object collection (TAXII server or local STIX objects) contain sub-techniques, by checking the existence of the first sub-technique (T1001.001)
    stix_sub_tech_check = get_technique(techniques, 'T1001.001')
    if stix_sub_tech_check is None:
        if local_stix_path:
            print('[!] The local STIX repository \'' + local_stix_path +
                  '\' doesn\'t contain ATT&CK sub-techniques. This is necessary to perform the update.')
        else:
            print('[!] The TAXII server doesn\'t contain ATT&CK sub-techniques. This is necessary to perform the update.')
        quit()

    # Keep an ignore list for techniques that are already been taken care of:
    ignore_list = []

    # Collect messages and show them at the end grouped by comparable messages:
    become_subtech_msgs = []
    deprecated_msgs = []
    renamed_msgs = []
    subtech_added_msgs = []
    new_id_msgs = []
    warning_msgs = []
    for item in conversion_table:
        for tech in item:
            for sub_tech in item[tech]:
                # Check if technique is in YAML file:
                yaml_technique = get_technique_from_yaml(yaml_content, tech)

                # Only apply changes to techniques that are in the YAML file:
                if yaml_technique is not None and tech not in ignore_list:
                    # First check the source techniques that are equal to the destination techniques:
                    if sub_tech['id'] == tech:
                        # Do nothing for the items with "Remains Technique" because nothing changes.
                        if 'Remains Technique' in sub_tech['explanation'] \
                                or 'Remove from lateral-movement, Renamed, Name change from Logon Scripts and new sub-techniques added' in sub_tech['explanation'] \
                                or 'Remove from credential-access, New sub-techniques added' in sub_tech['explanation']:
                            pass

                        # Explanations we've missed:
                        else:
                            warning_msgs.append('[!] Explanation \'' + sub_tech['explanation'] +
                                                '\' in the subtechniques-crosswalk.json provided by MITRE not handled by DeTT&CT. Please check manually. Technique ' + tech)

                        # Perform the renames
                        if 'renamed' in sub_tech['explanation'].lower():
                            new_name = get_technique(techniques, sub_tech['id'])['name']
                            if yaml_technique['technique_name'] != new_name:
                                renamed_msgs.append('[i] Technique ' + tech + ' is renamed from \'' + yaml_technique['technique_name'] +
                                                    '\' to \'' + new_name + '\'.')
                                yaml_technique['technique_name'] = new_name

                    # Then check the source techniques that are not equal to the destination techniques:
                    elif sub_tech['id'] != tech:
                        # No conversion possible: Multiple techniques became one technique or one sub-technique:
                        if sub_tech['explanation'] in ["Created to consolidate behavior around encrypted C2",
                                                       "Created to consolidate behavior around encrypting and compressing collected data",
                                                       "Created to refine the idea behind Common and Uncommonly Used Port to focus the behavior on use of a non-standard port for C2 based on the protocol used",
                                                       "Existing technique that became a sub-technique. Consolidates Modify Existing Service and New Service techniques into one sub-technique"]:
                            text = 'sub-technique' if '.' in sub_tech['id'] else 'technique'
                            warning_msgs.append('[!] Technique ' + tech + ' has been consolidated with multiple other techniques into one ' +
                                                text + ': ' + sub_tech['id'] + '. You need to migrate this technique manually.')

                        # No conversion: One technique became multiple sub techniques:
                        elif sub_tech['explanation'] in ["Deprecated and split into separate Bash, VBScript, and Python sub-techniques of Command and Scripting Interpreter.",
                                                         "Deprecated and split into separate Component Object Model and Distributed Component Object Model sub-techniques.",
                                                         "Deprecated and split into separate Unquoted Path, PATH Environment Variable, and Search Order Hijacking sub-techniques."]:
                            sub_ids = []
                            for i in item[tech]:
                                sub_ids.append(i['id'])
                            warning_msgs.append('[!] Technique ' + tech + ' is deprecated and split into multiple sub-techniques: ' + ', '.join(sub_ids) +
                                                '. You need to migrate this technique manually.')
                            ignore_list.append(tech)

                        # No conversion: Technique merged with other technique:
                        # # T1017 is also merged to T1072, unfortunatly the explanation doesn't tell this
                        elif sub_tech['explanation'] in ["Merged with and name change from Standard Non-Application Layer Protocol"] \
                                or 'Name change from Application Deployment Software' in sub_tech['explanation']:
                            warning_msgs.append('[!] Technique ' + tech + ' is merged with ' + sub_tech['id'] +
                                                '. You need to migrate this technique manually.')

                        # Remove deprecated items:
                        elif sub_tech['id'] == 'N/A':
                            remove_technique_from_yaml(yaml_content, tech)
                            deprecated_msgs.append('[i] Technique ' + tech + ' is deprecated. Technique bas been removed from the YAML file.')

                        # Technique ID's that are changed:
                        # T1070 changed to T1551
                        elif sub_tech['explanation'] == "Remains Technique":
                            yaml_technique['technique_id'] = sub_tech['id']
                            new_id_msgs.append('[i] The ID of technique ' + tech + ' is changed to ' + sub_tech['id'] + '.')

                        # Conversion from technique to sub-technique:
                        elif 'Existing technique that became a sub-technique' in sub_tech['explanation'] \
                                or 'Broken out from pre-defined behavior within Input Capture' in sub_tech['explanation'] \
                                or 'Broken out from pre-defined behavior within Process Injection' in sub_tech['explanation'] \
                                or 'Added due to manipulation of token information' in sub_tech['explanation'] \
                                or 'Added due to manipulation of tokens' in sub_tech['explanation']:
                            yaml_technique['technique_id'] = sub_tech['id']
                            yaml_technique['technique_name'] = get_technique(techniques, sub_tech['id'])['name']
                            become_subtech_msgs.append('[i] Technique ' + tech + ' has become sub-technique: ' +
                                                       sub_tech['id'] + '. Change applied in the YAML file.')

                        # Explanations we've missed:
                        else:
                            warning_msgs.append('[!] Explanation \'' + sub_tech['explanation'] +
                                                '\' in the subtechniques-crosswalk.json provided by MITRE not handled by DeTT&CT. Please check manually. Technique ' + tech)

                        # Perform the renames
                        if 'renamed' in sub_tech['explanation'].lower():
                            new_name = get_technique(techniques, sub_tech['id'])['name']
                            print(tech)
                            if yaml_technique['technique_name'] != new_name:
                                renamed_msgs.append('[i] Technique ' + tech + ' is renamed from \'' + yaml_technique['technique_name'] +
                                                    '\' to \'' + new_name + '\'.')
                                yaml_technique['technique_name'] = new_name

    # Print the results:
    if len(become_subtech_msgs + deprecated_msgs + renamed_msgs + subtech_added_msgs + new_id_msgs) > 0:
        print("Informational messages (no action needed):")

        for item in become_subtech_msgs:
            print(item)
        for item in deprecated_msgs:
            print(item)
        for item in renamed_msgs:
            print(item)
        for item in subtech_added_msgs:
            print(item)
        for item in new_id_msgs:
            print(item)
        print('')

    if len(warning_msgs) > 0:
        print("Messages that need your attention:")
        for item in warning_msgs:
            print(item)
        print('')

    if len(become_subtech_msgs + deprecated_msgs + renamed_msgs + subtech_added_msgs + new_id_msgs + warning_msgs) == 0:
        print('[i] No techniques found that need to be updated to ATT&CK sub-techniques.')
    else:
        if not notify_only:
            # Create backup of the YAML file:
            backup_file(filename)
            with open(filename, 'w') as fd:
                # ruamel does not support output to a variable. Therefore we make use of StringIO.
                string_io = StringIO()
                _yaml.dump(yaml_content, string_io)
                string_io.seek(0)
                new_lines = string_io.readlines()
                fd.writelines(new_lines)
                print('File written:   ' + filename)

    # Quit DeTT&CT when manual work needs to be done:
    if len(warning_msgs) > 0:
        quit()
