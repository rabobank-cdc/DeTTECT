from constants import *
import simplejson
from io import StringIO
from copy import deepcopy
import os


def _create_upgrade_text(file_type, file_version):
    """
    Create text on the upgrades to be performed on the YAML file.
    :param file_type: YAML file type
    :param file_version: version of the YAML file
    :return: upgrade text to be displayed in the console
    """
    if file_type == FILE_TYPE_DATA_SOURCE_ADMINISTRATION:
        text = 'You are using an old version of the YAML file.\n' \
               'The following upgrades will be performed on the data source administration file:\n'
        for version in FILE_TYPE_DATA_SOURCE_UPGRADE_TEXT:
            if file_version < version:
                text += '- Version: ' + str(version) + '\n'
                text += FILE_TYPE_DATA_SOURCE_UPGRADE_TEXT[version] + '\n'

        return text


def upgrade_yaml_file(filename, file_type, file_version):
    """
    Main function to upgrade the YAML file to a new version
    :param filename: YAML administration file
    :param file_type: YAML file type
    :param file_version: version of the YAML file
    :return:
    """
    from generic import ask_yes_no, backup_file

    is_upgraded = False

    # noinspection PyDictCreation
    data_source_upgrade_func = {}
    data_source_upgrade_func[1.1] = _upgrade_data_source_yaml_10_to_11

    with open(filename, 'r') as file:
        file_new_lines = file.readlines()

    if file_type == FILE_TYPE_DATA_SOURCE_ADMINISTRATION:
        if file_version < FILE_TYPE_DATA_SOURCE_ADMINISTRATION_VERSION:
            upgrade_text = _create_upgrade_text(file_type, file_version)
            print(upgrade_text)
            upgrade_question = 'Do you want to upgrade the below file. A backup will be created of the current file.\n' + \
                               '[!] Not upgrading the file will brake functionality within DeTT&CT.\n' + \
                               ' - ' + filename
            if ask_yes_no(upgrade_question):
                is_upgraded = True
                # create backup of the non-upgraded file
                backup_file(filename)

                for tech_f in data_source_upgrade_func.keys():
                    if file_version < tech_f:
                        file_new_lines = data_source_upgrade_func[tech_f](file_new_lines)
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


def _print_error_msg(msg):
    print(msg)
    return True


def _upgrade_data_source_yaml_10_to_11(file_lines):
    """
    Upgrade the YAML data source administration file from 1.0 to 1.1.
    :param file_lines: array containing the lines within the data source admin. file
    :return: array with new lines to be written to disk
    """
    from generic import ask_yes_no, fix_date_and_remove_null, init_yaml, get_platform_from_yaml

    # we will first do a health check on the data source admin file version 1.0. Having health issues in the file could
    # result in an upgraded file with errors.
    print('Checking the health of the file before we to the upgrade from version 1.0 to 1.1')
    healthy_file = _check_yaml_file_health_v10(file_lines)
    if not healthy_file:
        print('[!] Health issues found. It is advisable first to fix the health issues before continuing the upgrade.')
        if not ask_yes_no('Are you sure that you want to continue the upgrade?'):
            print('Upgrade cancelled')
            quit()
    else:
        print(' - No health issues found. We continue the upgrade to version 1.1\n')

    _yaml = init_yaml()
    yaml_file = _yaml.load(''.join(file_lines))
    yaml_file_new = deepcopy(yaml_file)

    # upgrade to the new v1.1 data source admin. file
    yaml_file_new['version'] = 1.1

    yaml_file_new['data_sources'] = []
    for ds in yaml_file['data_sources']:
        ds_details_obj = {
            'applicable_to': ['all']
        }
        for k, v in ds.items():
            if k != 'data_source_name':
                ds_details_obj[k] = v

        yaml_file_new['data_sources'].append({
            'data_source_name': ds['data_source_name'],
            'data_source': [ds_details_obj]
        })

    # remove the single quotes around the date
    new_lines = fix_date_and_remove_null(yaml_file_new, '', input_type='ruamel')
    return new_lines


def _check_yaml_file_health_v10(file_lines):
    """
    Check on error in the provided YAML data source admin. file version 1.0
    :param file_lines: YAML file lines
    :return: True for a healthy file, and False when encountering health issues
    """
    from generic import init_yaml, get_platform_from_yaml
    has_error = False

    # check for duplicate tech IDs
    _yaml = init_yaml()
    ds_content = _yaml.load(''.join(file_lines))

    platform = get_platform_from_yaml(ds_content)

    if isinstance(platform, str):
        platform = [platform]
    if platform is None or len(platform) == 0 or platform == '':
        platform = ['empty']
    for p in platform:
        if p.lower() not in PLATFORMS.keys():
            has_error = _print_error_msg(
                '[!] EMPTY or INVALID value for \'platform\' within the data source admin. '
                'file: %s (should be value(s) of: [%s] or all)' % (p, ', '.join(list(PLATFORMS.values()))))

    for ds in ds_content['data_sources']:
        # check for missing keys
        for key in ['data_source_name', 'date_registered', 'date_connected', 'products', 'available_for_data_analytics', 'comment', 'data_quality']:
            if key not in ds:
                has_error = _print_error_msg('[!] Data source: \'' + ds['data_source_name'] +
                                             '\' is MISSING a key-value pair: ' + key)

        for key in ['date_registered', 'date_connected']:
            if key in ds and not ds[key] is None:
                try:
                    # pylint: disable=pointless-statement
                    ds[key].year
                    # pylint: disable=pointless-statement
                    ds[key].month
                    # pylint: disable=pointless-statement
                    ds[key].day
                except AttributeError:
                    has_error = _print_error_msg('[!] Data source: \'' + ds['data_source_name'] + '\' has an INVALID data format for the key-value pair \'' + key
                                                 + '\': ' + ds[key] + '  (should be YYYY-MM-DD without quotes)')

        if 'available_for_data_analytics' in ds:
            if not isinstance(ds['available_for_data_analytics'], bool):
                has_error = _print_error_msg('[!] Data source: \'' + ds['data_source_name'] +
                                             '\' has an INVALID \'available_for_data_analytics\' value: should be set to \'true\' or \'false\'')

        if 'data_quality' in ds:
            if isinstance(ds['data_quality'], dict):
                for dimension in ['device_completeness', 'data_field_completeness', 'timeliness', 'consistency', 'retention']:
                    if dimension not in ds['data_quality']:
                        has_error = _print_error_msg('[!] Data source: \'' + ds['data_source_name'] +
                                                     '\' is MISSING a key-value pair in \'data_quality\': ' + dimension)
                    else:
                        if isinstance(ds['data_quality'][dimension], int):
                            if not 0 <= ds['data_quality'][dimension] <= 5:
                                has_error = _print_error_msg('[!] Data source: \'' + ds['data_source_name'] + '\' has an INVALID data quality score for the dimension \''
                                                             + dimension + '\': ' + str(ds['data_quality'][dimension]) + '  (should be between 0 and 5)')
                        else:
                            has_error = _print_error_msg('[!] Data source: \'' + ds['data_source_name'] + '\' has an INVALID data quality score for the dimension \'' +
                                                         dimension + '\': ' + str(ds['data_quality'][dimension]) + '  (should be an an integer)')
            else:
                has_error = _print_error_msg('[!] Data source: \'' + ds['data_source_name'] +
                                             '\' the key-value pair \'data_quality\' is NOT a dictionary with data quality dimension scores')

    if has_error:
        print('')
        return False
    else:
        return True


def check_yaml_updated_to_sub_techniques(filename):
    """
    Checks if the YAML technique administration file is already updated to ATT&CK with sub-techniques by comparing the techniques to the the crosswalk file.
    :param filename: YAML administration file
    :return: return False if an update is required, otherwise True
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
        for element in item:
            if element.startswith('T'):
                for migrate_item in item[element]:
                    # Check if technique is in YAML file:
                    yaml_technique = get_technique_from_yaml(yaml_content, element)
                    if yaml_technique is None:
                        break
                    else:
                        # Possible types of changes:
                        # - Remains Technique
                        # - Became a Sub-Technique
                        # - Multiple Techniques Became New Sub-Technique
                        # - One or More Techniques Became New Technique
                        # - Merged into Existing Technique
                        # - Deprecated
                        # - Became Multiple Sub-Techniques

                        if item['change-type'] == 'Became a Sub-Technique':
                            auto_updatable_techniques.append(element)
                        elif item['change-type'] == 'Multiple Techniques Became New Sub-Technique':
                            manual_update_techniques.append(element)
                        elif item['change-type'] == 'One or More Techniques Became New Technique':
                            manual_update_techniques.append(element)
                        elif item['change-type'] == 'Merged into Existing Technique':
                            manual_update_techniques.append(element)
                        elif item['change-type'] == 'Deprecated':
                            auto_updatable_techniques.append(element)
                        elif item['change-type'] == 'Became Multiple Sub-Techniques':
                            manual_update_techniques.append(element)

    if len(auto_updatable_techniques) > 0:
        print('[!] File: \'' + filename + '\' needs to be updated to ATT&CK with sub-techniques. Use the option \'--update-to-sub-techniques\' to perform the update.')
        return False
    elif len(auto_updatable_techniques) == 0 and len(manual_update_techniques) > 0:
        print('[!] File: \'' + filename + '\' needs some manual work to upgrade to ATT&CK with sub-techniques. See the list below on what needs to be changed.\n')
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
    :param notify_only: set to True by 'check_yaml_updated_to_sub_techniques' when no automatic upgrade of techniques can be performed because these require manual action
    :return:
    """
    from generic import init_yaml, backup_file, load_attack_data, get_technique, get_technique_from_yaml, remove_technique_from_yaml, ask_yes_no, local_stix_path, get_latest_score, get_latest_auto_generated

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
    warning_msgs = []
    for item in conversion_table:
        for element in item:
            if element.startswith('T'):
                for migrate_item in item[element]:
                    # Check if technique is in YAML file:
                    yaml_technique = get_technique_from_yaml(yaml_content, element)

                    # Only apply changes to techniques that are in the YAML file:
                    if yaml_technique is not None and element not in ignore_list:
                        change_name = False
                        # Possible types of changes:
                        # - Remains Technique
                        # - Became a Sub-Technique
                        # - Multiple Techniques Became New Sub-Technique
                        # - One or More Techniques Became New Technique
                        # - Merged into Existing Technique
                        # - Deprecated
                        # - Became Multiple Sub-Techniques

                        if item['change-type'] == 'Remains Technique':
                            # No upgrade necessary because techniques "Remains Technique". Only name changes can occur, these will be handled beneath.
                            change_name = True
                            # Only check if "new sub-techniques added" is within the explanation:
                            if 'new sub-techniques added' in migrate_item['explanation'].lower():
                                has_detection = False
                                is_auto_generated = False
                                if isinstance(yaml_technique['detection'], dict):  # There is just one detection entry
                                    has_detection = get_latest_score(yaml_technique['detection']) >= 0
                                    is_auto_generated = get_latest_auto_generated(yaml_technique['visibility'])
                                elif isinstance(yaml_technique['detection'], list):  # There are multiple detection entries
                                    has_detection = len([d for d in yaml_technique['detection'] if get_latest_score(d) >= 0]) > 0
                                    is_auto_generated = any([get_latest_auto_generated(v) for v in yaml_technique['visibility']])

                                if has_detection or not is_auto_generated:
                                    subtech_added_msgs.append(migrate_item['id'])
                        elif item['change-type'] == 'Became a Sub-Technique':
                            # Conversion from technique to sub-technique:
                            yaml_technique['technique_id'] = migrate_item['id']
                            become_subtech_msgs.append('[i] Technique ' + element + ' has become sub-technique: ' +
                                                       migrate_item['id'] + '. Change applied in the YAML file.')
                            change_name = True
                        elif item['change-type'] == 'Multiple Techniques Became New Sub-Technique':
                            # No conversion possible: Multiple techniques became new sub-technique:
                            warning_msgs.append(
                                '[!] Technique ' + element + ' has been consolidated with multiple other techniques into one sub-technique: ' + migrate_item['id'] + '. You need to migrate this technique manually.')
                        elif item['change-type'] == 'One or More Techniques Became New Technique':
                            # No conversion possible: One or more techniques became new technique:
                            warning_msgs.append(
                                '[!] Technique ' + element + ' has been consolidated (with multiple other techniques) into one technique: ' + migrate_item['id'] + '. You need to migrate this technique manually.')
                        elif item['change-type'] == 'Merged into Existing Technique':
                            # No conversion possible: Technique merged into existing technique:
                            warning_msgs.append('[!] Technique ' + element + ' is merged with ' + migrate_item['id'] +
                                                '. You need to migrate this technique manually.')
                        elif item['change-type'] == 'Deprecated':
                            # Remove deprecated items:
                            remove_technique_from_yaml(yaml_content, element)
                            deprecated_msgs.append('[i] Technique ' + element + ' is deprecated. Technique bas been removed from the YAML file.')
                        elif item['change-type'] == 'Became Multiple Sub-Techniques':
                            # No conversion: One technique became multiple sub techniques:
                            sub_ids = []
                            for i in item[element]:
                                sub_ids.append(i['id'])
                            warning_msgs.append('[!] Technique ' + element + ' is deprecated and split into multiple sub-techniques: ' +
                                                ', '.join(sub_ids) + '. You need to migrate this technique manually.')
                            ignore_list.append(element)

                        # Get the latest description from ATT&CK:
                        if change_name and migrate_item['id'] != 'N/A':
                            new_name = get_technique(techniques, migrate_item['id'])['name']
                            if yaml_technique['technique_name'] != new_name:
                                renamed_msgs.append('[i] Technique ' + element + ' is renamed from \'' +
                                                    yaml_technique['technique_name'] + '\' to \'' + new_name + '\'.')
                                yaml_technique['technique_name'] = new_name

    # Print the results:
    if len(become_subtech_msgs + deprecated_msgs + renamed_msgs) > 0:
        print('Informational messages (no action needed):')

        for item in become_subtech_msgs:
            print(item)
        for item in deprecated_msgs:
            print(item)
        for item in renamed_msgs:
            print(item)
        print('')

    if len(warning_msgs) > 0:
        print('Messages that need your attention:')
        for item in warning_msgs:
            print(item)
        print('')

    if len(become_subtech_msgs + deprecated_msgs + renamed_msgs + warning_msgs) == 0:
        print('[i] No techniques found that need to be updated to ATT&CK sub-techniques.\n')
    else:
        if len(subtech_added_msgs) > 0:
            print('The following techniques remained the same technique. However, to multiple techniques, sub-techniques were added. Please review the following list as there might be a sub-technique that fits better. Techniques: ' + ', '.join(subtech_added_msgs))
            print('')

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
                print('File written:   ' + filename + '\n')
        print('Some last notes before you continue:')
        print('- Please read MITRE\'s blog for more information on how to migrate techniques that need to be migrated manually: https://medium.com/mitre-attack/attack-with-sub-techniques-is-now-just-attack-8fc20997d8de')
        print('- It is recommended to run the \'--update function\' in the datasource (ds) mode, to update the visibility scores for all new techniques, new sub-techniques and changed techniques.')
        print('')

    # Quit DeTT&CT when manual work needs to be done:
    if len(warning_msgs) > 0:
        quit()
