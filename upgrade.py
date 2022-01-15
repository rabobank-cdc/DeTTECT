from copy import deepcopy
from constants import *
from file_output import backup_file


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
    print('Checking the health of the file before we do the upgrade from version 1.0 to 1.1')
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

    platforms = get_platform_from_yaml(yaml_file_new)
    if platforms == []:
        platforms = list(PLATFORMS_ENTERPRISE.values())
    del yaml_file_new['platform']

    # ask for the applicable_to value to be used
    applicable_to = ''
    while not re.match('^.+$', applicable_to,):
        applicable_to = input("What value for 'applicable_to' do you want to use for the to be created System object?\n\
Default = " + yaml_file['name'] + "\n\n >>   (Press Enter to use the default): ")
        print(applicable_to)
        if applicable_to == '':
            applicable_to = yaml_file['name']
        print('')

    # add a new kv-pair systems
    idx = 0
    for k, v in yaml_file_new.items():
        if k == 'name':
            break
        idx += 1
    yaml_file_new.insert(idx + 1, 'systems', [{'applicable_to': applicable_to, 'platform': platforms}])

    # add a new kv-pair applicable_to to every data source
    yaml_file_new['data_sources'] = []
    for ds in yaml_file['data_sources']:
        ds_details_obj = {
            'applicable_to': [applicable_to]
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
        if p.lower() not in PLATFORMS_ENTERPRISE.keys():
            has_error = _print_error_msg(
                '[!] EMPTY or INVALID value for \'platform\' within the data source admin. '
                'file: %s (should be value(s) of: [%s] or all)' % (p, ', '.join(list(PLATFORMS_ENTERPRISE.values()))))

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


def upgrade_yaml_file(filename, file_type, file_version):
    """
    Main function to upgrade the YAML file to a new version
    :param filename: YAML administration file
    :param file_type: YAML file type
    :param file_version: version of the YAML file
    :return:
    """
    from generic import ask_yes_no

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
