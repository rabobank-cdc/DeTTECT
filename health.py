import os
import pickle
from difflib import SequenceMatcher
from constants import *


def _print_error_msg(msg, print_error):
    if print_error:
        print(msg)
    return True


def _update_health_state(current, update):
    if current or update:
        return True
    else:
        return update


def _is_file_modified(filename):
    """
    Check if the provided file was modified since the last check
    :param filename: file location
    :return: true when modified else false
    """
    last_modified_file = 'cache/last-modified_' + os.path.basename(filename).rstrip('.yaml')

    def _update_modified_date(date):
        with open(last_modified_file, 'wb') as fd:
            pickle.dump(date, fd)

    if not os.path.exists(last_modified_file):
        last_modified = os.path.getmtime(filename)
        _update_modified_date(last_modified)

        return True
    else:
        with open(last_modified_file, 'rb') as f:
            last_modified_cache = pickle.load(f)
            last_modified_current = os.path.getmtime(filename)

            if last_modified_cache != last_modified_current:
                _update_modified_date(last_modified_current)
                return True
            else:
                return False


def _get_health_state_cache(filename):
    """
    Get file health state from disk
    :param filename: file location
    :return: the cached error state
    """
    last_error_file = 'cache/last-error-state_' + os.path.basename(filename).rstrip('.yaml')

    if os.path.exists(last_error_file):
        with open(last_error_file, 'rb') as f:
            last_error_state_cache = pickle.load(f)

        return last_error_state_cache


def _update_health_state_cache(filename, has_error):
    """
    Write the file health state to disk if changed
    :param filename: file location
    """
    # the function 'check_health_data_sources' will call this function without providing a filename when
    # 'check_health_data_sources' is called from '_events_to_yaml' within 'eql_yaml.py'
    if filename:
        last_error_file = 'cache/last-error-state_' + os.path.basename(filename).rstrip('.yaml')

        def _update(error):
            with open(last_error_file, 'wb') as fd:
                pickle.dump(error, fd)

        if not os.path.exists(last_error_file):
            _update(has_error)
        else:
            error_state_cache = _get_health_state_cache(filename)
            if error_state_cache != has_error:
                _update(has_error)


def _check_for_similar_values(values, values_key_name, health_is_called=False):
    """
    Check if values within the provided list 'values' are a very close match.
    :param values: the list of values to check for close matches
    :values_key_name: the kv-pair key name from which these values are originating
    :health_is_called: specify if an error message should be printed or not
    """
    values_non_empty = [v for v in values if v is not None]
    has_similar = False
    similar = set()
    for i1 in values_non_empty:
        for i2 in values_non_empty:
            match_value = SequenceMatcher(None, i1, i2).ratio()
            if match_value > 0.8 and match_value != 1:
                similar.add(i1)
                similar.add(i2)

    if len(similar) > 0:
        has_similar = _print_error_msg(
            '[!] There are values in the key-value pairs for \'' + values_key_name + '\' which are very similar. Correct where necessary:', health_is_called)
        for s in similar:
            _print_error_msg('    - ' + s, health_is_called)

    return has_similar


def _check_health_score_object(yaml_object, object_type, tech_id, health_is_called):
    """
    Check the health of a score_logbook inside a visibility or detection YAML object
    :param yaml_object: YAML file lines
    :param object_type: 'detection' or 'visibility'
    :param tech_id: ATT&CK technique ID
    :param health_is_called: boolean that specifies if detailed errors in the file will be printed
    :return: True if the YAML file is unhealthy, otherwise False
    """
    has_error = False
    min_score = None
    max_score = None

    if object_type == 'detection':
        min_score = -1
        max_score = 5
    elif object_type == 'visibility':
        min_score = 0
        max_score = 4

    if not isinstance(yaml_object['score_logbook'], list):
        yaml_object['score_logbook'] = [yaml_object['score_logbook']]

    try:
        for score_obj in yaml_object['score_logbook']:
            for key in ['date', 'score', 'comment']:
                if key not in score_obj:
                    has_error = _print_error_msg('[!] Technique ID: ' + tech_id + ' is MISSING a key-value pair in a ' +
                                                 object_type + ' score object within the \'score_logbook\': ' + key, health_is_called)

            if score_obj['score'] is None:
                has_error = _print_error_msg('[!] Technique ID: ' + tech_id + ' has an EMPTY key-value pair in a ' +
                                             object_type + ' score object within the \'score_logbook\': score', health_is_called)

            elif not isinstance(score_obj['score'], int):
                has_error = _print_error_msg('[!] Technique ID: ' + tech_id + ' has an INVALID score format in a ' + object_type +
                                             ' score object within the \'score_logbook\': ' + score_obj['score'] + '  (should be an integer)', health_is_called)

            if 'auto_generated' in score_obj:
                if not isinstance(score_obj['auto_generated'], bool):
                    has_error = _print_error_msg(
                        '[!] Technique ID: ' + tech_id + ' has an INVALID \'auto_generated\' value in a ' + object_type + ' score object within the \'score_logbook\': should be set to \'true\' or \'false\'', health_is_called)

            if isinstance(score_obj['score'], int):
                if score_obj['date'] is None and ((score_obj['score'] > -1 and object_type == 'detection') or (score_obj['score'] > 0 and object_type == 'visibility')):
                    has_error = _print_error_msg('[!] Technique ID: ' + tech_id + ' has an EMPTY key-value pair in a ' +
                                                 object_type + ' score object within the \'score_logbook\': date', health_is_called)

                if not (score_obj['score'] >= min_score and score_obj['score'] <= max_score):
                    has_error = _print_error_msg(
                        '[!] Technique ID: ' + tech_id + ' has an INVALID ' + object_type + ' score in a score object within the \'score_logbook\': ' + str(score_obj['score']) + '  (should be between ' + str(min_score) + ' and ' + str(max_score) + ')', health_is_called)

                if not score_obj['date'] is None:
                    try:
                        # pylint: disable=pointless-statement
                        score_obj['date'].year
                        # pylint: disable=pointless-statement
                        score_obj['date'].month
                        # pylint: disable=pointless-statement
                        score_obj['date'].day
                    except AttributeError:
                        has_error = _print_error_msg('[!] Technique ID: ' + tech_id + ' has an INVALID data format in a ' + object_type +
                                                     ' score object within the \'score_logbook\': ' + score_obj['date'] + '  (should be YYYY-MM-DD without quotes)', health_is_called)
    except KeyError:
        pass

    return has_error


def _check_health_techniques(filename, technique_content, health_is_called):
    """
    Check on errors in the provided technique administration YAML file.
    :param filename: YAML file location
    :param technique_content: content of the YAML file in a list of dicts
    :param health_is_called: boolean that specifies if detailed errors in the file will be printed to stdout
    :return:
    """
    from generic import load_techniques

    has_error = False

    platform = technique_content.get('platform', None)

    if platform != 'all' and platform != ['all']:
        if isinstance(platform, str):
            platform = [platform]
        if platform is None or len(platform) == 0 or platform == '':
            platform = ['empty']
        for p in platform:
            if p.lower() not in PLATFORMS.keys():
                has_error = _print_error_msg(
                    '[!] EMPTY or INVALID value for \'platform\' within the technique admin. '
                    'file: %s (should be value(s) of: [%s] or all)' % (p, ', '.join(list(PLATFORMS.values()))),
                    health_is_called)

    # create a list of ATT&CK technique IDs and check for duplicates
    tech_ids = list(map(lambda x: x['technique_id'], technique_content['techniques']))
    tech_dup = set()
    for tech in tech_ids:
        if tech not in tech_dup:
            tech_dup.add(tech)
        else:
            has_error = _print_error_msg('[!] Duplicate technique ID: ' + tech, health_is_called)

        # check if the technique has a valid format
        if not REGEX_YAML_TECHNIQUE_ID_FORMAT.match(tech):
            has_error = _print_error_msg('[!] Invalid technique ID: ' + tech, health_is_called)

    all_applicable_to = set()

    techniques = load_techniques(filename)
    for tech, v in techniques[0].items():
        for obj_type in ['detection', 'visibility']:
            if obj_type not in v:
                has_error = _print_error_msg('[!] Technique ID: ' + tech + ' is MISSING a key-value pair: ' + obj_type, health_is_called)
            else:
                obj_applicable_to = []
                for obj in v[obj_type]:
                    obj_keys = ['applicable_to', 'comment', 'score_logbook']
                    obj_keys_list = ['applicable_to']
                    obj_keys_not_none = ['applicable_to']
                    if obj_type == 'detection':
                        obj_keys.append('location')
                        obj_keys_list.append('location')
                        obj_keys_not_none.append('location')

                    for okey in obj_keys:
                        if okey not in obj:
                            has_error = _print_error_msg('[!] Technique ID: ' + tech +
                                                         ' is MISSING a key-value pair in \'' + obj_type + '\': ' + okey, health_is_called)

                    for okey in obj_keys_list:
                        if okey in obj:
                            if not isinstance(obj[okey], list):
                                has_error = _print_error_msg('[!] Technique ID: ' + tech + ' the key-value pair \'' + okey +
                                                             '\' in \'' + obj_type + '\' is NOT a list', health_is_called)

                    for okey in obj_keys_not_none:
                        if okey in obj and isinstance(obj[okey], list):
                            none_count = 0
                            for item in obj[okey]:
                                if item is None:
                                    none_count += 1
                            if none_count == 1:
                                has_error = _print_error_msg('[!] Technique ID: ' + tech + ' the key-value pair \'' + okey + '\' in \'' +
                                                             obj_type + '\' has an EMPTY value  (an empty string is allowed: \'\')', health_is_called)
                            elif none_count > 1:
                                has_error = _print_error_msg('[!] Technique ID: ' + tech + ' the key-value pair \'' + okey + '\' in \'' + obj_type +
                                                             '\' has multiple EMPTY values  (an empty string is allowed: \'\')', health_is_called)

                    health = _check_health_score_object(obj, obj_type, tech, health_is_called)
                    has_error = _update_health_state(has_error, health)

                    if 'applicable_to' in obj and isinstance(obj['applicable_to'], list):
                        all_applicable_to.update(obj['applicable_to'])
                        obj_applicable_to.extend(obj['applicable_to'])

                if len(obj_applicable_to) > len(set(obj_applicable_to)):
                    has_error = _print_error_msg('[!] Technique ID: ' + tech + ' the key-value pair \'applicable_to\' in \'' + obj_type +
                                                 '\' has DUPLICATE system values (a system can only be part of one ' +
                                                 'applicable_to key-value pair within the same technique).', health_is_called)

    has_error = _check_for_similar_values(all_applicable_to, 'applicable_to', health_is_called)

    if has_error and not health_is_called:
        print(HEALTH_ERROR_TXT + filename)

    _update_health_state_cache(filename, has_error)


def check_health_data_sources(filename, ds_content, health_is_called, no_print=False, src_eql=False):
    """
    Check on errors in the provided data sources administration YAML file.
    :param filename: YAML file location
    :param ds_content: content of the YAML file in a list of dicts
    :param health_is_called: boolean that specifies if detailed errors in the file will be printed to stdout
    :param no_print: specifies if the non-detailed error message is printed to stdout or not
    :param src_eql: if True, skip certain checks that can fail because EQL filtered out some data source and the
    ATT&CK Platform is not part of the EQL search result
    :return: False if no errors have been found, otherwise True
    """
    has_error = False

    if not src_eql:
        systems_applicable_to = set()
        if 'systems' in ds_content:
            for system in ds_content['systems']:
                # check the platform value
                platform = system['platform']
                if isinstance(platform, str):
                    platform = [platform]
                if platform is None or len(platform) == 0 or platform == '':
                    platform = ['empty']
                for p in platform:
                    if p.lower() not in PLATFORMS.keys() and p.lower() != 'all':
                        has_error = _print_error_msg(
                            '[!] EMPTY or INVALID value for \'platform\' within the data source admin file\'s \'systems\' key-value pair: '
                            '%s (should be value(s) of: [%s] or all)' % (p, ', '.join(list(PLATFORMS.values()))),
                            health_is_called)

                # check applicable_to value
                applicable_to = system['applicable_to']
                if applicable_to is None or applicable_to == '' or applicable_to.lower() == 'all':
                    has_error = _print_error_msg(
                            '[!] EMPTY or INVALID value for \'applicable_to\' within the data source admin file\'s \'systems\' key-value pair: '
                            '%s (should be any string value except an empty string and \'all\')' % applicable_to,
                            health_is_called)
                elif applicable_to.lower() not in systems_applicable_to:
                    systems_applicable_to.add(applicable_to.lower())
                else:
                    has_error = _print_error_msg(
                            '[!] DUPLICATE \'applicable_to\' value within the data source admin file\'s \'systems\' key-value pair: '
                            '%s' % applicable_to, health_is_called)
        else:
            has_error = _print_error_msg('[!] The data source administration file is MISSING the key-value pair \'systems\'',
                                         health_is_called)

    ds_objects_applicable_to = set()

    for ds_global_obj in ds_content['data_sources']:
        for key_global in ['data_source_name', 'data_source']:
            if key_global not in ds_global_obj:
                has_error = _print_error_msg('[!] Data source: \'' + ds_global_obj['data_source_name'] +
                                             '\' is MISSING a key-value pair: ' + key_global, health_is_called)

        if 'data_source' in ds_global_obj:
            if not isinstance(ds_global_obj['data_source'], list):
                ds_global_obj['data_source'] = [ds_global_obj['data_source']]

            glb_obj_applicable_to = []
            for ds_details_obj in ds_global_obj['data_source']:
                obk_keys = ['applicable_to', 'date_registered', 'date_connected',
                            'products', 'available_for_data_analytics', 'comment', 'data_quality']
                obj_keys_list = ['applicable_to', 'products']
                obj_keys_not_none = ['applicable_to', 'products']

                for okey in obk_keys:
                    if okey not in ds_details_obj:
                        has_error = _print_error_msg('[!] Data source: \'' + ds_global_obj['data_source_name'] +
                                                     '\' is MISSING a key-value pair: ' + okey, health_is_called)

                for okey in obj_keys_list:
                    if okey in ds_details_obj:
                        if not isinstance(ds_details_obj[okey], list):
                            has_error = _print_error_msg('[!] Data source: \'' + ds_global_obj['data_source_name'] + '\' the key-value pair \'' + okey +
                                                         '\' is NOT a list', health_is_called)

                for okey in obj_keys_not_none:
                    if okey in ds_details_obj and isinstance(ds_details_obj[okey], list):
                        none_count = 0
                        for item in ds_details_obj[okey]:
                            if item is None:
                                none_count += 1
                        if none_count == 1:
                            has_error = _print_error_msg('[!] Data source: \'' + ds_global_obj['data_source_name'] + '\' the key-value pair \'' + okey +
                                                         '\' has an EMPTY value  (an empty string is allowed: \'\')', health_is_called)
                        elif none_count > 1:
                            has_error = _print_error_msg('[!] Data source: \'' + ds_global_obj['data_source_name'] + '\' the key-value pair \'' + okey +
                                                         '\' has an EMPTY values  (an empty string is allowed: \'\')', health_is_called)

                for key in ['date_registered', 'date_connected']:
                    if key in ds_details_obj and not ds_details_obj[key] is None:
                        try:
                            # pylint: disable=pointless-statement
                            ds_details_obj[key].year
                            # pylint: disable=pointless-statement
                            ds_details_obj[key].month
                            # pylint: disable=pointless-statement
                            ds_details_obj[key].day
                        except AttributeError:
                            has_error = _print_error_msg('[!] Data source: \'' + ds_global_obj['data_source_name'] + '\' has an INVALID data format for the key-value pair \'' + key
                                                         + '\': ' + ds_details_obj[key] + '  (should be YYYY-MM-DD without quotes)', health_is_called)

                if 'available_for_data_analytics' in ds_details_obj:
                    if not isinstance(ds_details_obj['available_for_data_analytics'], bool):
                        has_error = _print_error_msg('[!] Data source: \'' + ds_global_obj['data_source_name'] +
                                                     '\' has an INVALID \'available_for_data_analytics\' value: should be set to \'true\' or \'false\'', health_is_called)

                if 'data_quality' in ds_details_obj:
                    if isinstance(ds_details_obj['data_quality'], dict):
                        for dimension in ['device_completeness', 'data_field_completeness', 'timeliness', 'consistency', 'retention']:
                            if dimension not in ds_details_obj['data_quality']:
                                has_error = _print_error_msg('[!] Data source: \'' + ds_global_obj['data_source_name'] +
                                                             '\' is MISSING a key-value pair in \'data_quality\': ' + dimension, health_is_called)
                            else:
                                if isinstance(ds_details_obj['data_quality'][dimension], int):
                                    if not 0 <= ds_details_obj['data_quality'][dimension] <= 5:
                                        has_error = _print_error_msg('[!] Data source: \'' + ds_global_obj['data_source_name'] + '\' has an INVALID data quality score for the dimension \''
                                                                     + dimension + '\': ' + str(ds_details_obj['data_quality'][dimension]) + '  (should be between 0 and 5)', health_is_called)
                                else:
                                    has_error = _print_error_msg('[!] Data source: \'' + ds_global_obj['data_source_name'] + '\' has an INVALID data quality score for the dimension \'' +
                                                                 dimension + '\': ' + str(ds_details_obj['data_quality'][dimension]) + '  (should be an an integer)', health_is_called)
                    else:
                        has_error = _print_error_msg('[!] Data source: \'' + ds_global_obj['data_source_name'] +
                                                     '\' the key-value pair \'data_quality\' is NOT a dictionary with data quality dimension scores', health_is_called)

                if 'applicable_to' in ds_details_obj and isinstance(ds_details_obj['applicable_to'], list):
                    ds_objects_applicable_to.update(ds_details_obj['applicable_to'])
                    glb_obj_applicable_to.extend(ds_details_obj['applicable_to'])

                    if len(ds_details_obj['applicable_to']) > 1 and 'all' in [a.lower() for a in ds_details_obj['applicable_to']]:
                        has_error = _print_error_msg('[!] Data source: \'' + ds_global_obj['data_source_name'] + '\' has \'all\' as system value ' +
                                                     'within the key-value pair \'applicable_to\', plus additional systems (the build-in system \'all\' ' +
                                                     'cannot be combined with other systems).', health_is_called)

            if len(glb_obj_applicable_to) > len(set(glb_obj_applicable_to)):
                has_error = _print_error_msg('[!] Data source: \'' + ds_global_obj['data_source_name'] + '\' has DUPLICATE system values ' +
                                             'within the key-value pair \'applicable_to\' (a system can only be part of one ' +
                                             'applicable_to key-value pair within the same data source).', health_is_called)
    if not src_eql:
        for ds_a in ds_objects_applicable_to:
            if ds_a.lower() not in systems_applicable_to and ds_a.lower() != 'all':
                has_error = _print_error_msg('[!] The \'applicable_to\' value: \'%s\' within the data source admin. file is used '
                                             'by a data source details object without being specified within the \'systems\' '
                                             'key-value pair' % ds_a, health_is_called)

    if 'exceptions' in ds_content:
        for tech in ds_content['exceptions']:
            tech_id = str(tech['technique_id'])

        if not REGEX_YAML_TECHNIQUE_ID_FORMAT.match(tech_id) and tech_id != 'None':
            has_error = _print_error_msg(
                '[!] INVALID technique ID in the \'exceptions\' list of data source admin. file: ' + tech_id, health_is_called)

    if has_error and not health_is_called and not no_print:
        print(HEALTH_ERROR_TXT + filename)

    _update_health_state_cache(filename, has_error)

    return has_error


def check_yaml_file_health(filename, file_type, health_is_called):
    """
    Check on errors in the provided YAML file.
    :param filename: YAML file location
    :param file_type: currently FILE_TYPE_TECHNIQUE_ADMINISTRATION and FILE_TYPE_DATA_SOURCE_ADMINISTRATION is supported
    :param health_is_called: boolean that specifies if detailed errors in the file will be printed to stdout
    :return:
    """
    from generic import init_yaml

    # first we check if the file was modified. Otherwise, the health check is skipped for performance reasons
    if _is_file_modified(filename) or health_is_called:

        _yaml = init_yaml()
        with open(filename, 'r') as yaml_file:
            yaml_content = _yaml.load(yaml_file)

        if file_type == FILE_TYPE_DATA_SOURCE_ADMINISTRATION:
            check_health_data_sources(filename, yaml_content, health_is_called)
        elif file_type == FILE_TYPE_TECHNIQUE_ADMINISTRATION:
            _check_health_techniques(filename, yaml_content, health_is_called)

    elif _get_health_state_cache(filename):
        print(HEALTH_ERROR_TXT + filename)
