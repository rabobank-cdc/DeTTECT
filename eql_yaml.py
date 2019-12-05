from generic import *
from health import *
import datetime
import sys
from pprint import pprint
import eql
from copy import deepcopy


def _traverse_dict(obj, callback=None):
    """
    Traverse all items in a dictionary
    :param obj: dictionary, list or value
    :param callback: a function that will be called to modify a value
    :return: value or call callback function
    """
    if isinstance(obj, dict):
        value = {k: _traverse_dict(v, callback)
                 for k, v in obj.items()}
    elif isinstance(obj, list):
        value = [_traverse_dict(elem, callback)
                 for elem in obj]
    else:
        value = obj

    if callback is None:  # if a callback is provided, call it to get the new value
        return value
    else:
        return callback(value)


def _traverse_modify_date(obj):
    """
    Modifies a datetime.date object to a string value
    :param obj: dictionary
    :return: function call
    """
    # This will get called for every value in the structure
    def _transformer(value):
        if isinstance(value, datetime.date):
            return str(value)
        else:
            return value

    return _traverse_dict(obj, callback=_transformer)


def _techniques_to_events(techniques, obj_type, include_all_score_objs):
    """
    Transform visibility or detection objects into EQL 'events'
    :param techniques: visibility or detection YAML objects within a list
    :param obj_type: 'visibility' or 'detection'
    :param include_all_score_objs: include all score objects within the score_logbook for the EQL query
    :return: EQL 'events'
    """
    technique_events = []

    techniques = techniques['techniques']

    for tech in techniques:
        if not isinstance(tech[obj_type], list):
            tech[obj_type] = [tech[obj_type]]

        # loop over all visibility or detection objects
        for obj in tech[obj_type]:
            obj = set_yaml_dv_comments(obj)

            if not isinstance(obj['score_logbook'], list):
                obj['score_logbook'] = [obj['score_logbook']]
            if not include_all_score_objs:
                obj['score_logbook'] = [get_latest_score_obj(obj)]

            # loop over all scores (if we have multiple) create the actual events for EQL
            for scr_log in obj['score_logbook']:
                event_lvl_2 = deepcopy(obj)
                event_lvl_2['score_logbook'] = scr_log
                event_lvl_1 = deepcopy(tech)
                del event_lvl_1['visibility']
                del event_lvl_1['detection']
                event_lvl_1[obj_type] = event_lvl_2

                technique_events.append(event_lvl_1)

    return technique_events


def _object_in_technique(obj_event, technique_yaml, obj_type):
    """
    - Check if the detection/visibility object already exists within the provided technique object ('technique_yaml')
    - If it exists return the object's index in the list of other detection/visibility objects to which the
    'score_logbook' should be added. This is needed for techniques which have multiple visibility or detection objects
    due to 'applicable_to'
    :param obj_event: visibility or detection EQL event
    :param technique_yaml: the technique object that's being reconstructing from the EQL events
    :param obj_type: 'visibility' or 'detection'
    :return: -1 if it does not exists, otherwise the index within the list
    """
    idx = 0
    for obj in technique_yaml[obj_type]:
        match = True
        for k, v in obj_event.items():
            # we need to skip the score_logbook in the comparison this will not match as we are still re-creating the object
            if (k in obj and obj[k] == v) or k == 'score_logbook':
                continue
            else:
                match = False
                break
        if match:
            return idx
        idx += 1

    return -1


def _value_in_dict_list(dict_list, dict_key, dict_value):
    """
    Checks if the provided value is present within a certain dict key against a list of dictionaries
    :param dict_list: list of dictionaries
    :param dict_key: key name
    :param dict_value: key value to match on
    :return: true or false
    """
    items = set(map(lambda k: k[dict_key], dict_list))
    if dict_value in items:
        return True
    else:
        return False


def _get_technique_from_list(techniques, tech_id):
    """
    Get a technique object from a list of techniques objects that matches the provided technique ID
    :param techniques: list of techniques
    :param tech_id: technique_id
    :return: technique object or None of no match is found
    """
    for tech in techniques:
        if tech['technique_id'] == tech_id:
            return tech
    return None


def _events_to_yaml(query_results, obj_type):
    """
    Transform the EQL 'events' back to valid YAML objects
    :param query_results: list with EQL 'events'
    :param obj_type: data_sources, detection or visibility EQL 'events'
    :return: list containing YAML objects or None when the events could not be turned into a valid YAML object
    """

    if obj_type == 'data_sources':
        try:
            for r in query_results:
                if r['date_registered'] and isinstance(r['date_registered'], str):
                    r['date_registered'] = datetime.datetime.strptime(r['date_registered'], '%Y-%m-%d')
                if r['date_connected'] and isinstance(r['date_connected'], str):
                    r['date_connected'] = datetime.datetime.strptime(r['date_connected'], '%Y-%m-%d')
        except KeyError:
            print(EQL_INVALID_RESULT_DS)
            pprint(query_results)
            # when using an EQL query that does not result in a dict having valid YAML 'data_source' objects.
            return None

        # Set 'src_eql' to true. EQL results will not contain the platform, but just data source YAML objects.
        # In addition, the search may have excluded certain data sources
        if check_health_data_sources(None, {'data_sources': query_results}, health_is_called=False, no_print=True,
                                     src_eql=True):
            print(EQL_INVALID_RESULT_DS)
            pprint(query_results)
            return None

        return query_results

    elif obj_type in ['visibility', 'detection']:
        try:
            techniques_yaml = []
            # loop over all events and reconstruct the YAML file
            for tech_event in query_results:
                tech_id = tech_event['technique_id']
                tech_name = tech_event['technique_name']
                obj_event = tech_event[obj_type]
                score_logbook_event = tech_event[obj_type]['score_logbook']

                # create the technique dict if not already created
                if not _value_in_dict_list(techniques_yaml, 'technique_id', tech_id):
                    tech_yaml = {
                        'technique_id': tech_id, 'technique_name': tech_name, 'detection': [], 'visibility': []
                    }
                    techniques_yaml.append(tech_yaml)
                else:
                    # The technique dict was already created. Get a tech. dict from the list with a specific tech. ID
                    tech_yaml = _get_technique_from_list(techniques_yaml, tech_id)

                # figure out if the detection/visibility dict already exists
                obj_idx = _object_in_technique(obj_event, tech_yaml, obj_type)

                # create the score object
                score_obj_yaml = {}
                for k, v in score_logbook_event.items():
                    value = v
                    if isinstance(v, str) and REGEX_YAML_VALID_DATE.match(value):
                        value = datetime.datetime.strptime(v, '%Y-%m-%d')
                    score_obj_yaml[k] = value

                # The detection/visibility dict is missing. Create it.
                if obj_idx == -1:
                    obj_event['score_logbook'] = [obj_event['score_logbook']]
                    tech_yaml[obj_type].append(obj_event)
                else:
                    # add the score object to the score_logbook within the proper detection/visibility object using 'obj_idx'
                    tech_yaml[obj_type][obj_idx]['score_logbook'].append(score_obj_yaml)

            return techniques_yaml

        except KeyError:
            print(EQL_INVALID_RESULT_TECH + obj_type + ' object(s):')
            pprint(query_results)
            # when using an EQL query that does not in a valid technique administration file.
            return None


def _merge_yaml(yaml_content_org, yaml_content_visibility=None, yaml_content_detection=None):
    """
    Merge possible filtered detection and visibility objects into a valid technique administration YAML 'file'
    :param yaml_content_org: original, untouched, technique administration 'file'
    :param yaml_content_visibility: list of visibility YAML objects
    :param yaml_content_detection: list of detection YAML objects
    :return: technique administration YAML 'file' (i.e. dict)
    """

    # for both a visibility and detection objects an EQL query was provided
    if yaml_content_visibility and yaml_content_detection:
        techniques_yaml = []

        # combine visibility objects with detection objects
        for tech_vis in yaml_content_visibility:
            detection = _get_technique_from_list(yaml_content_detection, tech_vis['technique_id'])
            if detection:
                detection = detection['detection']
            else:
                detection = deepcopy(YAML_OBJ_DETECTION)

            new_tech = tech_vis
            new_tech['detection'] = detection
            techniques_yaml.append(new_tech)

        # merge detection objects into 'techniques_yaml' which were not already added by the previous step
        for tech_d in yaml_content_detection:
            if not _value_in_dict_list(techniques_yaml, 'technique_id', tech_d['technique_id']):
                visibility = deepcopy(YAML_OBJ_VISIBILITY)

                new_tech = tech_d
                new_tech['visibility'] = visibility
                techniques_yaml.append(new_tech)

    # only a visibility EQL query was provided
    elif yaml_content_visibility:
        techniques_yaml = yaml_content_visibility

        for tech_yaml in techniques_yaml:
            tech_org = _get_technique_from_list(yaml_content_org['techniques'], tech_yaml['technique_id'])
            tech_yaml['detection'] = tech_org['detection']
    # only a detection EQL query was provided
    elif yaml_content_detection:
        techniques_yaml = yaml_content_detection

        for tech_yaml in techniques_yaml:
            tech_org = _get_technique_from_list(yaml_content_org['techniques'], tech_yaml['technique_id'])
            tech_yaml['visibility'] = tech_org['visibility']

    # create the final technique administration YAML 'file'/dict
    techniques_yaml_final = yaml_content_org
    techniques_yaml_final['techniques'] = techniques_yaml

    return techniques_yaml_final


def _prepare_yaml_file(filename, obj_type, include_all_score_objs):
    """
    Prepare the YAML file such that it can be used for EQL
    :param filename: file location of the YAML file
    :param obj_type: technique administration file ('techniques') or data source administration file ('data_sources')
    :return: A dict with date fields compatible for JSON and a new key-value pair event-type
    for the EQL engine
    """
    _yaml = init_yaml()

    with open(filename, 'r') as yaml_file:
        yaml_content = _yaml.load(yaml_file)

    yaml_content_eql = _traverse_modify_date(yaml_content)
    yaml_eql_events = []

    # create EQL events from the list of dictionaries
    if obj_type == 'data_sources':
        for item in yaml_content_eql[obj_type]:
            yaml_eql_events.append(eql.Event(obj_type, 0, item))

    # flatten the technique administration file to EQL events
    elif obj_type in ['visibility', 'detection']:
        yaml_content_eql = _techniques_to_events(yaml_content_eql, obj_type, include_all_score_objs)
        for e in yaml_content_eql:
            yaml_eql_events.append(eql.Event('techniques', 0, e))

    return yaml_eql_events, yaml_content


def _check_query_results(query_results, obj_type):
    """
    Check if the EQL query provided results that
    :param query_results: EQL events
    :param obj_type: 'data_sources', 'visibility' or 'detection'
    :return:
    """
    # the EQL query was not compatible with the schema
    if query_results is None:
        return False
    # show an error to the user when the query resulted on zero results
    result_len = len(query_results)
    if result_len == 0:
        error = '[!] The search returned 0 ' + obj_type + ' objects. Refine your search to return 1 or more ' \
                                                          + obj_type + ' objects.'
        print(error)
        return False
    else:
        if result_len == 1:
            msg = 'The ' + obj_type + ' query executed successfully and provided ' + str(len(query_results)) + ' result.'
        else:
            msg = 'The ' + obj_type + ' query executed successfully and provided ' + str(len(query_results)) + ' results.'
        print(msg)
        return True


def _execute_eql_query(events, query):
    """
    Execute an EQL query against the provided events
    :param events: events
    :param query: EQL query
    :return: the query results (i.e. filtered events) or None when the query did not match the schema
    """
    # learn and load the schema
    schema = eql.Schema.learn(events)

    query_results = []

    def callback(results):
        for event in results.events:
            query_results.append(event.data)

    # create the engine and parse the query
    engine = eql.PythonEngine()
    with schema:
        try:
            eql_query = eql.parse_query(query, implied_any=True, implied_base=True)
            engine.add_query(eql_query)
        except eql.EqlError as e:
            print(e, file=sys.stderr)
            print('\nTake into account the following schema:')
            pprint(schema.schema)
            # when using an EQL query that does not match the schema, return None.
            return None
    engine.add_output_hook(callback)

    # execute the query
    engine.stream_events(events)

    return query_results


def techniques_search(filename, query_visibility=None, query_detection=None, include_all_score_objs=False):
    """
    Perform an EQL search on the technique administration file.
    :param filename: file location of the YAML file on disk
    :param query_visibility: EQL query for the visibility YAML objects
    :param query_detection: EQL query for the detection YAML objects
    :param include_all_score_objs: include all score objects within the score_logbook for the EQL query
    :return: a filtered technique administration YAML 'file' (i.e. dict) or None when the query was not successful
    """
    results_visibility_yaml = None
    results_detection_yaml = None
    if query_visibility:
        visibility_events, yaml_content_org = _prepare_yaml_file(filename, 'visibility',
                                                                 include_all_score_objs=include_all_score_objs)

        results_visibility = _execute_eql_query(visibility_events, query_visibility)
        if not _check_query_results(results_visibility, 'visibility'):
            return None  # the EQL query was not compatible with the schema

        results_visibility_yaml = _events_to_yaml(results_visibility, 'visibility')
    if query_detection:
        detection_events, yaml_content_org = _prepare_yaml_file(filename, 'detection',
                                                                include_all_score_objs=include_all_score_objs)

        results_detection = _execute_eql_query(detection_events, query_detection)
        if not _check_query_results(results_detection, 'detection'):
            return None  # the EQL query was not compatible with the schema

        results_detection_yaml = _events_to_yaml(results_detection, 'detection')

    if (query_visibility and not results_visibility_yaml) or (query_detection and not results_detection_yaml):
        # when using an EQL query that does not result in a dict having a valid technique administration YAML content
        return None

    if query_visibility and query_detection:
        yaml_content = _merge_yaml(yaml_content_org, results_visibility_yaml, results_detection_yaml)
    elif results_visibility_yaml:
        yaml_content = _merge_yaml(yaml_content_org, yaml_content_visibility=results_visibility_yaml)
    elif results_detection_yaml:
        yaml_content = _merge_yaml(yaml_content_org, yaml_content_detection=results_detection_yaml)
    else:
        return filename

    return yaml_content


def data_source_search(filename, query=''):
    """
    Perform an EQL search on a data source administration file
    :param filename: file location of the YAML file on disk
    :param query: EQL query
    :return: a filtered YAML 'file' (i.e. dict) or None when the query was not successful
    """

    yaml_content_eql, yaml_content_org = _prepare_yaml_file(filename, 'data_sources',
                                                            include_all_score_objs=False)
    query_results = _execute_eql_query(yaml_content_eql, query)

    if not _check_query_results(query_results, 'data_sources'):
        return None  # the EQL query was not compatible with the schema

    query_results_yaml = _events_to_yaml(query_results, 'data_sources')

    if query_results_yaml:
        yaml_content = yaml_content_org
        yaml_content['data_sources'] = query_results_yaml

        return yaml_content
    else:
        # when using an EQL query that does not result in a dict having valid YAML objects, return None
        return None
