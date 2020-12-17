import glob
from data_source_mapping import *
from technique_mapping import *
from group_mapping import *
from eql_yaml import *

groups = 'all'
software_group = False
default_platform = ['Windows']
default_matrix = 'enterprise'
groups_overlay = ['']
overlay_type = 'group'
yaml_path = 'sample-data/'
eql_all_scores = False
eql_query_detection = None
eql_query_visibility = None
eql_query_data_sources = None
yaml_all_techniques = False


def _clear():
    """
    Clears the terminal screen and prints the title and version of the application.
    :return:
    """
    if sys.platform.startswith('linux') or sys.platform == 'darwin':
        os.system('clear')
    elif sys.platform == 'win32':
        os.system('cls')
    name = '-= %s =-' % APP_NAME
    desc = '-- %s --' % APP_DESC
    version = 'version %s' % VERSION
    print(' ' * int((len(desc) - len(name)) / 2) + name)
    print(desc)
    print(' ' * int((len(desc) - len(version)) / 2) + version)
    print('')


def _ask_input():
    """
    Waits for input from the terminal.
    :return:
    """
    return input(' >>   ')


def _wait():
    """
    Prints wait statement and wait for pressing ENTER key.
    :return:
    """
    print('')
    print('Press a key to continue')
    input('')


def interactive_menu():
    """
    Main menu for interactive mode.
    :return:
    """
    _clear()
    print('Select a mode:')
    print('1. %s' % MENU_NAME_DATA_SOURCE_MAPPING)
    print('2. %s' % MENU_NAME_VISIBILITY_MAPPING)
    print('3. %s' % MENU_NAME_DETECTION_COVERAGE_MAPPING)
    print('4. %s' % MENU_NAME_THREAT_ACTOR_GROUP_MAPPING)
    print('5. Updates')
    print('6. Statistics')
    print('9. Quit')
    choice = _ask_input()
    if choice == '1':
        _menu_data_source(_select_file(MENU_NAME_DATA_SOURCE_MAPPING, 'data sources', FILE_TYPE_DATA_SOURCE_ADMINISTRATION))
    elif choice == '2':
        _menu_visibility(_select_file(MENU_NAME_VISIBILITY_MAPPING, 'techniques (used to score the level of visibility)', FILE_TYPE_TECHNIQUE_ADMINISTRATION),
                         _select_file(MENU_NAME_VISIBILITY_MAPPING, 'data sources (used to add metadata on the involved data sources to the heat map)', FILE_TYPE_DATA_SOURCE_ADMINISTRATION, False))
    elif choice == '3':
        _menu_detection(_select_file(MENU_NAME_DETECTION_COVERAGE_MAPPING, 'techniques', FILE_TYPE_TECHNIQUE_ADMINISTRATION))
    elif choice == '4':
        _menu_groups()
    elif choice == '5':
        _menu_updates()
    elif choice == '6':
        _menu_statistics()
    elif choice in ['9', 'q']:
        quit()
    else:
        interactive_menu()


def _select_file(title, what, expected_file_type, b_clear=True):
    """
    Prints and handles the file selection in the terminal. It shows just .yaml files.
    :param title: title to print on top of this menu
    :param what: print for what purpose the file is selected
    :param expected_file_type: the expected file type of the YAML file
    :param b_clear: clear the terminal before showing this menu
    :return: filename of the selected file
    """
    global yaml_path
    if b_clear:
        _clear()
        print('Menu: %s' % title)
        print('')
    print('Select the YAML file with %s:' % what)
    print('')
    print('Path: %s' % yaml_path)
    n = 1
    files = []
    for f in glob.glob(yaml_path + '*.yaml'):
        files.append(f)
        print('%d. %s' % (n, f))
        n += 1

    change_path_nr = 8 if n < 8 else n + (5 - n % 5) - 1
    print('%d. Change path' % change_path_nr)

    back_nr = 9 if n < 9 else n + (5 - n % 5)
    print('%d. Back to main menu.' % back_nr)

    choice = _ask_input()
    if choice == str(change_path_nr):
        print("Supply full or relative path:")
        choice = _ask_input()
        choice = choice if choice.endswith('/') else choice + '/'
        if os.path.exists(choice):
            yaml_path = choice
            return _select_file(title, what, expected_file_type, b_clear)
        else:
            print("[!] Path doesn't exist")
            _wait()
            return _select_file(title, what, expected_file_type, b_clear)
    elif choice == str(back_nr):
        interactive_menu()
    elif choice == 'q':
        quit()
    else:
        if choice.isdigit() and int(choice) < n:
            filename = files[int(choice) - 1]
            file_type = check_file(filename, file_type=expected_file_type)
            if file_type:
                print('Selected file: ' + filename)
                _wait()
                return filename
        else:
            print("[!] Invalid choice")

        _wait()
        return _select_file(title, what, expected_file_type, b_clear)


def _menu_updates():
    """
    Prints and handles the menu for the Updates functionality.
    :return:
    """
    _clear()

    print('Menu: Updates')
    print('')
    print('Select for what you want to see updates:')
    print('1.  Techniques (sorted by modified date)')
    print('1s. Techniques (sorted by creation date)')
    print('2.  Groups (sorted by modified date)')
    print('2s. Groups (sorted by creation date)')
    print('3.  Software (sorted by modified date)')
    print('3s. Software (sorted by creation date)')
    print('9. Back to main menu.')
    choice = _ask_input()
    if choice == '1':
        get_updates('techniques')
        _wait()
    if choice == '1s':
        get_updates('techniques', 'created')
        _wait()
    elif choice == '2':
        get_updates('groups')
        _wait()
    elif choice == '2s':
        get_updates('groups', 'created')
        _wait()
    elif choice == '3':
        get_updates('software')
        _wait()
    elif choice == '3s':
        get_updates('software', 'created')
        _wait()
    elif choice == '9':
        interactive_menu()
    elif choice == 'q':
        quit()
    _menu_updates()


def _menu_statistics():
    """
    Handles the Statistics functionality.
    :return:
    """
    global default_matrix
    _clear()
    print('Menu: Statistics')
    print('')
    print('Options:')
    print('1. Matrix: %s' % default_matrix)
    print('')
    print('Select what you want to do:')
    print('2. Get a sorted count on how many ATT&CK Enterprise techniques are covered by a particular Data Source.')
    print('3. Get a sorted count on how many ATT&CK Enterprise or Mobile techniques are covered by a Mitigation.')
    print('9. Back to main menu.')
    choice = _ask_input()
    if choice == '1':
        default_matrix = 'mobile' if default_matrix == 'enterprise' else 'enterprise'
    elif choice == '2':
        get_statistics_data_sources()
        _wait()
    elif choice == '3':
        get_statistics_mitigations(default_matrix)
        _wait()
    elif choice == '9':
        interactive_menu()
        _wait()
    elif choice == 'q':
        quit()

    _menu_statistics()


def _menu_data_source(filename_ds):
    """
    Prints and handles the Data source mapping functionality.
    :param filename_ds:
    :return:
    """
    global eql_query_data_sources, yaml_all_techniques
    _clear()
    print('Menu: %s' % MENU_NAME_DATA_SOURCE_MAPPING)
    print('')
    print('Selected data source YAML file: %s' % filename_ds)
    print('')
    print('Options:')
    eql_ds_str = '' if not eql_query_data_sources else eql_query_data_sources
    print('1. Only include data sources which match the provided EQL query: ' + eql_ds_str)
    print('2. Include all ATT&CK techniques in the generated YAML file that apply to the platform(s) '
          'specified in the data source YAML file: ' + str(yaml_all_techniques))
    print('')
    print('Select what you want to do:')
    print('3. Generate a data source layer for the ATT&CK Navigator.')
    print('4. Generate a graph with data sources added through time.')
    print('5. Generate an Excel sheet with all data sources.')
    print('6. Generate a technique administration YAML file with visibility scores, based on the number of available '
          'data sources')
    print('7. update the visibility scores within a technique administration YAML file based on changes within any of '
          'the data sources. \nPast visibility scores are preserved in the score_logbook, and manually assigned scores are '
          'not updated without your approval. \nThe updated visibility are based on the number of available data sources.')
    print('8. Check the data sources YAML file for errors.')
    print('9. Back to main menu.')
    choice = _ask_input()
    if choice == '1':
        print('Specify the EQL query for data source objects:')
        eql_query_data_sources = _ask_input().lower()
    elif choice == '2':
        yaml_all_techniques = not yaml_all_techniques

    elif choice in ['3', '4', '5', '6']:
        file_ds = filename_ds

        if eql_query_data_sources:
            file_ds = data_source_search(filename_ds, eql_query_data_sources)
            if not file_ds:
                _wait()  # something went wrong in executing the search or 0 results where returned
                _menu_data_source(filename_ds)
        if choice == '3':
            print('Writing data sources layer...')
            generate_data_sources_layer(file_ds, None, None)
            _wait()
        elif choice == '4':
            print('Drawing the graph...')
            plot_data_sources_graph(file_ds, None)
            _wait()
        elif choice == '5':
            print('Generating Excel file...')
            export_data_source_list_to_excel(file_ds, None, eql_search=eql_query_data_sources)
            _wait()
        elif choice == '6':
            print('Generating YAML file...')
            generate_technique_administration_file(file_ds, None, all_techniques=yaml_all_techniques)
            _wait()
    elif choice == '7':
        filename_t = _select_file(MENU_NAME_DETECTION_COVERAGE_MAPPING, 'techniques (used to score the level of visibility)',
                                  FILE_TYPE_TECHNIQUE_ADMINISTRATION, False)
        print('Updating visibility scores...')
        update_technique_administration_file(filename_ds, filename_t)
        _wait()
    elif choice == '8':
        print('Checking the data source YAML for errors...')
        check_yaml_file_health(filename_ds, FILE_TYPE_DATA_SOURCE_ADMINISTRATION, health_is_called=True)
        _wait()
    elif choice == '9':
        interactive_menu()
    elif choice == 'q':
        quit()
    _menu_data_source(filename_ds)


def _menu_detection(filename_t):
    """
    Prints and handles the Detection coverage mapping functionality.
    :param filename_t:
    :return:
    """
    global eql_all_scores, eql_query_detection, eql_query_visibility

    filename_str = filename_t
    _clear()
    print('Menu: %s' % MENU_NAME_DETECTION_COVERAGE_MAPPING)
    print('')
    print('Selected techniques YAML file: %s' % filename_str)
    print('')
    print('Options:')
    eql_d_str = '' if not eql_query_detection else eql_query_detection
    eql_v_str = '' if not eql_query_visibility else eql_query_visibility
    print('1. Only include detection objects which match the EQL query: ' + eql_d_str)
    print('2. Only include visibility objects which match the EQL query: ' + eql_v_str)
    print('3. Include all \'score\' objects from the \'score_logbook\' in the EQL search: ' + str(eql_all_scores))
    print('')
    print('Select what you want to do:')
    print('4. Generate a layer for detection coverage for the ATT&CK Navigator.')
    print('5. Generate a layer for detection coverage overlaid with visibility for the ATT&CK Navigator.')
    print('6. Generate a graph with detections added through time.')
    print('7. Generate an Excel sheet with all administrated techniques.')
    print('8. Check the technique YAML file for errors.')
    print('9. Back to main menu.')
    choice = _ask_input()
    if choice == '1':
        print('Specify the EQL query for detection objects:')
        eql_query_detection = _ask_input().lower()
    elif choice == '2':
        print('Specify the EQL query for visibility objects:')
        eql_query_visibility = _ask_input().lower()
    elif choice == '3':
        eql_all_scores = not eql_all_scores
    elif choice in ['4', '5', '6', '7']:
        file_tech = filename_t

        if eql_query_detection or eql_query_visibility:
            file_tech = techniques_search(filename_t, eql_query_visibility, eql_query_detection,
                                          include_all_score_objs=eql_all_scores)
            if not file_tech:
                _wait()  # something went wrong in executing the search or 0 results where returned
                _menu_detection(filename_t)
        if choice == '4':
            print('Writing detection coverage layer...')
            generate_detection_layer(file_tech, None, False, None, None)
            _wait()
        elif choice == '5':
            filename_ds = _select_file(MENU_NAME_DETECTION_COVERAGE_MAPPING, 'data sources (used to add metadata on the '
                                                                             'involved data sources to the heat map)',
                                       FILE_TYPE_DATA_SOURCE_ADMINISTRATION, False)
            print('Writing detection coverage layer with visibility as overlay...')
            generate_detection_layer(file_tech, filename_ds, True, None, None)
            _wait()
        elif choice == '6':
            print('Drawing the graph...')
            plot_graph(file_tech, 'detection', None)
            _wait()
        elif choice == '7':
            print('Generating Excel file...')
            export_techniques_list_to_excel(file_tech, None)
            _wait()
    elif choice == '8':
        print('Checking the technique YAML file for errors...')
        check_yaml_file_health(filename_t, FILE_TYPE_TECHNIQUE_ADMINISTRATION, health_is_called=True)
        _wait()
    elif choice == '9':
        interactive_menu()
    elif choice == 'q':
        quit()
    _menu_detection(filename_t)


def _menu_visibility(filename_t, filename_ds):
    """
    Prints and handles the Visibility coverage mapping functionality.
    :param filename_t:
    :param filename_ds:
    :return:
    """
    global eql_all_scores, eql_query_detection, eql_query_visibility

    filename_str = filename_t
    _clear()
    print('Menu: %s' % MENU_NAME_VISIBILITY_MAPPING)
    print('')
    print('Selected techniques YAML file: %s' % filename_str)
    print('Selected data source YAML file: %s' % filename_ds)
    print('')
    print('Options:')
    eql_d_str = '' if not eql_query_detection else eql_query_detection
    eql_v_str = '' if not eql_query_visibility else eql_query_visibility
    print('1. Only include visibility objects which match the EQL query: ' + eql_v_str)
    print('2. Only include detection objects which match the EQL query: ' + eql_d_str)
    print('3. Include all \'score\' objects from the \'score_logbook\' in the EQL search: ' + str(eql_all_scores))
    print('')
    print('Select what you want to do:')
    print('4. Generate a layer for visibility for the ATT&CK Navigator.')
    print('5. Generate a layer for visibility overlaid with detection coverage for the ATT&CK Navigator.')
    print('6. Generate a graph with visibility added through time.')
    print('7. Generate an Excel sheet with all administrated techniques.')
    print('8. Check the technique YAML file for errors.')
    print('9. Back to main menu.')
    choice = _ask_input()
    if choice == '1':
        print('Specify the EQL query for visibility objects:')
        eql_query_visibility = _ask_input().lower()
    elif choice == '2':
        print('Specify the EQL query for detection objects:')
        eql_query_detection = _ask_input().lower()
    elif choice == '3':
        eql_all_scores = not eql_all_scores
    elif choice in ['4', '5', '6', '7']:
        file_tech = filename_t

        if eql_query_detection or eql_query_visibility:
            file_tech = techniques_search(filename_t, eql_query_visibility, eql_query_detection,
                                          include_all_score_objs=eql_all_scores)
            if not file_tech:
                _wait()  # something went wrong in executing the search or 0 results where returned
                _menu_visibility(filename_t, filename_ds)
        if choice == '4':
            print('Writing visibility coverage layer...')
            generate_visibility_layer(file_tech, filename_ds, False, None, None)
            _wait()
        elif choice == '5':
            print('Writing visibility coverage layer overlaid with detections...')
            generate_visibility_layer(file_tech, filename_ds, True, None, None)
            _wait()
        elif choice == '6':
            print('Drawing the graph...')
            plot_graph(file_tech, 'visibility', None)
            _wait()
        elif choice == '7':
            print('Generating Excel file...')
            export_techniques_list_to_excel(file_tech, None)
            _wait()
        elif choice == '8':
            print('Checking the technique YAML file for errors...')
            check_yaml_file_health(file_tech, FILE_TYPE_TECHNIQUE_ADMINISTRATION, health_is_called=True)
            _wait()
    elif choice == '9':
        interactive_menu()
    elif choice == 'q':
        quit()
    _menu_visibility(filename_t, filename_ds)


def _menu_groups():
    """
    Prints and handles the Threat actor group mapping functionality.
    :return:
    """
    global groups, software_group, default_platform, groups_overlay, overlay_type, eql_all_scores, \
        eql_query_detection, eql_query_visibility
    _clear()
    print('Menu: %s' % MENU_NAME_THREAT_ACTOR_GROUP_MAPPING)
    print('')
    print('Options:')
    print('1. Software group: %s' % str(software_group))
    print('2. Platform: %s' % ','.join(default_platform))
    print('3. Groups: %s' % groups)
    print('4. Overlay: ')
    print('    - %s: %s' % ('File' if os.path.exists(groups_overlay[0]) else 'Groups', ",".join(groups_overlay)))
    print('    - Type: %s' % overlay_type)
    print('5. EQL search: ')
    eql_d_str = '' if not eql_query_detection else eql_query_detection
    eql_v_str = '' if not eql_query_visibility else eql_query_visibility
    print('    - Only include detection objects which match the EQL query: ' + eql_d_str)
    print('    - Only include visibility objects which match the EQL query: ' + eql_v_str)
    print('    - Include all \'score\' objects from the \'score_logbook\' in the EQL search: ' + str(eql_all_scores))
    print('')
    print('Select what you want to do:')
    print('6. Generate a heat map layer.')
    print('9. Back to main menu.')
    choice = _ask_input()
    if choice == '1':
        software_group = not software_group
    elif choice == '2':
        print('Specify platform (%s):' % ', '.join(['all'] + list(PLATFORMS.values())))
        p = _ask_input().lower()
        default_platform = [PLATFORMS[p]] if p in PLATFORMS.keys() else ['all']
    elif choice == '3':
        print('Specify the groups to include separated using commas. Group can be their ID, name or alias '
              '(default is all groups). Other option is to provide a YAML file with a custom group(s)')
        g = _ask_input()
        groups = g if g != '' else 'all'
    elif choice == '4':
        print('')
        print('1. Overlay with groups.')
        print('2. Overlay with detections.')
        print('3. Overlay with visibility.')
        print('4. No overlay.')
        choice = _ask_input()
        if choice == '1':
            print('Specify the group(s) to overlay (in a different color) on the one specified in the Groups option. '
                  'A group can be their ID, name or alias separated using commas. Other option is to provide a YAML '
                  'file with a custom group(s).')
            overlay_type = OVERLAY_TYPE_GROUP
            groups_overlay = _ask_input().split(",")
        elif choice == '2':
            overlay_type = OVERLAY_TYPE_DETECTION
            groups_overlay = [_select_file(MENU_NAME_THREAT_ACTOR_GROUP_MAPPING, 'techniques', FILE_TYPE_TECHNIQUE_ADMINISTRATION, False)]
        elif choice == '3':
            overlay_type = OVERLAY_TYPE_VISIBILITY
            groups_overlay = [_select_file(MENU_NAME_THREAT_ACTOR_GROUP_MAPPING, 'techniques', FILE_TYPE_TECHNIQUE_ADMINISTRATION, False)]
        elif choice == '4':
            overlay_type = ''
            groups_overlay = ['']
    elif choice == '5':
        print('')
        print('1. Only include detection objects which match the EQL query: ' + eql_d_str)
        print('2. Only include visibility objects which match the EQL query: ' + eql_v_str)
        print('3. Include all \'score\' objects from the \'score_logbook\' in the EQL search: ' + str(eql_all_scores))
        choice = _ask_input()

        if choice == '1':
            print('Specify the EQL query for detection objects:')
            eql_query_detection = _ask_input().lower()
        elif choice == '2':
            print('Specify the EQL query for visibility objects:')
            eql_query_visibility = _ask_input().lower()
        elif choice == '3':
            eql_all_scores = not eql_all_scores

    elif choice == '6':
        generate_group_heat_map(groups, groups_overlay, overlay_type, default_platform,
                                software_group, eql_query_visibility, eql_query_detection, False,
                                None, None, include_all_score_objs=eql_all_scores)
        _wait()
    elif choice == '9':
        interactive_menu()
    elif choice == 'q':
        quit()
    _menu_groups()
