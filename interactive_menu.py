import sys
import glob
from data_source_mapping import *
from technique_mapping import *
from group_mapping import *
from constants import *


groups = 'all'
software_group = False
platform = 'Windows'
stage = 'attack'
groups_overlay = ''
overlay_type = 'group'
filter_applicable_to = 'all'
yaml_path = 'sample-data/'


def clear():
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
    print(' ' * int((len(desc)-len(name))/2) + name)
    print(desc)
    print(' ' * int((len(desc)-len(version))/2) + version)
    print('')


def ask_input():
    """
    Waits for input from the terminal.
    :return:
    """
    return input(' >>   ')


def wait():
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
    clear()
    print('Select a mode:')
    print('1. %s' % MENU_NAME_DATA_SOURCE_MAPPING)
    print('2. %s' % MENU_NAME_VISIBILITY_MAPPING)
    print('3. %s' % MENU_NAME_DETECTION_COVERAGE_MAPPING)
    print('4. %s' % MENU_NAME_THREAT_ACTOR_GROUP_MAPPING)
    print('5. Updates')
    print('6. Statistics')
    print('9. Quit')
    choice = ask_input()
    if choice == '1':
        menu_data_source(select_file(MENU_NAME_DATA_SOURCE_MAPPING, 'data sources', FILE_TYPE_DATA_SOURCE_ADMINISTRATION))
    elif choice == '2':
        menu_visibility(select_file(MENU_NAME_VISIBILITY_MAPPING, 'techniques (used to score the level of visibility)', FILE_TYPE_TECHNIQUE_ADMINISTRATION),
                        select_file(MENU_NAME_VISIBILITY_MAPPING, 'data sources (used to add metadata on the involved data sources to the heat map)', FILE_TYPE_DATA_SOURCE_ADMINISTRATION, False))
    elif choice == '3':
        menu_detection(select_file(MENU_NAME_DETECTION_COVERAGE_MAPPING, 'techniques', FILE_TYPE_TECHNIQUE_ADMINISTRATION))
    elif choice == '4':
        menu_groups()
    elif choice == '5':
        menu_updates()
    elif choice == '6':
        menu_statistics()
    elif choice in ['9', 'q']:
        quit()
    else:
        interactive_menu()


def select_file(title, what, expected_file_type, b_clear=True):
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
        clear()
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

    choice = ask_input()
    if choice == str(change_path_nr):
        print("Supply full or relative path:")
        choice = ask_input()
        choice = choice if choice.endswith('/') else choice + '/'
        if os.path.exists(choice):
            yaml_path = choice
            return select_file(title, what, expected_file_type, b_clear)
        else:
            print("[!] Path doesn't exist")
            wait()
            return select_file(title, what, expected_file_type, b_clear)
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
                wait()
                return filename
        else:
            print("[!] Invalid choice")

        wait()
        return select_file(title, what, expected_file_type, b_clear)


def menu_updates():
    """
    Prints and handles the menu for the Updates functionality.
    :return:
    """
    clear()

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
    choice = ask_input()
    if choice == '1':
        get_updates('techniques')
        wait()
    if choice == '1s':
        get_updates('techniques', 'created')
        wait()
    elif choice == '2':
        get_updates('groups')
        wait()
    elif choice == '2s':
        get_updates('groups', 'created')
        wait()
    elif choice == '3':
        get_updates('software')
        wait()
    elif choice == '3s':
        get_updates('software', 'created')
        wait()
    elif choice == '9':
        interactive_menu()
    elif choice == 'q':
        quit()
    menu_updates()


def menu_statistics():
    """
    Handles the Statistics functionality.
    :return:
    """
    clear()
    print('Menu: Statistics')
    print('')
    get_statistics()
    wait()
    interactive_menu()


def menu_data_source(filename):
    """
    Prints and handles the Data source mapping functionality.
    :param filename:
    :return:
    """
    clear()
    print('Menu: %s' % MENU_NAME_DATA_SOURCE_MAPPING)
    print('')
    print('Selected data source YAML file: %s' % filename)
    print('')
    print('Select what you want to do:')
    print('1. Generate a data source layer for the ATT&CK Navigator.')
    print('2. Generate a graph with data sources added through time.')
    print('3. Generate an Excel sheet with all data sources.')
    print('4. Generate a technique administration YAML file with visibility scores, based on the number of available '
          'data sources')
    print('9. Back to main menu.')
    choice = ask_input()
    if choice == '1':
        print('Writing data sources layer...')
        generate_data_sources_layer(filename)
        wait()
    elif choice == '2':
        print('Drawing the graph...')
        plot_data_sources_graph(filename)
        wait()
    elif choice == '3':
        print('Generating Excel file...')
        export_data_source_list_to_excel(filename)
        wait()
    elif choice == '4':
        print('Generating YAML file...')
        generate_technique_administration_file(filename)
        wait()
    elif choice == '9':
        interactive_menu()
    elif choice == 'q':
        quit()
    menu_data_source(filename)


def menu_detection(filename_t):
    """
    Prints and handles the Detection coverage mapping functionality.
    :param filename_t:
    :return:
    """
    global filter_applicable_to
    clear()
    print('Menu: %s' % MENU_NAME_DETECTION_COVERAGE_MAPPING)
    print('')
    print('Selected techniques YAML file: %s' % filename_t)
    print('')
    print('Options:')
    print('1. Filter techniques based on the \'applicable_to\' field in the technique administration YAML file (not '
          'for Excel output): %s' % filter_applicable_to)
    print('')
    print('Select what you want to do:')
    print('2. Generate a layer for detection coverage for the ATT&CK Navigator.')
    print('3. Generate a layer for detection coverage overlaid with visibility for the ATT&CK Navigator.')
    print('4. Generate a graph with detections added through time.')
    print('5. Generate an Excel sheet with all administrated techniques.')
    print('6. Check the technique YAML file for errors.')
    print('9. Back to main menu.')
    choice = ask_input()
    if choice == '1':
        print('Specify your filter for the applicable_to field:')
        filter_applicable_to = ask_input().lower()
    elif choice == '2':
        print('Writing detection coverage layer...')
        generate_detection_layer(filename_t, None, False, filter_applicable_to)
        wait()
    elif choice == '3':
        filename_ds = select_file(MENU_NAME_DETECTION_COVERAGE_MAPPING, 'data sources (used to add metadata on the '
                                                                        'involved data sources to the heat map)',
                                  FILE_TYPE_DATA_SOURCE_ADMINISTRATION, False)
        print('Writing detection coverage layer with visibility as overlay...')
        generate_detection_layer(filename_t, filename_ds, True, filter_applicable_to)
        wait()
    elif choice == '4':
        print('Drawing the graph...')
        plot_detection_graph(filename_t, filter_applicable_to)
        wait()
    elif choice == '5':
        print('Generating Excel file...')
        export_techniques_list_to_excel(filename_t)
        wait()
    elif choice == '6':
        print('Checking the technique YAML file for errors...')
        check_yaml_file_health(filename_t, FILE_TYPE_TECHNIQUE_ADMINISTRATION, health_is_called=True)
        wait()
    elif choice == '9':
        interactive_menu()
    elif choice == 'q':
        quit()
    menu_detection(filename_t)


def menu_visibility(filename_t, filename_ds):
    """
    Prints and handles the Visibility coverage mapping functionality.
    :param filename_t:
    :param filename_ds:
    :return:
    """
    global filter_applicable_to
    clear()
    print('Menu: %s' % MENU_NAME_VISIBILITY_MAPPING)
    print('')
    print('Selected techniques YAML file: %s' % filename_t)
    print('Selected data source YAML file: %s' % filename_ds)
    print('')
    print('Options:')
    print('1. Filter techniques based on the \'applicable_to\' field in the technique administration YAML file (not for '
          'Excel output): %s' % filter_applicable_to)
    print('')
    print('Select what you want to do:')
    print('2. Generate a layer for visibility for the ATT&CK Navigator.')
    print('3. Generate a layer for visibility overlaid with detection coverage for the ATT&CK Navigator.')
    print('4. Generate an Excel sheet with all administrated techniques.')
    print('5. Check the technique YAML file for errors.')
    print('9. Back to main menu.')
    choice = ask_input()
    if choice == '1':
        print('Specify your filter for the applicable_to field:')
        filter_applicable_to = ask_input().lower()
    elif choice == '2':
        print('Writing visibility coverage layer...')
        generate_visibility_layer(filename_t, filename_ds, False, filter_applicable_to)
        wait()
    elif choice == '3':
        print('Writing visibility coverage layer overlaid with detections...')
        generate_visibility_layer(filename_t, filename_ds, True, filter_applicable_to)
        wait()
    elif choice == '4':
        print('Generating Excel file...')
        export_techniques_list_to_excel(filename_t)
        wait()
    elif choice == '5':
        print('Checking the technique YAML file for errors...')
        check_yaml_file_health(filename_t, FILE_TYPE_TECHNIQUE_ADMINISTRATION, health_is_called=True)
        wait()
    elif choice == '9':
        interactive_menu()
    elif choice == 'q':
        quit()
    menu_visibility(filename_t, filename_ds)


def menu_groups():
    """
    Prints and handles the Threat actor group mapping functionality.
    :return:
    """
    global groups, software_group, platform, stage, groups_overlay, overlay_type, filter_applicable_to
    clear()
    print('Menu: %s' % MENU_NAME_THREAT_ACTOR_GROUP_MAPPING)
    print('')
    print('Options:')
    print('1. Software group: %s' % str(software_group))
    print('2. Platform: %s' % platform)
    print('3. Stage: %s' % stage)
    print('4. Groups: %s' % groups)
    print('5. Overlay: ')
    print('    - %s: %s' % ('File' if os.path.exists(groups_overlay) else 'Groups', groups_overlay))
    print('    - Type: %s' % overlay_type)
    print('6. Filter techniques in the detection or visibility overlay based on the \'applicable_to\' field in the '
          'technique administration YAML file: %s' % filter_applicable_to)
    print('')
    print('7. Generate a heat map layer.')
    print('9. Back to main menu.')
    choice = ask_input()
    if choice == '1':
        print('Specify True or False for software group:')
        software_group = True if ask_input().lower() == 'true' else False
    elif choice == '2':
        print('Specify platform (all, Linux, macOS, Windows):')
        p = ask_input().lower()
        platform = 'Windows' if p == 'windows' else 'Linux' if p == 'linux' else 'macOS' if p == 'macos' else 'all'
    elif choice == '3':
        print('Specify stage (pre-attack, attack):')
        s = ask_input().lower()
        stage = 'pre-attack' if s == 'pre-attack' else 'attack'
    elif choice == '4':
        print('Specify the groups to include separated using commas. Group can be their ID, name or alias '
              '(default is all groups). Other option is to provide a YAML file with a custom group(s)')
        g = ask_input()
        groups = g if g is not '' else 'all'
    elif choice == '5':
        print('')
        print('1. Overlay with groups.')
        print('2. Overlay with detections.')
        print('3. Overlay with visibility.')
        print('4. No overlay.')
        choice = ask_input()
        if choice == '1':
            print('Specify the group(s) to overlay (in a different color) on the one specified in the Groups option. '
                  'A group can be their ID, name or alias separated using commas. Other option is to provide a YAML '
                  'file with a custom group(s).')
            overlay_type = OVERLAY_TYPE_GROUP
            groups_overlay = ask_input()
        elif choice == '2':
            overlay_type = OVERLAY_TYPE_DETECTION
            groups_overlay = select_file(MENU_NAME_THREAT_ACTOR_GROUP_MAPPING, 'techniques', FILE_TYPE_TECHNIQUE_ADMINISTRATION, False)
        elif choice == '3':
            overlay_type = OVERLAY_TYPE_VISIBILITY
            groups_overlay = select_file(MENU_NAME_THREAT_ACTOR_GROUP_MAPPING, 'techniques', FILE_TYPE_TECHNIQUE_ADMINISTRATION, False)
        elif choice == '4':
            overlay_type = ''
            groups_overlay = ''
    elif choice == '6':
        print('Specify your filter for the applicable_to field:')
        filter_applicable_to = ask_input().lower()
    elif choice == '7':
        generate_group_heat_map(groups, groups_overlay, overlay_type, stage, platform, software_group, filter_applicable_to)
        wait()
    elif choice == '9':
        interactive_menu()
    elif choice == 'q':
        quit()
    menu_groups()
