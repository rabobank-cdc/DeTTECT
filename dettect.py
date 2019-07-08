import argparse
from interactive_menu import *
import os
import signal


def init_menu():
    """
    Initialise the command line parameter menu.
    :return:
    """
    menu_parser = argparse.ArgumentParser(description='Detect Tactics, Techniques & Combat Threats',
                                          epilog='Source: https://github.com/rabobank-cdc/DeTTECT')
    menu_parser.add_argument('--version', action='version', version='%(prog)s ' + VERSION)
    menu_parser.add_argument('-i', '--interactive', help='launch the interactive menu, which has support for all modes',
                             action='store_true')

    # add subparsers
    subparsers = menu_parser.add_subparsers(title='MODE',
                                            description='Select the mode to use. Every mode has its own arguments and '
                                                        'help info displayed using: {visibility, detection, group, '
                                                        'generic} --help', metavar='', dest='subparser')

    # create the data source parser
    parser_data_sources = subparsers.add_parser('datasource', help='data source mapping and quality',
                                                aliases=['ds'],
                                                description='Create a heat map based on data sources, output data '
                                                            'sources to Excel or generate a data source improvement '
                                                            'graph.')
    parser_data_sources.add_argument('-f', '--file', help='path to the data source administration YAML file',
                                     required=True)
    parser_data_sources.add_argument('-l', '--layer', help='generate a data source layer for the ATT&CK navigator',
                                     action='store_true')
    parser_data_sources.add_argument('-e', '--excel', help='generate an Excel sheet with all data source',
                                     action='store_true')
    parser_data_sources.add_argument('-g', '--graph', help='generate a graph with data sources added through time',
                                     action='store_true')
    parser_data_sources.add_argument('-y', '--yaml', help='generate a technique administration YAML file with '
                                                          'visibility scores based on the number of available data '
                                                          'sources',
                                     action='store_true')

    # create the visibility parser
    parser_visibility = subparsers.add_parser('visibility', aliases=['v'],
                                              help='visibility coverage mapping based on techniques and data sources',
                                              description='Create a heat map based on visibility scores, overlay '
                                                          'visibility with detections, output to Excel or check the '
                                                          'health of the technique administration YAML file.')
    parser_visibility.add_argument('-ft', '--file-tech', help='path to the technique administration YAML file (used to '
                                                              'score the level of visibility)', required=True)
    parser_visibility.add_argument('-fd', '--file-ds', help='path to the data source administration YAML file (used to '
                                                            'add metadata on the involved data sources)')
    parser_visibility.add_argument('-a', '--applicable', help='filter techniques based on the \'applicable_to\' field '
                                                              'in the technique administration YAML file. '
                                                              'Not supported for Excel output', default='all')
    parser_visibility.add_argument('-l', '--layer', help='generate a visibility layer for the ATT&CK navigator',
                                   action='store_true')
    parser_visibility.add_argument('-e', '--excel', help='generate an Excel sheet with all administrated techniques',
                                     action='store_true')
    parser_visibility.add_argument('-o', '--overlay', help='generate a visibility layer overlaid with detections for '
                                                           'the ATT&CK navigator', action='store_true')
    parser_visibility.add_argument('--health', help='check the technique YAML file for errors', action='store_true')

    # create the detection parser
    parser_detection = subparsers.add_parser('detection', aliases=['d'],
                                             help='detection coverage mapping based on techniques',
                                             description='Create a heat map based on detection scores, overlay '
                                                         'detections with visibility, generate a detection '
                                                         'improvement graph, output to Excel or check the health of '
                                                         'the technique administration YAML file.')
    parser_detection.add_argument('-ft', '--file-tech', help='path to the technique administration YAML file (used to '
                                                             'score the level of visibility)', required=True)
    parser_detection.add_argument('-fd', '--file-ds', help='path to the data source administration YAML file (used in '
                                                           'the overlay with visibility to add metadata on the '
                                                           'involved data sources)')
    parser_detection.add_argument('-a', '--applicable', help='filter techniques based on the \'applicable_to\' field '
                                                             'in the technique administration YAML file. '
                                                             'Not supported for Excel output', default='all')
    parser_detection.add_argument('-l', '--layer', help='generate detection layer for the ATT&CK navigator',
                                  action='store_true')
    parser_detection.add_argument('-e', '--excel', help='generate an Excel sheet with all administrated techniques',
                                   action='store_true')
    parser_detection.add_argument('-o', '--overlay', help='generate a detection layer overlaid with visibility for '
                                                          'the ATT&CK navigator', action='store_true')
    parser_detection.add_argument('-g', '--graph', help='generate a graph with detections added through time',
                                  action='store_true')
    parser_detection.add_argument('--health', help='check the technique YAML file for errors', action='store_true')

    # create the group parser
    parser_group = subparsers.add_parser('group', aliases=['g'],
                                         description='Create threat actor group heat maps, compare group(s) and '
                                                     'compare group(s) with visibility and detection coverage.',
                                         help='threat actor group mapping')
    parser_group.add_argument('-g', '--groups', help='specify the groups to include separated using commas. '
                                                     'Group can be their ID, name or alias (default is all groups). '
                                                     'Other option is to provide a YAML file with a custom group(s) '
                                                     '(default = all)',
                              default='all')
    parser_group.add_argument('-o', '--overlay', help='specify what to overlay on the group(s) (provided using the '
                                                      'arguments \'-g/--groups\'): group(s), visibility or detection. '
                                                      'When overlaying a GROUP: the group can be their ID, name or '
                                                      'alias separated using commas. Or provide a file path of a YAML '
                                                      'file with a custom group(s). When overlaying DETECTION or '
                                                      'VISIBILITY provide a YAML with the technique administration.')
    parser_group.add_argument('-t', '--overlay-type', help='specify the type of overlay (default = group)',
                              choices=['group', 'visibility', 'detection'], default='group')
    parser_group.add_argument('-a', '--applicable', help='filter techniques in the detection or visibility overlay ' 
                                                         'based on the \'applicable_to\' field in the technique '
                                                         'administration YAML file. ', default='all')
    parser_group.add_argument('--software-group', help='add techniques to the heat map by checking which software is '
                                                       'used by group(s), and hence which techniques the software '
                                                       'supports (does not influence the scores). If overlay group(s) '
                                                       'are provided, only software related to those group(s) are '
                                                       'included', action='store_true', default=False)
    parser_group.add_argument('-p', '--platform', help='specify the platform (default = Windows)',
                              choices=['all', 'Linux', 'macOS', 'Windows'], default='Windows')
    parser_group.add_argument('-s', '--stage', help='specify the stage (default = attack)',
                              choices=['attack', 'pre-attack'], default='attack')

    # create the generic parser
    parser_generic = subparsers.add_parser('generic', description='Generic functions which will output to stdout.',
                                           help='includes: statistics on ATT&CK data source and updates on techniques'
                                                ', groups and software', aliases=['ge'])

    parser_generic.add_argument('-s', '--statistics', help='get a sorted count on how much techniques are covered by a '
                                                           'particular data source', action='store_true')

    parser_generic.add_argument('-u', '--updates', help='get a sorted list for when updates were released for '
                                                        'techniques, groups or software',
                                choices=['techniques', 'groups', 'software'])
    parser_generic.add_argument('--sort', help='sorting of the output from \'-u/--update\' on modified or creation '
                                               'date (default = modified)', choices=['modified', 'created'],
                                default='modified')

    return menu_parser


def menu(menu_parser):
    """
    Parser for the command line parameter menu and calls the appropriate functions.
    :param menu_parser: the argparse menu as created with 'init_menu()'
    :return:
    """
    args = menu_parser.parse_args()

    if args.interactive:
        interactive_menu()

    elif args.subparser in ['datasource', 'ds']:
        if check_file(args.file, FILE_TYPE_DATA_SOURCE_ADMINISTRATION):
            if args.layer:
                generate_data_sources_layer(args.file)
            if args.excel:
                export_data_source_list_to_excel(args.file)
            if args.graph:
                plot_data_sources_graph(args.file)
            if args.yaml:
                generate_technique_administration_file(args.file)

    elif args.subparser in ['visibility', 'v']:
        if args.layer or args.overlay:
            if not args.file_ds:
                print('[!] Generating a visibility layer or doing an overlay requires adding the data source'
                      'administration YAML file (\'--file-ds\')')
                quit()

            if check_file(args.file_tech, FILE_TYPE_TECHNIQUE_ADMINISTRATION, args.health) and \
               check_file(args.file_ds, FILE_TYPE_DATA_SOURCE_ADMINISTRATION, args.health):
                if args.layer:
                    generate_visibility_layer(args.file_tech, args.file_ds, False, args.applicable)
                if args.overlay:
                    generate_visibility_layer(args.file_tech, args.file_ds, True, args.applicable)

        if check_file(args.file_tech, FILE_TYPE_TECHNIQUE_ADMINISTRATION, args.health):
            if args.excel and args.applicable == 'all':
                export_techniques_list_to_excel(args.file_tech)
            if args.excel and args.applicable != 'all':
                print('[!] Filtering on \'applicable_to\' is not supported for Excel output')

    elif args.subparser in ['group', 'g']:
        generate_group_heat_map(args.groups, args.overlay, args.overlay_type, args.stage, args.platform, args.software_group, args.applicable)

    elif args.subparser in ['detection', 'd']:
        if args.overlay:
            if not args.file_ds:
                print('[!] Doing an overlay requires adding the data source administration YAML file (\'--file-ds\')')
                quit()
            if not check_file(args.file_ds, FILE_TYPE_DATA_SOURCE_ADMINISTRATION, args.health):
                quit()

        if check_file(args.file_tech, FILE_TYPE_TECHNIQUE_ADMINISTRATION, args.health):
            if args.layer:
                generate_detection_layer(args.file_tech, args.file_ds, False, args.applicable)
            if args.overlay and check_file(args.file_ds, FILE_TYPE_DATA_SOURCE_ADMINISTRATION, args.health):
                generate_detection_layer(args.file_tech, args.file_ds, True, args.applicable)
            if args.graph:
                plot_detection_graph(args.file_tech, args.applicable)
            if args.excel and args.applicable == 'all':
                export_techniques_list_to_excel(args.file_tech)
            if args.excel and args.applicable != 'all':
                print("[!] Filtering on 'applicable_to' is not supported for Excel output")

    elif args.subparser in ['generic', 'ge']:
        if args.statistics:
            get_statistics()
        elif args.updates:
            get_updates(args.updates, args.sort)

    else:
        menu_parser.print_help()


def prepare_folders():
    """
    Create the folders 'cache' and 'output' if they do not exist.
    :return:
    """
    if not os.path.exists('cache'):
        os.mkdir('cache')
    if not os.path.exists('output'):
        os.mkdir('output')


def signal_handler(signum, frame):
    """
    Function to handles exiting via Ctrl+C.
    :param signum:
    :param frame:
    :return:
    """
    sys.exit(0)


if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    prepare_folders()
    menu(init_menu())
