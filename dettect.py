from data_source_mapping import *
from technique_mapping import *
from group_mapping import *
from eql_yaml import *
from generic_mode import *
from editor import DeTTECTEditor
import generic
import argparse
import os
import signal
import sys
from logging import getLogger, ERROR as LOGERROR
getLogger("taxii2client").setLevel(LOGERROR)


def _init_menu():
    """
    Initialise the command line parameter menu.
    :return:
    """
    menu_parser = argparse.ArgumentParser(description='Detect Tactics, Techniques & Combat Threats',
                                          epilog='Source: https://github.com/rabobank-cdc/DeTTECT')
    menu_parser.add_argument('--version', action='version', version='%(prog)s ' + VERSION)

    # add subparsers
    subparsers = menu_parser.add_subparsers(title='MODE',
                                            description='Select the mode to use. Every mode has its own arguments and '
                                                        'help info displayed using: {editor, datasource, visibility, detection, '
                                                        'group, generic} --help', metavar='', dest='subparser')

    parser_editor = subparsers.add_parser('editor', aliases=['e'], help='DeTT&CT Editor',
                                          description='Start the DeTT&CT Editor for easy editing the YAML administration files')
    parser_editor.add_argument('-p', '--port', help='port where the webserver listens on (default is 8080)', required=False, default=8080)

    # create the data source parser
    parser_data_sources = subparsers.add_parser('datasource', help='data source mapping and quality',
                                                aliases=['ds'],
                                                description='Create a heat map based on data sources, output data '
                                                            'sources to Excel or generate a data source improvement '
                                                            'graph.')
    parser_data_sources.add_argument('-ft', '--file-tech', help='path to the technique administration YAML file '
                                                                '(used with the option \'-u, --update\' to update '
                                                                'the visibility scores)',
                                     required='-u' in sys.argv or '--update' in sys.argv)
    parser_data_sources.add_argument('-fd', '--file-ds', help='path to the data source administration YAML file',
                                     required=True)
    parser_data_sources.add_argument('-a', '--applicable-to', action='append', help='specify which data source objects '
                                     'to include by filtering on applicable to value(s) (used to define the type of '
                                     'system). You can provide multiple applicable to values with extra '
                                     '\'-a/--applicable-to\' arguments')
    parser_data_sources.add_argument('-s', '--search', help='only include data sources which match the provided EQL '
                                                            'query')
    parser_data_sources.add_argument('-l', '--layer', help='generate a data source layer for the ATT&CK navigator',
                                     action='store_true')
    parser_data_sources.add_argument('-e', '--excel', help='generate an Excel sheet with all data source',
                                     action='store_true')
    parser_data_sources.add_argument('-g', '--graph', help='generate a graph with data sources added through time',
                                     action='store_true')
    parser_data_sources.add_argument('-y', '--yaml', help='generate a technique administration YAML file with '
                                                          'visibility scores based on the number of available data '
                                                          'sources', action='store_true')
    parser_data_sources.add_argument('-ya', '--yaml-all-techniques', help='include all ATT&CK techniques in the '
                                     'generated YAML file (when the argument -y, --yaml is provided) that apply '
                                     'to the platform(s) specified in the data source YAML file', action='store_true')
    parser_data_sources.add_argument('-u', '--update', help='update the visibility scores within a technique '
                                                            'administration YAML file based on changes within any of '
                                                            'the data sources. Past visibility scores are preserved in '
                                                            'the \'score_logbook\', and manually assigned scores are '
                                                            'not updated without your approval. The updated visibility '
                                                            'scores are calculated in the same way as with the option: '
                                                            '-y, --yaml', action='store_true')
    parser_data_sources.add_argument('-of', '--output-filename', help='set the output filename')
    parser_data_sources.add_argument('--force-overwrite', help='force overwriting the output file if it already exists',
                                     action='store_true')
    parser_data_sources.add_argument('-ln', '--layer-name', help='set the name of the Navigator layer')
    parser_data_sources.add_argument('--health', help='check the YAML file(s) for errors', action='store_true')
    parser_data_sources.add_argument('--local-stix-path', help='path to a local STIX repository to use DeTT&CT offline '
                                     'or to use a specific version of STIX objects')
    parser_data_sources.add_argument('--layer-settings', help='specific settings for the Navigator layer. Supported settings: '
                                     + ', '.join(['%s=%s' % (k, '|'.join(v)) for k, v in LAYER_SETTINGS.items()]) +
                                     '. Multiple settings can be provided with extra --layer-settings'
                                     ' arguments. Example: --layer-settings showAggregateScores=True',
                                     action='append')

    # create the visibility parser
    parser_visibility = subparsers.add_parser('visibility', aliases=['v'],
                                              help='visibility coverage mapping based on techniques and data sources',
                                              description='Create a heat map based on visibility scores, overlay '
                                                          'visibility with detections, output to Excel or check the '
                                                          'health of the technique administration YAML file.')
    parser_visibility.add_argument('-ft', '--file-tech', help='path to the technique administration YAML file (used to '
                                                              'score the level of visibility)', required=True)
    parser_visibility.add_argument('-p', '--platform', action='append', help='specify the platform for the Navigator '
                                   'layer file (default = platform(s) specified in the YAML file). Multiple platforms'
                                   ' can be provided with extra \'-p/--platform\' arguments. The available platforms '
                                   ' can be listed from the generic mode: \'ge --list-platforms\'')
    parser_visibility.add_argument('-sd', '--search-detection', help='only include detection objects which match the '
                                                                     'provided EQL query')
    parser_visibility.add_argument('-sv', '--search-visibility', help='only include visibility objects which match the '
                                                                      'provided EQL query')
    parser_visibility.add_argument('--all-scores', help='include all \'score\' objects from the \'score_logbook\' in '
                                                        'the EQL search. The default behaviour is to only include the '
                                                        'most recent \'score\' objects',
                                   action='store_true', default=False)
    parser_visibility.add_argument('-l', '--layer', help='generate a visibility layer for the ATT&CK navigator',
                                   action='store_true')
    parser_visibility.add_argument('-e', '--excel', help='generate an Excel sheet with all administrated techniques',
                                   action='store_true')
    parser_visibility.add_argument('-o', '--overlay', help='generate a visibility layer overlaid with detections for '
                                                           'the ATT&CK navigator', action='store_true')
    parser_visibility.add_argument('-g', '--graph', help='generate a graph with visibility added through time',
                                   action='store_true')
    parser_visibility.add_argument('-of', '--output-filename', help='set the output filename')
    parser_visibility.add_argument('--force-overwrite', help='force overwriting the output file if it already exists',
                                     action='store_true')
    parser_visibility.add_argument('-ln', '--layer-name', help='set the name of the Navigator layer')
    parser_visibility.add_argument('-cd', '--count-detections', help='Show the number of detections instead of listing '
                                   'all detection locations in Layer metadata (when using '
                                   'an overlay with detection). Location prefix will be '
                                   'used to group detections. Location prefix can be used '
                                   'in the location field, e.g. "EDR: Rule 1".',
                                   action='store_true')
    parser_visibility.add_argument('--health', help='check the YAML file for errors', action='store_true')
    parser_visibility.add_argument('--local-stix-path', help='path to a local STIX repository to use DeTT&CT offline '
                                   'or to use a specific version of STIX objects')
    parser_visibility.add_argument('--layer-settings', help='specific settings for the Navigator layer. Supported settings: '
                                   + ', '.join(['%s=%s' % (k, '|'.join(v)) for k, v in LAYER_SETTINGS.items()]) +
                                   '. Multiple settings can be provided with extra --layer-settings'
                                   ' arguments. Example: --layer-settings showAggregateScores=True',
                                   action='append')

    # create the detection parser
    parser_detection = subparsers.add_parser('detection', aliases=['d'],
                                             help='detection coverage mapping based on techniques',
                                             description='Create a heat map based on detection scores, overlay '
                                             'detections with visibility, generate a detection '
                                             'improvement graph, output to Excel or check the health of '
                                             'the technique administration YAML file.')
    parser_detection.add_argument('-ft', '--file-tech', help='path to the technique administration YAML file (used to '
                                                             'score the level of detection)', required=True)
    parser_detection.add_argument('-p', '--platform', action='append', help='specify the platform for the Navigator '
                                  'layer file (default = platform(s) specified in the YAML file). Multiple platforms'
                                  ' can be provided with extra \'-p/--platform\' arguments. The available platforms '
                                  ' can be listed from the generic mode: \'ge --list-platforms\'')
    parser_detection.add_argument('-sd', '--search-detection', help='only include detection objects which match the '
                                                                    'provided EQL query')
    parser_detection.add_argument('-sv', '--search-visibility', help='only include visibility objects which match the '
                                                                     'provided EQL query')
    parser_detection.add_argument('--all-scores', help='include all \'score\' objects from the \'score_logbook\' in '
                                                       'the EQL search. The default behaviour is to only include the '
                                                       'most recent \'score\' objects',
                                  action='store_true', default=False)
    parser_detection.add_argument('-l', '--layer', help='generate detection layer for the ATT&CK navigator',
                                  action='store_true')
    parser_detection.add_argument('-e', '--excel', help='generate an Excel sheet with all administrated techniques',
                                  action='store_true')
    parser_detection.add_argument('-o', '--overlay', help='generate a detection layer overlaid with visibility for '
                                                          'the ATT&CK navigator', action='store_true')
    parser_detection.add_argument('-g', '--graph', help='generate a graph with detections added through time',
                                  action='store_true')
    parser_detection.add_argument('-of', '--output-filename', help='set the output filename')
    parser_detection.add_argument('--force-overwrite', help='force overwriting the output file if it already exists',
                                     action='store_true')
    parser_detection.add_argument('-ln', '--layer-name', help='set the name of the Navigator layer')
    parser_detection.add_argument('-cd', '--count-detections', help='Show the number of detections instead of listing '
                                                                    'all detection locations in Layer metadata. Location '
                                                                    'prefix will be used to group detections. Location prefix '
                                                                    'can be used in the location field, e.g. "EDR: Rule 1".',
                                  action='store_true')
    parser_detection.add_argument('--health', help='check the YAML file(s) for errors', action='store_true')
    parser_detection.add_argument('--local-stix-path', help='path to a local STIX repository to use DeTT&CT offline '
                                  'or to use a specific version of STIX objects')
    parser_detection.add_argument('--layer-settings', help='specific settings for the Navigator layer. Supported settings: '
                                  + ', '.join(['%s=%s' % (k, '|'.join(v)) for k, v in LAYER_SETTINGS.items()]) +
                                  '. Multiple settings can be provided with extra --layer-settings'
                                  ' arguments. Example: --layer-settings showAggregateScores=True',
                                  action='append')

    # create the group parser
    parser_group = subparsers.add_parser('group', aliases=['g'],
                                         description='Create threat actor group heat maps, compare group(s) and '
                                         'compare group(s) with visibility and detection coverage.',
                                         help='threat actor group mapping')
    parser_group.add_argument('-g', '--groups', help='specify the ATT&CK Groups to include. A group can be its ID, name or alias. '
                                                     'If no group is specified, all groups are used (except when a -c/--campaign '
                                                     'is specified). The -g/--groups and -c/--campaign options complement each other. '
                                                     'Multiple Groups can be provided with extra -g/--group arguments. Another '
                                                     'option is to provide a YAML file with a custom group(s)',
                              default=None, action='append')
    parser_group.add_argument('-c', '--campaigns', help='specify the ATT&CK Campaigns to include. A campaign can be its ID or name. '
                              'If no campaign is specified, all campaigns are used (except when a -g/--group '
                              'is specified). The -c/--campaign and -g/--groups options complement each other. '
                              'Multiple Campaigns can be provided with extra -c/--campaign arguments.',
                              default=None, action='append')
    parser_group.add_argument('-d', '--domain', help='specify the ATT&CK domain (default = enterprise). This argument '
                                                     'is ignored if a domain is specified in the Group YAML file.',
                              required=False, choices=['enterprise', 'ics', 'mobile'])
    parser_group.add_argument('-o', '--overlay', help='specify what to overlay: group(s), campaign(s), visibility or detection. '
                                                      'Default overlay type is Groups, to change it use -t/--overlay-type. '
                                                      'When overlaying a Group: it can be its ATT&CK ID, name or alias. '
                                                      'When overlaying a Campaign: it can be its ID or name. '
                                                      'Multiple Groups or Campaigns can be provided with extra '
                                                      '-o/--overlay arguments. Another option is to provide a '
                                                      'YAML file with a custom group(s). When overlaying VISIBILITY '
                                                      'or DETECTION provide a YAML with the technique administration. ',
                                                      action='append')
    parser_group.add_argument('-t', '--overlay-type', help='specify the type of overlay (default = group)',
                              choices=['group', 'campaign', 'visibility', 'detection'], default='group')

    software_parse_group = parser_group.add_mutually_exclusive_group()
    software_parse_group.add_argument('--software', help='add techniques to the heat map by checking which software is used by '
                                      'groups/campaigns, and hence which techniques the software '
                                      'supports (does not influence the scores). If overlay groups/campaigns '
                                      'are provided, only software related to those groups/campaigns are '
                                      'included. Cannot be used together with --include-software',
                                      action='store_true', default=False)
    software_parse_group.add_argument('--include-software', help='include techniques that software supports in the scores for '
                                      'groups/campaigns in scope. Cannot be used together with --software',
                                      action='store_true', default=False)

    parser_group.add_argument('-p', '--platform', action='append', help='specify the platform (default = all). Multiple platforms '
                              'can be provided with extra \'-p/--platform\' arguments. The available platforms '
                              ' can be listed from the generic mode: \'ge --list-platforms\'')
    parser_group.add_argument('-sd', '--search-detection', help='only include detection objects which match the '
                                                                'provided EQL query')
    parser_group.add_argument('-sv', '--search-visibility', help='only include visibility objects which match the '
                                                                 'provided EQL query')
    parser_group.add_argument('--all-scores', help='include all \'score\' objects from the \'score_logbook\' in '
                                                   'the EQL search. The default behaviour is to only include the '
                                                   'most recent \'score\' objects',
                              action='store_true', default=False)
    parser_group.add_argument('-of', '--output-filename', help='set the output filename')
    parser_group.add_argument('--force-overwrite', help='force overwriting the output file if it already exists',
                                     action='store_true')
    parser_group.add_argument('-ln', '--layer-name', help='set the name of the Navigator layer')
    parser_group.add_argument('-cd', '--count-detections', help='Show the number of detections instead of listing '
                              'all detection locations in Layer metadata (when using an overlay with detection). Location '
                              'prefix will be used to group detections. Location prefix can be used in the location field, '
                              'e.g. "EDR: Rule 1".',
                              action='store_true')
    parser_group.add_argument('--health', help='check the YAML file(s) for errors', action='store_true')
    parser_group.add_argument('--local-stix-path', help='path to a local STIX repository to use DeTT&CT offline '
                                                        'or to use a specific version of STIX objects')
    parser_group.add_argument('--layer-settings', help='specific settings for the Navigator layer. Supported settings: '
                              + ', '.join(['%s=%s' % (k, '|'.join(v)) for k, v in LAYER_SETTINGS.items()]) +
                              '. Multiple settings can be provided with extra --layer-settings'
                              ' arguments. Example: --layer-settings showAggregateScores=True',
                              action='append')

    # create the generic parser
    parser_generic = subparsers.add_parser('generic', description='Generic functions which will output to stdout.',
                                           help='includes: statistics on ATT&CK data source and updates on techniques'
                                           ', groups and software', aliases=['ge'])

    parser_generic.add_argument('-ds', '--datasources', help='get a sorted count on how many ATT&CK techniques'
                                                             'are covered by a particular data source '
                                                             '(default = enterprise data sources)',
                                choices=['enterprise', 'ics', 'mobile'], const='enterprise', nargs='?')
    parser_generic.add_argument('-p', '--platform', action='append', help='only include data sources for the provided '
                                'ATT&CK platforms in the \'-ds\' argument (default = all). Multiple platforms can be '
                                'provided with extra \'-p/--platform\' arguments. The available platforms can be listed '
                                'using \'--list-platforms\'')
    parser_generic.add_argument('-m', '--mitigations', help='get a sorted count on how many ATT&CK Enterprise or '
                                                            'Mobile techniques are covered by a Mitigation',
                                choices=['enterprise', 'ics', 'mobile'], const='enterprise', nargs='?')
    parser_generic.add_argument('--list-platforms', help='list the ATT&CK Enterprise, ICS or Mobile (default = Enterprise) '
                                'platforms that can be used with the \'-p/--platform\' argument',
                                choices=['enterprise', 'ics', 'mobile'], const='enterprise', nargs='?')
    parser_generic.add_argument('-u', '--updates', help='get a sorted list for when updates were released for '
                                                        'techniques, groups or software',
                                choices=['techniques', 'groups', 'software'])
    parser_generic.add_argument('--sort', help='sorting of the output from \'-u/--update\' on modified or creation '
                                               'date (default = modified)', choices=['modified', 'created'],
                                default='modified')
    parser_generic.add_argument('--local-stix-path', help='path to a local STIX repository to use DeTT&CT offline '
                                'or to use a specific version of STIX objects')

    return menu_parser


def _menu(menu_parser):
    """
    Parser for the command line parameter menu and calls the appropriate functions.
    :param menu_parser: the argparse menu as created with '_init_menu()'
    :return:
    """
    args = menu_parser.parse_args()

    if 'local_stix_path' in args and args.local_stix_path:
        generic.local_stix_path = args.local_stix_path

    if args.subparser in ['editor', 'e']:
        DeTTECTEditor(int(args.port)).start()

    elif args.subparser in ['datasource', 'ds']:
        if check_file(args.file_ds, FILE_TYPE_DATA_SOURCE_ADMINISTRATION, args.health):
            layer_settings = _parse_layer_settings(args.layer_settings)
            file_ds = args.file_ds

            if args.applicable_to:
                eql_search = get_eql_applicable_to_query(args.applicable_to, file_ds, FILE_TYPE_DATA_SOURCE_ADMINISTRATION)
                file_ds = data_source_search(args.file_ds, eql_search)
                if not file_ds:
                    quit()  # something went wrong in executing the search or 0 results where returned
            if args.search:
                file_ds = data_source_search(file_ds, args.search)
                if not file_ds:
                    quit()  # something went wrong in executing the search or 0 results where returned
            if args.update and check_file(args.file_tech, FILE_TYPE_TECHNIQUE_ADMINISTRATION, args.health):
                update_technique_administration_file(file_ds, args.file_tech)
            if args.layer:
                generate_data_sources_layer(file_ds, args.output_filename, args.force_overwrite, args.layer_name, layer_settings)
            if args.excel:
                export_data_source_list_to_excel(file_ds, args.output_filename, args.force_overwrite, eql_search=args.search)
            if args.graph:
                plot_data_sources_graph(file_ds, args.output_filename, args.force_overwrite)
            if args.yaml:
                generate_technique_administration_file(file_ds, args.output_filename, args.force_overwrite, all_techniques=args.yaml_all_techniques)

    elif args.subparser in ['visibility', 'v']:
        if check_file(args.file_tech, FILE_TYPE_TECHNIQUE_ADMINISTRATION, args.health):
            layer_settings = _parse_layer_settings(args.layer_settings)
            file_tech = args.file_tech

            if args.platform:
                if not check_platform(args.platform, filename=file_tech):
                    quit()
            if args.search_detection or args.search_visibility:
                file_tech = techniques_search(args.file_tech, args.search_visibility, args.search_detection,
                                              include_all_score_objs=args.all_scores)
                if not file_tech:
                    quit()  # something went wrong in executing the search or 0 results where returned
            if args.layer:
                generate_visibility_layer(file_tech, False, args.output_filename, args.force_overwrite, args.layer_name,
                                          layer_settings, args.platform, args.count_detections)
            if args.overlay:
                generate_visibility_layer(file_tech, True, args.output_filename, args.force_overwrite, args.layer_name,
                                          layer_settings, args.platform, args.count_detections)
            if args.graph:
                plot_graph(file_tech, 'visibility', args.output_filename, args.force_overwrite)
            if args.excel:
                export_techniques_list_to_excel(file_tech, args.output_filename, args.force_overwrite)

    # TODO add Group EQL search capabilities
    elif args.subparser in ['group', 'g']:
        layer_settings = _parse_layer_settings(args.layer_settings)
        generate_group_heat_map(args.groups, args.campaigns, args.overlay, args.overlay_type, args.platform,
                                args.software, args.include_software, args.search_visibility, args.search_detection, args.health,
                                args.output_filename, args.force_overwrite, args.layer_name, args.domain, layer_settings,
                                args.all_scores, args.count_detections)

    elif args.subparser in ['detection', 'd']:
        if check_file(args.file_tech, FILE_TYPE_TECHNIQUE_ADMINISTRATION, args.health):
            layer_settings = _parse_layer_settings(args.layer_settings)
            file_tech = args.file_tech

            if args.platform:
                if not check_platform(args.platform, filename=file_tech):
                    quit()
            if args.search_detection or args.search_visibility:
                file_tech = techniques_search(args.file_tech, args.search_visibility, args.search_detection,
                                              include_all_score_objs=args.all_scores)
                if not file_tech:
                    quit()  # something went wrong in executing the search or 0 results where returned
            if args.layer:
                generate_detection_layer(file_tech, False, args.output_filename, args.force_overwrite, args.layer_name,
                                         layer_settings, args.platform, args.count_detections)
            if args.overlay:
                generate_detection_layer(file_tech, True, args.output_filename, args.force_overwrite, args.layer_name,
                                         layer_settings, args.platform, args.count_detections)
            if args.graph:
                plot_graph(file_tech, 'detection', args.output_filename, args.force_overwrite)
            if args.excel:
                export_techniques_list_to_excel(file_tech, args.output_filename, args.force_overwrite)

    elif args.subparser in ['generic', 'ge']:
        if args.datasources:
            platform = args.platform
            if platform:
                if not check_platform(platform, domain=args.datasources):
                    quit()
            get_statistics_data_sources(args.datasources, platform)
        elif args.mitigations:
            get_statistics_mitigations(args.mitigations)
        elif args.updates:
            get_updates(args.updates, args.sort)
        elif args.list_platforms:
            get_platforms(args.list_platforms)

    else:
        menu_parser.print_help()


def _parse_layer_settings(args_layer_settings):
    layer_settings = {}
    if args_layer_settings is not None:
        for s in args_layer_settings:
            if '=' in s:
                key, value = s.split('=')
                if key in LAYER_SETTINGS:
                    layer_settings[key] = value
            else:
                print("[!] Layer setting '%s' is not valid, it doesn't contain a value." % s)
    return layer_settings


def _prepare_folders():
    """
    Create the folders 'cache' and 'output' if they do not exist.
    :return:
    """
    if not os.path.exists('cache'):
        os.mkdir('cache')
    if not os.path.exists('output'):
        os.mkdir('output')

# pylint: disable=unused-argument


def _signal_handler(signum, frame):
    """
    Function to handles exiting via Ctrl+C.
    :param signum:
    :param frame:
    :return:
    """
    sys.exit(0)


if __name__ == '__main__':
    signal.signal(signal.SIGINT, _signal_handler)
    _prepare_folders()
    _menu(_init_menu())
