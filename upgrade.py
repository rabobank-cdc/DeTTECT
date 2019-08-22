import re
import os
import shutil
from constants import *


def _get_attack_id(stix_obj):
    """
    Get the Technique, Group or Software ID from the STIX object
    :param stix_obj: STIX object (Technique, Software or Group)
    :return: ATT&CK ID
    """
    for ext_ref in stix_obj['external_references']:
        if ext_ref['source_name'] in ['mitre-attack', 'mitre-mobile-attack', 'mitre-pre-attack']:
            return ext_ref['external_id']


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
                text += FILE_TYPE_TECHNIQUE_ADMINISTRATION_UPGRADE_TEXT[version] + '\n'

        return text


def _ask_to_upgrade(filename):
    """
    Ask the user to upgrade the YAML file or not.
    :param filename: YAML administration file
    :return: boolean value indicating if the upgrade can be performed
    """
    yes_no = ''
    while not re.match('^(y|yes|n|no)$', yes_no, re.IGNORECASE):
        yes_no = input('Do you want to upgrade the below file. A backup will be created of the current file.\n'
                       '[!] Not upgrading the file will brake some functionality within DeTT&CT.\n'
                       ' - ' + filename + '\n >>   y(yes)/n(no): ')

    if re.match('^(y|yes)$', yes_no, re.IGNORECASE):
        return True
    else:
        return False


def upgrade_yaml_file(filename, file_type, file_version, attack_tech_data):
    """
    Main function to upgrade the YAML file to a new version
    :param filename: YAML administration file
    :param file_type: YAML file type
    :param file_version: version of the YAML file
    :param attack_tech_data: ATT&CK data on techniques
    :return:
    """

    is_upgraded = False
    tech_upgrade_func = {}
    tech_upgrade_func[1.1] = _upgrade_technique_yaml_10_to_11

    with open(filename, 'r') as file:
        file_new_lines = file.readlines()

    if file_type == FILE_TYPE_TECHNIQUE_ADMINISTRATION:
        if file_version != FILE_TYPE_TECHNIQUE_ADMINISTRATION_VERSION:
            upgrade_text = _create_upgrade_text(file_type, file_version)
            print(upgrade_text)
            if _ask_to_upgrade(filename):
                is_upgraded = True
                # create backup of the non-upgraded file
                backup_filename = _get_backup_filename(filename)
                shutil.copy2(filename, backup_filename)
                print('Written backup file:   ' + backup_filename)

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
        print('-'*80)


def _get_technique(techniques, technique_id):
    """
    Generic function to lookup a specific technique_id in a list of dictionaries with techniques.
    :param techniques: list with all techniques
    :param technique_id: technique_id to look for
    :return: the technique you're searching for. None if not found.
    """
    for t in techniques:
        if technique_id == _get_attack_id(t):
            return t
    return None


def _get_backup_filename(filename):
    """
    Create a filename to be used for backup of the YAML file
    :param filename: existing YAML filename
    :return: a name for the backup file
    """
    suffix = 1
    backup_filename = filename.replace('.yaml', '_backup_' + str(suffix) + '.yaml')
    while os.path.exists(backup_filename):
        backup_filename = backup_filename.replace('_backup_' + str(suffix) + '.yaml', '_backup_' + str(suffix+1) + '.yaml')
        suffix += 1

    return backup_filename


def _upgrade_technique_yaml_10_to_11(file_lines, attack_tech_data):
    """
    Upgrade the YAML technique administration file from 1.0 to 1.1.
    :param file_lines: array containing the lines within the tech. admin. file
    :param attack_tech_data: ATT&CK data on techniques
    :return: array with new lines to be written to disk
    """
    regex_version = re.compile(r'^\s*version:\s+1\.0\s*$', re.IGNORECASE)
    regex_tech = re.compile(r'^-\s+technique_id:\s+T[0-9]{4}\s*$', re.IGNORECASE)
    regex_tech_id = re.compile(r'^-\s+technique_id:\s+(T[0-9]{4})\s*$', re.IGNORECASE)
    regex_detection = re.compile(r'^\s+detection:\s*$', re.IGNORECASE)
    regex_visibility = re.compile(r'^\s+visibility:\s*$', re.IGNORECASE)

    file_new_lines = []
    x = 0
    for l in file_lines:
        if regex_version.match(l):
            file_new_lines.append(l.replace('1.0', '1.1'))
        elif regex_tech.match(l):
            file_new_lines.append(l)

            tech_id = regex_tech_id.search(l).group(1)
            tech_name = _get_technique(attack_tech_data, tech_id)['name']
            file_new_lines.append('  technique_name: ' + tech_name+'\n')
        elif regex_detection.match(l):
            file_new_lines.append(l)
            file_new_lines.append("    applicable_to: ['all']\n")
        elif regex_visibility.match(l):
            file_new_lines.append(l)
            file_new_lines.append("    applicable_to: ['all']\n")
        else:
            file_new_lines.append(l)
        x += 1

    return file_new_lines
