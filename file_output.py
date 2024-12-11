import os
import shutil


def _clean_filename(filename):
    """
    Remove invalid characters from filename and maximize it to 200 characters
    :param filename: Input filename
    :return: sanitized filename
    """
    return filename.replace('/', '').replace('\\', '').replace(':', '')[:200]


def write_file(filename, overwrite_mode, content):
    """
    Writes content to a file and ensures if the file already exists it won't be overwritten by appending a number
    as suffix.
    :param filename: filename
    :param overwrite_mode: defines whether we want to force overwriting existing file
    :param content: the content of the file that needs to be written to the file
    :return:
    """
    output_filename = 'output/%s' % _clean_filename(filename)

    if not overwrite_mode:
        output_filename = get_non_existing_filename(output_filename, 'json')
    else:
        output_filename = use_existing_filename(output_filename, 'json')

    with open(output_filename, 'w') as f:
        f.write(content)

    print('File written:   ' + output_filename)


def backup_file(filename):
    """
    Create a backup of the provided file
    :param filename: existing YAML filename
    :return:
    """
    suffix = 1
    backup_filename = filename.replace('.yaml', '_backup_' + str(suffix) + '.yaml')
    while os.path.exists(backup_filename):
        backup_filename = backup_filename.replace('_backup_' + str(suffix) + '.yaml', '_backup_' + str(suffix + 1) + '.yaml')
        suffix += 1

    shutil.copy2(filename, backup_filename)
    print('Written backup file:   ' + backup_filename + '\n')


def create_output_filename(filename_prefix, filename):
    """
    Creates a filename using pre determined convention.
    :param filename_prefix: prefix part of the filename
    :param filename: filename
    :return:
    """
    return '%s_%s' % (filename_prefix, normalize_name_to_filename(filename))


def get_non_existing_filename(filename, extension):
    """
    Generates a filename that doesn't exist based on the given filename by appending a number as suffix.
    :param filename: input filename
    :param extension: input extension
    :return: unique filename
    """
    if filename.endswith('.' + extension):
        filename = filename.replace('.' + extension, '')
    if os.path.exists('%s.%s' % (filename, extension)):
        suffix = 1
        while os.path.exists('%s_%s.%s' % (filename, suffix, extension)):
            suffix += 1
        output_filename = '%s_%s.%s' % (filename, suffix, extension)
    else:
        output_filename = '%s.%s' % (filename, extension)
    return output_filename


def use_existing_filename(filename, extension):
    """
    Generates a filename that preserves the file extension if present.
    If no extension is present, adds the provided extension.
    :param filename: input filename
    :param extension: input extension
    :return: filename and extension, without duplicating extensions
    """
    if filename.endswith('.' + extension):
        filename = filename.replace('.' + extension, '')
    output_filename = '%s.%s' % (filename, extension)
    return output_filename


def normalize_name_to_filename(name):
    """
    Normalize the input filename to a lowercase filename and replace spaces with dashes.
    :param name: input filename
    :return: normalized filename
    """
    return name.lower().replace(' ', '-').replace('/', '-')
