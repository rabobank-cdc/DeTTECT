APP_NAME = 'DeTT&CT'
APP_DESC = 'Detect Tactics, Techniques & Combat Threats'
VERSION = '1.1.2'

EXPIRE_TIME = 60*60*24

# MITRE ATT&CK data types for custom schema and STIX
DATA_TYPE_CUSTOM_TECH_BY_GROUP = 'mitre_techniques_used_by_group'
DATA_TYPE_CUSTOM_TECH_BY_SOFTWARE = 'mitre_techniques_used_by_software'
DATA_TYPE_CUSTOM_SOFTWARE_BY_GROUP = 'mitre_software_used_by_group'
DATA_TYPE_STIX_ALL_TECH = 'mitre_all_techniques'
DATA_TYPE_STIX_ALL_TECH_ENTERPRISE = 'mitre_all_techniques_enterprise'
DATA_TYPE_STIX_ALL_GROUPS = 'mitre_all_groups'
DATA_TYPE_STIX_ALL_SOFTWARE = 'mitre_all_software'
DATA_TYPE_STIX_ALL_RELATIONSHIPS = 'mitre_all_relationships'

# Group colors
COLOR_GROUP_OVERLAY_MATCH = '#f9a825'            # orange
COLOR_GROUP_OVERLAY_NO_MATCH = '#ffee58'         # yellow
COLOR_SOFTWARE = '#0d47a1 '                      # dark blue
COLOR_GROUP_AND_SOFTWARE = '#64b5f6 '            # light blue
COLOR_GRADIENT_MIN = '#ffcece'                   # light red
COLOR_GRADIENT_MAX = '#ff0000'                   # red
COLOR_TACTIC_ROW_BACKGRND = '#dddddd'            # light grey
COLOR_GROUP_OVERLAY_ONLY_DETECTION = '#8BC34A'   # green
COLOR_GROUP_OVERLAY_ONLY_VISIBILITY = '#1976D2'  # blue

# data source colors (purple range)
COLOR_DS_25p = '#E1BEE7'
COLOR_DS_50p = '#CE93D8'
COLOR_DS_75p = '#AB47BC'
COLOR_DS_99p = '#7B1FA2'
COLOR_DS_100p = '#4A148C'

# data source colors HAPPY (green range)
COLOR_DS_25p_HAPPY = '#DCEDC8'
COLOR_DS_50p_HAPPY = '#AED581'
COLOR_DS_75p_HAPPY = '#8BC34A'
COLOR_DS_99p_HAPPY = '#689F38'
COLOR_DS_100p_HAPPY = '#33691E'

# Detection colors (green range)
COLOR_D_0 = '#64B5F6'  # Blue: Forensics/Context
COLOR_D_1 = '#DCEDC8'
COLOR_D_2 = '#AED581'
COLOR_D_3 = '#8BC34A'
COLOR_D_4 = '#689F38'
COLOR_D_5 = '#33691E'

# Visibility colors (blue range)
COLOR_V_1 = '#BBDEFB'
COLOR_V_2 = '#64B5F6'
COLOR_V_3 = '#1976D2'
COLOR_V_4 = '#0D47A1'

# Detection and visibility overlay color:
COLOR_OVERLAY_VISIBILITY = COLOR_V_3
COLOR_OVERLAY_DETECTION = COLOR_D_3
COLOR_OVERLAY_BOTH = COLOR_GROUP_OVERLAY_MATCH

# Overlay types as used within the group functionality
OVERLAY_TYPE_GROUP = 'group'
OVERLAY_TYPE_VISIBILITY = 'visibility'
OVERLAY_TYPE_DETECTION = 'detection'

FILE_TYPE_DATA_SOURCE_ADMINISTRATION = 'data-source-administration'
FILE_TYPE_TECHNIQUE_ADMINISTRATION = 'technique-administration'
FILE_TYPE_GROUP_ADMINISTRATION = 'group-administration'

# YAML administration file versions
FILE_TYPE_DATA_SOURCE_ADMINISTRATION_VERSION = 1.0
FILE_TYPE_TECHNIQUE_ADMINISTRATION_VERSION = 1.1
FILE_TYPE_GROUP_ADMINISTRATION_VERSION = 1.0

# YAML file upgrade text
FILE_TYPE_TECHNIQUE_ADMINISTRATION_UPGRADE_TEXT = {1.1: " - Adding new key 'technique_name' containing the ATT&CK technique name.\n"
                                                        " - Adding new key 'applicable_to' for both detection and visibility. Default value is ['all']."}
# Interactive menu
MENU_NAME_DATA_SOURCE_MAPPING = 'Data source mapping'
MENU_NAME_VISIBILITY_MAPPING = 'Visibility coverage mapping'
MENU_NAME_DETECTION_COVERAGE_MAPPING = 'Detection coverage mapping'
MENU_NAME_THREAT_ACTOR_GROUP_MAPPING = 'Threat actor group mapping'
