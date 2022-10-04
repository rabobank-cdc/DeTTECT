export default {
    YAML_DATASOURCES_VERSION: 1.1,
    YAML_TECHNIQUES_VERSION: 1.2,
    YAML_GROUPS_VERSION: 1.0,
    DETTECT_DOMAIN_SUPPORT: ['enterprise-attack', 'ics-attack', 'mobile-attack'],
    YAML_OBJ_NEW_DATA_SOURCES_FILE: {
        version: 1.1,
        file_type: 'data-source-administration',
        name: 'example',
        domain: 'enterprise-attack',
        systems: [{ applicable_to: 'default', platform: ['all'] }],
        data_sources: []
    },
    YAML_OBJ_DATA_SOURCES: {
        data_source_name: '',
        data_source: [
            {
                applicable_to: ['all'],
                date_registered: null,
                date_connected: null,
                products: [],
                available_for_data_analytics: false,
                comment: '',
                data_quality: {
                    device_completeness: 0,
                    data_field_completeness: 0,
                    timeliness: 0,
                    consistency: 0,
                    retention: 0
                }
            }
        ]
    },
    YAML_OBJ_NEW_GROUPS_FILE: {
        version: 1.0,
        file_type: 'group-administration',
        domain: 'enterprise-attack',
        platform: ['all'],
        groups: []
    },
    YAML_OBJ_GROUP: {
        group_name: '',
        campaign: '',
        technique_id: [],
        software_id: [],
        enabled: true
    },
    YAML_OBJ_NEW_TECHNIQUES_FILE: {
        version: 1.2,
        file_type: 'technique-administration',
        name: 'example',
        domain: 'enterprise-attack',
        platform: ['all'],
        techniques: []
    },
    YAML_OBJ_TECHNIQUE: {
        technique_id: '',
        technique_name: '',
        detection: [
            {
                applicable_to: ['all'],
                location: [],
                comment: '',
                score_logbook: [{ date: null, score: -1, comment: '' }]
            }
        ],
        visibility: [
            {
                applicable_to: ['all'],
                comment: '',
                score_logbook: [{ date: null, score: 0, comment: '', auto_generated: true }]
            }
        ]
    },
    YAML_OBJ_TECHNIQUE_DETECTION: {
        applicable_to: ['all'],
        location: [],
        comment: '',
        score_logbook: [{ date: null, score: -1, comment: '' }]
    },
    YAML_OBJ_TECHNIQUE_VISIBILITY: {
        applicable_to: ['all'],
        comment: '',
        score_logbook: [{ date: null, score: 0, comment: '', auto_generated: true }]
    },
    YAML_OBJ_SCORE_DETECTION_LOGBOOK: {
        date: null,
        score: -1,
        comment: ''
    },
    YAML_OBJ_SCORE_VISIBILITY_LOGBOOK: {
        date: null,
        score: 0,
        comment: '',
        auto_generated: false
    },
    PLATFORMS: ['all', 'PRE', 'Windows', 'macOS', 'Linux', 'Office 365', 'Azure AD', 'Google Workspace', 'SaaS', 'IaaS', 'Network', 'Containers'],
    PLATFORM_CONVERSION: {
        pre: 'PRE',
        windows: 'Windows',
        macos: 'macOS',
        linux: 'Linux',
        'office 365': 'Office 365',
        'azure ad': 'Azure AD',
        'google workspace': 'Google Workspace',
        saas: 'SaaS',
        iaas: 'IaaS',
        network: 'Network',
        containers: 'Containers'
    },
    PLATFORMS_ICS: ['all', 'Control Server', 'Data Historian', 'Device Configuration/Parameters', 'Engineering Workstation', 'Field Controller/RTU/PLC/IED', 'Human-Machine Interface', 'Input/Output Server', 'Safety Instrumented System/Protection Relay', 'None'],
    PLATFORM_CONVERSION_ICS: {'control server': 'Control Server', 'data historian': 'Data Historian', 'device configuration/parameters': 'Device Configuration/Parameters',
    'engineering workstation': 'Engineering Workstation', 'field controller/rtu/plc/ied': 'Field Controller/RTU/PLC/IED',
    'human-machine interface': 'Human-Machine Interface', 'input/output server': 'Input/Output Server',
    'safety instrumented system/protection relay': 'Safety Instrumented System/Protection Relay', 'none': 'None'},
    PLATFORMS_MOBILE: ['all', 'Android', 'iOS'],
    PLATFORM_CONVERSION_MOBILE: {'android': 'Android', 'ios': 'iOS'}
};
