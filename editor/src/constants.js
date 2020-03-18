export default {
    YAML_DATASOURCES_VERSION: 1.0,
    YAML_TECHNIQUES_VERSION: 1.2,
    YAML_GROUPS_VERSION: 1.0,
    YAML_OBJ_NEW_DATA_SOURCES_FILE: {
        version: 1.0,
        file_type: 'data-source-administration',
        name: 'example',
        platform: ['all'],
        data_sources: []
    },
    YAML_OBJ_DATA_SOURCES: {
        data_source_name: '',
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
    },
    YAML_OBJ_NEW_GROUPS_FILE: {
        version: 1.0,
        file_type: 'group-administration',
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
                score_logbook: [{ date: null, score: 0, comment: '', auto_generated: false }]
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
        score_logbook: [{ date: null, score: 0, comment: '', auto_generated: false }]
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
    PLATFORMS: ['all', 'Windows', 'Linux', 'macOS', 'AWS', 'GCP', 'Azure', 'Azure AD', 'Office 365', 'SaaS'],
    PLATFORM_CONVERSION: {
        windows: 'Windows',
        linux: 'Linux',
        macos: 'macOS',
        aws: 'AWS',
        gcp: 'GCP',
        azure: 'Azure',
        'azure ad': 'Azure AD',
        'office 365': 'Office 365',
        saas: 'SaaS'
    }
};
