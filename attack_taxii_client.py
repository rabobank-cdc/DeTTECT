from stix2 import TAXIICollectionSource, Filter, CompositeDataSource
from stix2 import MemorySource
from stix2.datastore.filters import apply_common_filters
from stix2.utils import get_type_from_id
from taxii2client.v21 import Collection
import os

class attack_client():
    '''
    Client to connect to the MITRE ATT&CK STIX2.1 data via either the TAXII server at attack-taxii.mitre.org or via the
    STIX objects hosted in the GitHub repository (for offline usage): https://github.com/mitre-attack/attack-stix-data
    
    More information on the use of the TAXII server and the STIX2.1 objects:
    https://medium.com/mitre-attack/introducing-taxii-2-1-and-a-fond-farewell-to-taxii-2-0-d9fca6ce4c58
    '''
    
    ENTERPRISE_COLLECTION_ID = 'x-mitre-collection--1f5f1533-f617-4ca8-9ab4-6a02367fa019'
    MOBILE_COLLECTION_ID = 'x-mitre-collection--dac0d2d7-8653-445c-9bff-82f934c1e858'
    ICS_COLLECTION_ID = 'x-mitre-collection--90c00720-636b-4485-b342-8751d232bf09'
    
    enterprise_source = None
    mobile_source = None
    ics_source = None
    composite_source = None
    
    def __init__(self, local_path=None, verify=True):
        if local_path is not None:
            enterprise_local_path = os.path.join(local_path, 'enterprise-attack/enterprise-attack.json')
            mobile_local_path = os.path.join(local_path, 'mobile-attack/mobile-attack.json')
            ics_local_path = os.path.join(local_path, 'ics-attack/ics-attack.json')
            if os.path.exists(enterprise_local_path) and os.path.exists(mobile_local_path) and os.path.exists(ics_local_path):
                if not os.path.exists(os.path.join(local_path, 'index.json')):
                    raise ValueError('It seems you\'re using the old CTI repository, please use the new STIX2.1 repository: https://github.com/mitre-attack/attack-stix-data')
                else:
                    self.enterprise_source = MemorySource(version='2.1')
                    self.enterprise_source.load_from_file(enterprise_local_path)
                    self.mobile_source = MemorySource(version='2.1')
                    self.mobile_source.load_from_file(mobile_local_path)
                    self.ics_source = MemorySource(version='2.1')
                    self.ics_source.load_from_file(ics_local_path)
            else:
                raise ValueError('Invalid local_path.')
        else:
            self.enterprise_source = TAXIICollectionSource(Collection(f'https://attack-taxii.mitre.org/api/v21/collections/{self.ENTERPRISE_COLLECTION_ID}', verify=verify))
            self.mobile_source = TAXIICollectionSource(Collection(f'https://attack-taxii.mitre.org/api/v21/collections/{self.MOBILE_COLLECTION_ID}', verify=verify))
            self.ics_source = TAXIICollectionSource(Collection(f'https://attack-taxii.mitre.org/api/v21/collections/{self.ICS_COLLECTION_ID}', verify=verify))

        self.composite_source = CompositeDataSource()
        self.composite_source.add_data_sources([self.enterprise_source, self.mobile_source, self.ics_source])
    
    def get_techniques(self):
        techniques = self.composite_source.query([Filter('type', '=', 'attack-pattern')])
        techniques = self.remove_revoked_deprecated(techniques)
        return techniques

    def get_enterprise_techniques(self):
        enterprise_techniques = self.enterprise_source.query([Filter('type', '=', 'attack-pattern')])
        enterprise_techniques = self.remove_revoked_deprecated(enterprise_techniques)
        return enterprise_techniques
    
    def get_mobile_techniques(self):
        mobile_techniques = self.mobile_source.query([Filter('type', '=', 'attack-pattern')])
        mobile_techniques = self.remove_revoked_deprecated(mobile_techniques)
        return mobile_techniques
    
    def get_ics_techniques(self):
        ics_techniques = self.ics_source.query([Filter('type', '=', 'attack-pattern')])
        ics_techniques = self.remove_revoked_deprecated(ics_techniques)
        return ics_techniques

    def get_relationships(self, relationship_type):
        if relationship_type is None:
            relationships = self.composite_source.query([Filter('type', '=', 'relationship')])
        else:
            relationships = self.composite_source.query([Filter('type', '=', 'relationship'),
                                                         Filter('relationship_type', '=', relationship_type)])
        
        relationships = self.remove_revoked_deprecated(relationships)

        return relationships
    
    # https://github.com/mitre/cti/blob/master/USAGE.md#removing-revoked-and-deprecated-objects
    def remove_revoked_deprecated(self, stix_objects):
        """Remove any revoked or deprecated objects from queries made to the data source"""
        # Note we use .get() because the property may not be present in the JSON data. The default is False
        # if the property is not set.
        return list(
            filter(
                lambda x: x.get("x_mitre_deprecated", False) is False and x.get("revoked", False) is False,
                stix_objects
            )
        )

    def get_campaigns(self):
        campaigns = self.composite_source.query([Filter('type', '=', 'campaign')])
        campaigns = self.remove_revoked_deprecated(campaigns)
        return campaigns

    def get_software(self):
        malware = self.composite_source.query([Filter('type', '=', 'malware')])
        tools = self.composite_source.query([Filter('type', '=', 'tool')])
        malware_tools = self.remove_revoked_deprecated(malware+tools)
        return malware_tools

    def get_enterprise_mitigations(self):
        enterprise_mitigations = self.enterprise_source.query([Filter('type', '=', 'course-of-action')])
        enterprise_mitigations = self.remove_revoked_deprecated(enterprise_mitigations)
        return enterprise_mitigations

    def get_mobile_mitigations(self):
        mobile_mitigations = self.mobile_source.query([Filter('type', '=', 'course-of-action')])
        mobile_mitigations = self.remove_revoked_deprecated(mobile_mitigations)
        return mobile_mitigations

    def get_ics_mitigations(self):
        ics_mitigations = self.ics_source.query([Filter('type', '=', 'course-of-action')])
        ics_mitigations = self.remove_revoked_deprecated(ics_mitigations)
        return ics_mitigations

    def get_groups(self):
        groups_enterprise = self.enterprise_source.query(Filter("type", "=", "intrusion-set"))
        groups_mobile = self.mobile_source.query(Filter("type", "=", "intrusion-set"))
        groups_ics = self.ics_source.query(Filter("type", "=", "intrusion-set"))
        
        # Fix the x_mitre_domains field for ICS and Mobile. This information is not properly delivered.
        for g in groups_ics:
            g['x_mitre_domains'].clear()
            g['x_mitre_domains'].append('ics-attack')

        for g in groups_mobile:
            g['x_mitre_domains'].clear()
            g['x_mitre_domains'].append('mobile-attack')

        all_groups = self.remove_revoked_deprecated(groups_enterprise + groups_mobile + groups_ics)
        return all_groups
    
    def get_enterprise_data_sources(self):
        data_sources = self.enterprise_source.query(Filter("type", "=", "x-mitre-data-source"))
        data_sources = self.remove_revoked_deprecated(data_sources)
        return data_sources

    def get_mobile_data_sources(self):
        data_sources = self.mobile_source.query(Filter("type", "=", "x-mitre-data-source"))
        data_sources = self.remove_revoked_deprecated(data_sources)
        return data_sources

    def get_ics_data_sources(self):
        data_sources = self.ics_source.query(Filter("type", "=", "x-mitre-data-source"))
        data_sources = self.remove_revoked_deprecated(data_sources)
        return data_sources
    
    def get_data_sources(self):
        data_sources = self.composite_source.query(Filter("type", "=", "x-mitre-data-source"))
        data_sources = self.remove_revoked_deprecated(data_sources)
        return data_sources

    def get_enterprise_data_components(self):
        data_components = self.enterprise_source.query(Filter("type", "=", "x-mitre-data-component"))
        data_components = self.remove_revoked_deprecated(data_components)
        return data_components

    def get_mobile_data_components(self):
        data_components = self.mobile_source.query(Filter("type", "=", "x-mitre-data-component"))
        data_components = self.remove_revoked_deprecated(data_components)
        return data_components

    def get_ics_data_components(self):
        data_components = self.ics_source.query(Filter("type", "=", "x-mitre-data-component"))
        data_components = self.remove_revoked_deprecated(data_components)
        return data_components

    def get_data_components(self):
        data_components = self.composite_source.query(Filter("type", "=", "x-mitre-data-component"))
        data_components = self.remove_revoked_deprecated(data_components)
        return data_components

    def get_enterprise_tactics(self):
        enterprise_tactics = self.enterprise_source.query(Filter("type", "=", "x-mitre-tactic"))
        enterprise_tactics = self.remove_revoked_deprecated(enterprise_tactics)
        return enterprise_tactics