import unittest
from copy import deepcopy
from datetime import datetime
from unittest.mock import patch

from technique_mapping import (
    _map_and_colorize_techniques_for_detections,
    _map_and_colorize_techniques_for_overlaid,
)


TECHNIQUE = {
    'external_references': [{'source_name': 'mitre-attack', 'external_id': 'T1003'}],
    'kill_chain_phases': [{'kill_chain_name': 'mitre-attack', 'phase_name': 'credential-access'}],
    'data_components': [],
    'dettect_data_sources': [],
}

BASE_DETECTION = {
    'applicable_to': ['all'],
    'location': ['SIEM: Rule 1'],
    'comment': 'Technique level note',
    'score_logbook': [{
        'date': datetime(2022, 1, 7),
        'score': -1,
        'comment': 'Assessed, but no detection coverage yet',
    }],
}


class NegativeDetectionScoreCommentsLayerTest(unittest.TestCase):
    def _map_detection(self, detection):
        techniques = {'T1003': {'detection': [detection]}}
        with patch('technique_mapping.load_attack_data', return_value=[TECHNIQUE]):
            return _map_and_colorize_techniques_for_detections(
                techniques,
                'enterprise-attack',
                count_detections=False,
                layer_settings={},
            )

    def _map_overlay(self, detection):
        techniques = {'T1003': {'detection': [detection], 'visibility': []}}
        with patch('technique_mapping.load_attack_data', return_value=[TECHNIQUE]):
            return _map_and_colorize_techniques_for_overlaid(
                techniques,
                ['Windows'],
                'enterprise-attack',
                count_detections=False,
                layer_settings={},
            )

    def test_negative_detection_score_with_date_is_included_without_visual_score(self):
        mapped = self._map_detection(deepcopy(BASE_DETECTION))

        self.assertEqual(1, len(mapped))
        technique = mapped[0]
        self.assertEqual('T1003', technique['techniqueID'])
        self.assertNotIn('score', technique)
        self.assertNotIn('color', technique)
        self.assertIn(
            {'name': 'Detection comment', 'value': 'Assessed, but no detection coverage yet'},
            technique['metadata'],
        )

    def test_negative_detection_score_without_date_stays_hidden(self):
        detection = deepcopy(BASE_DETECTION)
        detection['score_logbook'][0]['date'] = None

        self.assertEqual([], self._map_detection(detection))

    def test_negative_detection_score_comment_is_included_in_overlay_metadata(self):
        mapped = self._map_overlay(deepcopy(BASE_DETECTION))

        self.assertEqual(1, len(mapped))
        metadata = mapped[0]['metadata']
        self.assertIn({'name': 'Detection score', 'value': '-1'}, metadata)
        self.assertIn(
            {'name': 'Detection score comment', 'value': 'Assessed, but no detection coverage yet'},
            metadata,
        )


if __name__ == '__main__':
    unittest.main()
