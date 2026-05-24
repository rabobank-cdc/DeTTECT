import unittest
from pathlib import Path


class NotificationRenderingTest(unittest.TestCase):
    def test_notification_messages_are_not_rendered_as_html(self):
        notification = Path('editor/src/components/NotificationPlugin/Notification.vue').read_text()

        self.assertNotIn('v-html="message"', notification)
        self.assertIn('{{ message }}', notification)


if __name__ == '__main__':
    unittest.main()
