import botsBattles
import unittest


class BotsBattlesTestCase(unittest.TestCase):

    def setUp(self):
        botsBattles.app.config['TESTING'] = True
        self.app = botsBattles.app.test_client()

    def tearDown(self):
        botsBattles.app.config['TESTING'] = False

if __name__ == '__main__':
    unittest.main()
