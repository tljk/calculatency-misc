#!/usr/bin/env python3

import unittest
import datetime as dt
import scheduler as s


class TestUtilityFunctions(unittest.TestCase):
    def test_ready_for_measurement(self):
        self.assertEqual(s.ready_for_measurement(dt.time(hour=0)), True)
        self.assertEqual(s.ready_for_measurement(dt.time(second=59)), True)
        self.assertEqual(
            s.ready_for_measurement(dt.time(hour=20, minute=59, second=5)), True
        )
        self.assertEqual(s.ready_for_measurement(dt.time(hour=21, second=20)), True)

        self.assertEqual(s.ready_for_measurement(dt.time(minute=1)), False)
        self.assertEqual(s.ready_for_measurement(dt.time(hour=1)), False)
        self.assertEqual(s.ready_for_measurement(dt.time(hour=20, minute=58)), False)


if __name__ == "__main__":
    unittest.main()
