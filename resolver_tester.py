"""
Module: resolve_tester

Test cases for comp375 p03: iterative DNS resolver
"""

import sys
import io
import unittest
from unittest.mock import patch

from resolver import resolve

class TestResolver(unittest.TestCase):

    def test_a_record(self):
        """
        Tests for valid A records. These should not be CNAME entries.
        """
        with self.subTest(msg="A record for TLD: .com"):
            self.assertTrue(resolve("webopedia.com") in ["141.193.213.20", "141.193.213.21"])
            self.assertEqual(resolve("pokemon.com"), "69.172.200.183")

        with self.subTest(msg="A record for TLD: .net"):
            self.assertTrue(resolve("happycow.net") in ["107.154.146.2", "45.60.96.2"])
            self.assertEqual(resolve("sdcoe.net"), "209.66.192.225")

        with self.subTest(msg="A record for TLD: .edu"):
            self.assertEqual(resolve("www.sandiego.edu"), "192.195.155.200")
            self.assertEqual(resolve("www.harvard.edu"), "23.185.0.1")

        with self.subTest(msg="A record for TLD: .org"):
            self.assertTrue(resolve("consumerreports.org") in ["65.8.158.100", "65.8.158.14", "65.8.158.67", "65.8.158.37", "99.84.203.46", "99.84.203.50", "99.84.203.93", "99.84.203.105"])
            self.assertTrue(resolve("pcta.org") in ["172.67.69.188", "104.26.15.163", "104.26.14.163"])

        with self.subTest(msg="A record for TLD: .io"):
            self.assertTrue(resolve("github.io") in [ "185.199.109.153", "185.199.111.153", "185.199.108.153", "185.199.110.153" ])
            self.assertEqual(resolve("gigatron.io"), "85.17.207.47")

        with self.subTest(msg="A record for TLD: .gov"):
            self.assertEqual(resolve("mentalhealth.gov"), "52.23.42.165")
            self.assertEqual(resolve("ca.gov"), "13.87.221.220")

        with self.subTest(msg="A record for TLD: .ca"):
            self.assertTrue(resolve("thecanadianencyclopedia.ca") in [ "15.222.77.222", "3.96.106.51" ])
            self.assertEqual(resolve("sportsnet.ca"), "23.57.52.245")



    def test_cname_record(self):
        """
        Tests for valid A records that end up being CNAME entries.
        """
        with self.subTest(msg="CNAME to same TLD: .com -> .com"):
            self.assertEqual(resolve("www.campuswire.com"), "35.241.17.106")

        with self.subTest(msg="CNAME to same TLD: .org -> .org"):
            self.assertEqual(resolve("en.wikipedia.org"), "198.35.26.96")

        with self.subTest(msg="CNAME to different TLD: .edu -> .com"):
            self.assertEqual(resolve("catalogs.sandiego.edu"), "12.2.169.179")


    def test_mx_record(self):
        with self.subTest(msg="MX record for TLD: .com"):
            self.assertTrue(resolve("google.com", True) in [ "aspmx.l.google.com", "alt2.aspmx.l.google.com", "alt3.aspmx.l.google.com", "alt4.aspmx.l.google.com", "alt1.aspmx.l.google.com" ])

        with self.subTest(msg="MX record for TLD: .edu"):
            self.assertEqual(resolve("drexel.edu", True), "drexel-edu.mail.protection.outlook.com")

        with self.subTest(msg="MX record for TLD: .org"):
            self.assertEqual(resolve("archive.org", True), "mail.archive.org")


    def test_invalid_requests(self):
        with self.subTest(msg="Bad A Request: no TLD given"):
            self.assertIsNone(resolve("floobatuba"))

        with self.subTest(msg="Bad A Request: non-existent TLD"):
            self.assertIsNone(resolve("devo.whipit"))

        with self.subTest(msg="Bad A Request: non-existent domain"):
            self.assertIsNone(resolve("asdkjfasjafby.com"))

        with self.subTest(msg="Bad A Request: non-existent subdomain"):
            self.assertIsNone(resolve("evil.sandiego.edu"))

        with self.subTest(msg="Bad MX Request: no MX record"):
            self.assertIsNone(resolve("www.sandiego.edu", True))

        with self.subTest(msg="Bad MX Request: non-existent domain"):
            self.assertIsNone(resolve("asdkjfasjafby.com", True))


if __name__ == '__main__':
    unittest.main()
