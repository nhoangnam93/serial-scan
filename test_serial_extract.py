import unittest

from serial_parser import extract_serial_from_text, is_likely_dell_service_tag, is_likely_macbook_serial


class SerialExtractTests(unittest.TestCase):
    def test_extracts_from_sample_ocr_text(self):
        text = (
            "11:274 41 TOTAL SCANS 1 TODAY 1 UNIQUE 1 DUPLICATES 0 USERS ONLINE 8 "
            "Model A2338 Rated 20.3V and IC: 579C-A2338 Serial WLQ7PKOMY2 "
            "10.242.28.199:5000"
        )
        self.assertEqual(extract_serial_from_text(text), "WLQ7PK0MY2")

    def test_extracts_when_serial_is_split_into_many_tokens(self):
        text = "Serial WL Q7 PK 0M Y2"
        self.assertEqual(extract_serial_from_text(text), "WLQ7PK0MY2")

    def test_strips_leading_s_from_barcode_serial(self):
        text = "Serial SWLQ7PK0MY2"
        self.assertEqual(extract_serial_from_text(text), "WLQ7PK0MY2")

    def test_normalizes_apple_o_i_to_zero_one(self):
        text = "Serial WLO7PKOMY2"
        self.assertEqual(extract_serial_from_text(text), "WL07PK0MY2")

    def test_ignores_dashboard_noise(self):
        text = "TOTAL SCANS USERS ONLINE UNIQUE DUPLICATES AUTOSAVE TODAY"
        self.assertEqual(extract_serial_from_text(text), "")

    def test_macbook_serial_filter(self):
        self.assertTrue(is_likely_macbook_serial("JFXK6LM6P6"))
        self.assertFalse(is_likely_macbook_serial("ABCDEF"))
        self.assertFalse(is_likely_macbook_serial("JFXK6LM6P6X"))

    def test_rejects_model_number_like_candidate(self):
        text = "Model A2338 FCC ID XX Serial A2338"
        self.assertEqual(extract_serial_from_text(text), "")

    def test_rejects_random_noise_without_label_hints(self):
        text = "ZXCVB12345 asdf qwer 10.242.28.11 online users"
        self.assertEqual(extract_serial_from_text(text), "")

    def test_extracts_dell_service_tag_from_st_prefix(self):
        text = "DELL Reg Model ST:BNKGR44 EX:25369701700"
        self.assertEqual(extract_serial_from_text(text, profile="dell"), "BNKGR44")

    def test_extracts_dell_service_tag_from_service_tag_label(self):
        text = "Dell Service Tag 7J6B1D2"
        self.assertEqual(extract_serial_from_text(text, profile="dell"), "7J6B1D2")

    def test_dell_service_tag_filter(self):
        self.assertTrue(is_likely_dell_service_tag("7J6B1D2"))
        self.assertFalse(is_likely_dell_service_tag("ABCDEFG"))


if __name__ == "__main__":
    unittest.main()
