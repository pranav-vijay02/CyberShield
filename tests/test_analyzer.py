import sys

import unittest

from pathlib import Path



sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import app

from analyzer import MAX_MESSAGE_LENGTH, MessageInputError, analyze_message





class AnalyzerTests(unittest.TestCase):

    def test_legitimate_message_has_low_score_and_no_indicators(self):

        result = analyze_message(

            "Hi Sam, our science club meets in room 12 at 3 pm on Thursday. See you there!"

        )

        self.assertEqual(result["score"], 0)

        self.assertEqual(result["category"], "Low risk")

        self.assertEqual(result["indicators"], [])

        self.assertTrue(result["recommendations"])



    def test_coercive_authority_message_receives_explained_elevated_score(self):

        message = (

            "The boss wanted to meet you at 9AM sharp tomorrow. Clean out your desk "

            "and meet him there and do not tell anyone of this, even your managers. "

            "This is highly confidential. If you refuse to turn up, your job and "

            "life could be at stake."

        )

        result = analyze_message(message)

        indicators = {indicator["title"]: indicator for indicator in result["indicators"]}

        self.assertEqual(result["score"], 68)

        self.assertEqual(result["category"], "High risk")

        self.assertEqual(

            {title: indicator["points"] for title, indicator in indicators.items()},

            {

                "Pressure to act quickly": 18,

                "Pressure from a claimed authority": 10,

                "Pressure to keep a request secret": 12,

                "Threats or intimidation": 28,

            },

        )

        self.assertTrue(all(indicator["explanation"] for indicator in indicators.values()))

        self.assertEqual(

            result["score"],

            min(100, sum(indicator["points"] for indicator in result["indicators"])),

        )

    def test_routine_manager_meeting_and_time_do_not_trigger_coercion_rules(self):

        result = analyze_message(

            "My manager scheduled a project check-in for 9AM sharp tomorrow."

        )

        self.assertEqual(result["score"], 0)

        self.assertEqual(result["indicators"], [])

    def test_confidential_work_message_is_not_high_risk_by_itself(self):

        result = analyze_message(

            "Our product launch plan is confidential until Friday's public announcement."

        )

        self.assertEqual(result["score"], 0)

        self.assertEqual(result["indicators"], [])



    def test_secrecy_demand_and_threat_receive_distinct_indicators(self):

        result = analyze_message(

            "Do not tell your manager about the draft, or you will be fired."

        )

        titles = [indicator["title"] for indicator in result["indicators"]]

        self.assertIn("Pressure to keep a request secret", titles)

        self.assertIn("Threats or intimidation", titles)



    def test_urgent_password_request_scores_high(self):

        result = analyze_message(

            "URGENT: Your account will be suspended today. Click now to verify your password."

        )

        self.assertGreaterEqual(result["score"], 50)

        self.assertEqual(result["category"], "High risk")

        self.assertIn(

            "Request for sign-in information",

            [indicator["title"] for indicator in result["indicators"]],

        )



    def test_explicit_password_request_is_detected_but_a_mention_is_not(self):

        request_result = analyze_message("I need your password to keep it safe.")

        self.assertEqual(request_result["score"], 32)

        self.assertIn(

            "Request for sign-in information",

            [indicator["title"] for indicator in request_result["indicators"]],

        )

        mention_result = analyze_message("I changed my password yesterday.")

        self.assertEqual(mention_result["score"], 0)

        self.assertEqual(mention_result["indicators"], [])


    def test_sensitive_information_request_is_detected(self):

        result = analyze_message(

            "Please reply with your bank account details and credit card number to claim your refund."

        )

        self.assertIn(

            "Request for sensitive personal or financial information",

            [indicator["title"] for indicator in result["indicators"]],

        )



    def test_http_ip_and_shortened_url_are_never_visited(self):

        result = analyze_message(

            "Pay immediately at http://192.0.2.1/login or use https://bit.ly/abc."

        )

        self.assertGreater(result["score"], 0)

        self.assertIn(

            "Suspicious link characteristics",

            [indicator["title"] for indicator in result["indicators"]],

        )

        self.assertLessEqual(result["score"], 100)



    def test_normal_https_whatsapp_url_is_not_flagged(self):

        result = analyze_message(

            "click on this link to have fun https://web.whatsapp.com/"

        )

        self.assertEqual(result["score"], 0)

        self.assertEqual(result["indicators"], [])



    def test_unicode_lookalike_hostname_gets_cautious_idn_warning(self):

        result = analyze_message("See https://раypal.example/")

        self.assertEqual(result["score"], 22)

        self.assertEqual(len(result["indicators"]), 1)

        indicator = result["indicators"][0]

        self.assertEqual(indicator["title"], "Suspicious link characteristics")

        self.assertIn("can disguise look-alike characters", indicator["explanation"])

        self.assertNotIn("definitely malicious", indicator["explanation"].lower())

    def test_punycode_hostname_gets_cautious_idn_warning(self):

        result = analyze_message("See https://xn--ypal-43d9g.example/")

        self.assertEqual(result["score"], 22)

        self.assertEqual(len(result["indicators"]), 1)

        indicator = result["indicators"][0]

        self.assertEqual(indicator["title"], "Suspicious link characteristics")

        self.assertIn("can disguise look-alike characters", indicator["explanation"])

        self.assertNotIn("definitely malicious", indicator["explanation"].lower())

    def test_ordinary_ascii_hostname_is_not_flagged_as_idn(self):

        result = analyze_message("See https://paypal.example/")

        self.assertEqual(result["score"], 0)

        self.assertEqual(result["indicators"], [])

    def test_immediately_requires_urgent_action_context(self):

        announcement = analyze_message("students go to the ground immediately.")

        self.assertEqual(announcement["score"], 0)

        self.assertEqual(announcement["indicators"], [])

        urgent_request = analyze_message("Please respond immediately.")

        self.assertEqual(urgent_request["score"], 18)

        self.assertEqual(

            [indicator["title"] for indicator in urgent_request["indicators"]],

            ["Pressure to act quickly"],

        )



    def test_malformed_link_is_flagged(self):

        result = analyze_message("Open http://[::1 and sign in.")

        self.assertIn(

            "Unusual link format",

            [indicator["title"] for indicator in result["indicators"]],

        )



    def test_empty_and_oversized_input_are_rejected(self):

        with self.assertRaises(MessageInputError):

            analyze_message("  \n ")

        with self.assertRaises(MessageInputError):

            analyze_message("x" * (MAX_MESSAGE_LENGTH + 1))



    def test_score_is_bounded_and_points_are_explainable(self):

        result = analyze_message(

            "URGENT final notice: account suspended, verify password, "

            "send your bank account and credit card number, pay by gift card at "

            "http://192.0.2.44 now"

        )

        self.assertLessEqual(result["score"], 100)

        self.assertGreaterEqual(result["score"], 0)

        self.assertEqual(

            result["score"],

            min(100, sum(indicator["points"] for indicator in result["indicators"])),

        )





class FlaskRouteTests(unittest.TestCase):

    def setUp(self):

        app.config["TESTING"] = True

        self.client = app.test_client()



    def test_analyze_route_returns_expected_shape(self):

        response = self.client.post(

            "/analyze",

            json={"message": "URGENT: click now to verify your password."},

        )

        self.assertEqual(response.status_code, 200)

        data = response.get_json()

        self.assertTrue({"score", "category", "indicators", "recommendations"} <= data.keys())



    def test_route_rejects_empty_malformed_and_non_json_input(self):

        self.assertEqual(

            self.client.post("/analyze", json={"message": ""}).status_code, 400

        )

        self.assertEqual(

            self.client.post("/analyze", data="{", content_type="application/json").status_code,

            400,

        )

        self.assertEqual(

            self.client.post("/analyze", data="message=hello").status_code, 415

        )



    def test_route_rejects_missing_message_field(self):

        response = self.client.post("/analyze", json={})

        self.assertEqual(response.status_code, 400)

        self.assertEqual(

            response.get_json(), {"error": "Message must be plain text."}

        )

    def test_route_rejects_numeric_message(self):

        response = self.client.post("/analyze", json={"message": 123})

        self.assertEqual(response.status_code, 400)

        self.assertEqual(

            response.get_json(), {"error": "Message must be plain text."}

        )

    def test_route_rejects_null_message(self):

        response = self.client.post("/analyze", json={"message": None})

        self.assertEqual(response.status_code, 400)

        self.assertEqual(

            response.get_json(), {"error": "Message must be plain text."}

        )

    def test_route_rejects_empty_string_message(self):

        response = self.client.post("/analyze", json={"message": ""})

        self.assertEqual(response.status_code, 400)

        self.assertEqual(response.get_json(), {"error": "Paste a message to analyze."})





    def test_route_rejects_oversized_input(self):

        response = self.client.post(

            "/analyze",

            json={"message": "x" * (MAX_MESSAGE_LENGTH + 1)},

        )

        self.assertEqual(response.status_code, 400)



    def test_user_text_is_not_stored_or_rendered_as_html(self):

        response = self.client.post(

            "/analyze", json={"message": "<script>alert(1)</script>"}

        )

        self.assertEqual(response.status_code, 200)

        self.assertNotIn(b"<script>", response.data)





if __name__ == "__main__":

    unittest.main()
