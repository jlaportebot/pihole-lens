"""Tests for the queries-over-time series behind the dashboard chart."""
import sqlite3
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import server  # noqa: E402

MINUTE = 60
HOUR = 3600
DAY = 86400
NOW = 1_793_930_000
LAN_CLIENT = "192.168.1.20"
OTHER_LAN_CLIENT = "192.168.1.21"
STATUS_FORWARDED = 2
STATUS_GRAVITY_BLOCKED = 1


def make_db(rows):
    """In-memory FTL-shaped database holding (timestamp, client, status) rows."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE queries (timestamp REAL, client TEXT, "
                 "domain TEXT, status INTEGER)")
    conn.executemany(
        "INSERT INTO queries VALUES (?, ?, 'example.com', ?)", rows)
    return conn


def run_timeline(conn, window_seconds, client_ip=None):
    with mock.patch.object(server.time, "time", return_value=NOW):
        where, params = server.since_clause(window_seconds)
        return server.timeline(conn, where, params, window_seconds,
                               client_ip=client_ip)


class ChartBucketSecondsTest(unittest.TestCase):
    def test_one_hour_uses_one_minute_buckets(self):
        self.assertEqual(server.chart_bucket_seconds(HOUR), MINUTE)

    def test_one_day_uses_ten_minute_buckets(self):
        self.assertEqual(server.chart_bucket_seconds(DAY), 10 * MINUTE)

    def test_one_week_uses_two_hour_buckets(self):
        self.assertEqual(server.chart_bucket_seconds(7 * DAY), 2 * HOUR)

    def test_zero_span_uses_smallest_bucket(self):
        self.assertEqual(server.chart_bucket_seconds(0), MINUTE)

    def test_very_long_span_caps_at_one_day(self):
        self.assertEqual(server.chart_bucket_seconds(400 * DAY), DAY)


class AlignDownTest(unittest.TestCase):
    def test_aligns_to_utc_boundary_without_offset(self):
        self.assertEqual(server.align_down(DAY + 5 * HOUR, DAY, 0), DAY)

    def test_aligns_day_buckets_to_local_midnight(self):
        utc_minus_five = -5 * HOUR
        local_ten_pm = 2 * DAY + 3 * HOUR
        local_midnight = DAY + 5 * HOUR
        self.assertEqual(
            server.align_down(local_ten_pm, DAY, utc_minus_five),
            local_midnight)

    def test_is_idempotent(self):
        once = server.align_down(NOW, 10 * MINUTE, -5 * HOUR)
        self.assertEqual(server.align_down(once, 10 * MINUTE, -5 * HOUR), once)


class FillTimelineTest(unittest.TestCase):
    def test_zero_fills_empty_buckets(self):
        counts = {0: (5, 1), 2 * MINUTE: (3, 0)}
        points = server.fill_timeline(counts, MINUTE, 0, 2 * MINUTE)
        self.assertEqual(points, [
            {"ts": 0, "allowed": 4, "blocked": 1},
            {"ts": MINUTE, "allowed": 0, "blocked": 0},
            {"ts": 2 * MINUTE, "allowed": 3, "blocked": 0},
        ])

    def test_returns_nothing_when_range_is_inverted(self):
        self.assertEqual(server.fill_timeline({}, MINUTE, MINUTE, 0), [])


class TimelineTest(unittest.TestCase):
    def test_empty_database_returns_no_points(self):
        result = run_timeline(make_db([]), DAY)
        self.assertEqual(result["points"], [])

    def test_counts_every_query_once_split_by_status(self):
        conn = make_db([
            (NOW - 30 * MINUTE, LAN_CLIENT, STATUS_FORWARDED),
            (NOW - 30 * MINUTE + 0.5, LAN_CLIENT, STATUS_GRAVITY_BLOCKED),
            (NOW - 5 * MINUTE, LAN_CLIENT, STATUS_FORWARDED),
        ])
        points = run_timeline(conn, DAY)["points"]
        self.assertEqual(sum(p["allowed"] for p in points), 2)
        self.assertEqual(sum(p["blocked"] for p in points), 1)

    def test_points_are_evenly_spaced_by_bucket(self):
        conn = make_db([(NOW - 50 * MINUTE, LAN_CLIENT, STATUS_FORWARDED),
                        (NOW - MINUTE, LAN_CLIENT, STATUS_FORWARDED)])
        result = run_timeline(conn, DAY)
        gaps = {b["ts"] - a["ts"]
                for a, b in zip(result["points"], result["points"][1:])}
        self.assertEqual(gaps, {result["bucket"]})

    def test_starts_at_first_logged_query_not_window_start(self):
        first_query = NOW - 2 * HOUR
        conn = make_db([(first_query, LAN_CLIENT, STATUS_FORWARDED)])
        result = run_timeline(conn, 7 * DAY)
        start = result["points"][0]["ts"]
        self.assertLessEqual(start, first_query)
        self.assertGreater(start, first_query - result["bucket"])

    def test_reports_window_start_inside_first_bucket(self):
        conn = make_db([(NOW - 3 * DAY, LAN_CLIENT, STATUS_FORWARDED)])
        result = run_timeline(conn, HOUR)
        self.assertEqual(result["start"], NOW - HOUR)
        self.assertLessEqual(result["points"][0]["ts"], result["start"])

    def test_ends_at_the_bucket_containing_now(self):
        conn = make_db([(NOW - HOUR, LAN_CLIENT, STATUS_FORWARDED)])
        result = run_timeline(conn, DAY)
        last = result["points"][-1]["ts"]
        self.assertTrue(last <= NOW < last + result["bucket"])

    def test_ignores_queries_older_than_the_window(self):
        conn = make_db([(NOW - 3 * DAY, LAN_CLIENT, STATUS_FORWARDED),
                        (NOW - 10 * MINUTE, LAN_CLIENT, STATUS_FORWARDED)])
        result = run_timeline(conn, HOUR)
        self.assertEqual(result["bucket"], MINUTE)
        self.assertEqual(sum(p["allowed"] for p in result["points"]), 1)

    def test_all_window_spans_the_whole_log(self):
        conn = make_db([(NOW - 3 * DAY, LAN_CLIENT, STATUS_FORWARDED),
                        (NOW - 10 * MINUTE, LAN_CLIENT, STATUS_FORWARDED)])
        result = run_timeline(conn, 0)
        self.assertEqual(sum(p["allowed"] for p in result["points"]), 2)

    def test_filters_to_one_client(self):
        conn = make_db([(NOW - MINUTE, LAN_CLIENT, STATUS_FORWARDED),
                        (NOW - MINUTE, OTHER_LAN_CLIENT, STATUS_FORWARDED)])
        points = run_timeline(conn, HOUR, client_ip=LAN_CLIENT)["points"]
        self.assertEqual(sum(p["allowed"] for p in points), 1)


if __name__ == "__main__":
    unittest.main()
