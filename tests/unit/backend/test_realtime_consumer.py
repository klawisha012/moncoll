import pytest
from src.realtime.consumer import _Aggregator


def test_aggregator_add_and_drain():
    agg = _Aggregator()
    
    # 1. Add invalid events
    agg.add_event({})
    agg.add_event({"geoip": {}})
    agg.add_event({"geoip": {"latitude": None, "longitude": 12.34, "country_code": "RU"}})
    
    assert len(agg.drain()) == 0
    assert agg._dropped_no_geoip == 3

    # 2. Add valid events
    event1 = {
        "geoip": {
            "latitude": 55.7558,
            "longitude": 37.6173,
            "country_code": "RU",
            "city_name": "Moscow",
        }
    }
    event2 = {
        "geoip": {
            "latitude": 55.7562,  # Close to the first, rounds to the same bucket
            "longitude": 37.6170,
            "country_code": "RU",
            "city_name": "Moscow",
        }
    }
    event3 = {
        "geoip": {
            "latitude": 37.4220,
            "longitude": -122.0841,
            "country_code": "US",
            "city_name": "Mountain View",
        }
    }

    agg.add_event(event1)
    agg.add_event(event2)
    agg.add_event(event3)

    points = agg.drain()
    assert len(points) == 2  # Moscow (aggregated) and Mountain View
    
    # Verify Moscow aggregation
    moscow = next(p for p in points if p["cc"] == "RU")
    assert moscow["delta"] == 2
    assert moscow["city"] == "Moscow"
    
    # Verify Mountain View
    mv = next(p for p in points if p["cc"] == "US")
    assert mv["delta"] == 1
    assert mv["city"] == "Mountain View"

    # 3. Drain should clear the aggregator
    assert len(agg.drain()) == 0
