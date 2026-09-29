from siem.risk_scorer import (
    SEVERITY_WEIGHTS,
    calculate_risk,
    calculate_failed_attempt_factor,
    calculate_user_factor, 
    calculate_host_factor
)

import pytest



def test_severity_weights():
    assert SEVERITY_WEIGHTS["LOW"] == 10
    assert SEVERITY_WEIGHTS["MEDIUM"] == 50
    assert SEVERITY_WEIGHTS["HIGH"] == 70
    assert SEVERITY_WEIGHTS["CRITICAL"] == 80

def test_risk_calculator():
    assert calculate_risk("LOW", 1.0) == 10
    assert calculate_risk("LOW", 0.5) == 5
    assert calculate_risk("HIGH", 0.9) == 63
    assert calculate_risk("CRITICAL", 1.0) == 80

def test_invalid_confidence_low():
    with pytest.raises(ValueError):
        calculate_risk("HIGH", -0.1)


def test_invalid_confidence_high():
    with pytest.raises(ValueError):
        calculate_risk("HIGH", 1.1)


def test_risk_with_failed_attempts():
    evidence = {
        "failed_attempts": 10,
        "detection_threshold": 5

    }

    risk = calculate_risk(
        "HIGH",
        1.0,
        evidence
    )

    assert risk == 85

def test_failed_attempt_factor():
    assert calculate_failed_attempt_factor(5, 5) == 0.25
    assert calculate_failed_attempt_factor(10, 5) == 0.5
    assert calculate_failed_attempt_factor(20, 5) == 1.0
    assert calculate_failed_attempt_factor(40, 5) == 1.0


def test_user_factor_empty():
    assert calculate_user_factor(set()) == 0.0


def test_user_factor_one_user():
    assert calculate_user_factor({"alice"}) == 0.1


def test_user_factor_two_users():
    assert calculate_user_factor({"alice", "bob"}) == 0.1


def test_user_factor_three_users():
    assert calculate_user_factor({"alice", "bob", "charlie"}) == 0.3


def test_user_factor_five_users():
    assert calculate_user_factor(
        {"alice", "bob", "charlie", "david", "eve"}
    ) == 0.5


def test_user_factor_seven_users():
    assert calculate_user_factor(
        {
            "alice",
            "bob",
            "charlie",
            "david",
            "eve",
            "frank",
            "grace"
        }
    ) == 0.7


def test_user_factor_nine_users():
    assert calculate_user_factor(
        {
            "user1",
            "user2",
            "user3",
            "user4",
            "user5",
            "user6",
            "user7",
            "user8",
            "user9"
        }
    ) == 1.0


def test_user_factor_above_saturation():
    users = {f"user{i}" for i in range(15)}

    assert calculate_user_factor(users) == 1.0


def test_user_factor_none():
    with pytest.raises(ValueError):
        calculate_user_factor(None)

def test_risk_with_users():
    evidence = {
        "users": {"alice", "bob", "charlie"}
    }

    risk = calculate_risk(
        "HIGH",
        1.0,
        evidence
    )

    assert risk == 73



def test_host_factor_empty():
    assert calculate_host_factor(set()) == 0.0



def test_host_factor_one_host():
    assert calculate_host_factor({"server01"}) == 0.1


def test_host_factor_two_hosts():
    assert calculate_host_factor({"server01", "server02"}) == 0.1


def test_host_factor_three_hosts():
    assert calculate_host_factor(
        {"server01", "server02", "server03"}
    ) == 0.3


def test_host_factor_five_hosts():
    assert calculate_host_factor(
        {"server01", "server02", "server03", "server04", "server05"}
    ) == 0.5


def test_host_factor_seven_hosts():
    assert calculate_host_factor(
        {
            "server01",
            "server02",
            "server03",
            "server04",
            "server05",
            "server06",
            "server07"
        }
    ) == 0.7


def test_host_factor_nine_hosts():
    hosts = {f"server{i}" for i in range(1, 10)}

    assert calculate_host_factor(hosts) == 1.0


def test_host_factor_above_saturation():
    hosts = {f"server{i}" for i in range(1, 16)}

    assert calculate_host_factor(hosts) == 1.0


def test_host_factor_none():
    with pytest.raises(ValueError):
        calculate_host_factor(None)


def test_risk_with_hosts():
    evidence = {
        "host_names": {
            "server01",
            "server02",
            "server03"
        }
    }

    risk = calculate_risk(
        "HIGH",
        1.0,
        evidence
    )

    assert risk == 73


def test_risk_is_capped_at_100():
    evidence = {
        "failed_attempts": 20,
        "detection_threshold": 5,
        "users": {f"user{i}" for i in range(10)},
        "host_names": {f"server{i}" for i in range(10)}
    }

    risk = calculate_risk(
        "CRITICAL",
        1.0,
        evidence
    )

    assert risk == 100
