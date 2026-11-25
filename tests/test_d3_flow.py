from defi_lsa.d3_flow import (
    audit_flow_volume_by_token,
    build_balance_inputs,
    build_flow_legs,
    classify_addresses,
    classify_flow_leg,
    classify_transaction,
    normalize_actor_role,
    validate_incident_leg_ownership,
)


def test_classification_preserves_rules_and_prioritizes_exploit():
    result = classify_transaction(
        {"tx_hash": "0xEXPLOIT"},
        decoded_events=[{"event_name": "Swap"}],
        decoded_calls=[{"function_name": "flashLoan"}],
        exploit_hashes=["0xexploit"],
    )

    assert result["primary_label"] == "exploit"
    assert result["matched_rules"] == ["exploit", "flash_loan", "swap"]


def test_roles_are_address_level_and_preserve_source_role():
    assert normalize_actor_role("white-hat") == "whitehat"
    rows = classify_addresses(
        event_id="evt",
        tx_hash="0xtx",
        addresses=["0xuser", "0xattacker"],
        role_by_address={"0xuser": "victim", "0xattacker": "attacker"},
        chain_id=1,
    )

    assert {row["actor_role"] for row in rows} == {"user", "attacker"}
    assert {row["source_role"] for row in rows} == {"victim", "attacker"}


def test_incident_leg_validation_detects_orphans_duplicates_and_scope():
    result = validate_incident_leg_ownership(
        ["0xone", "0xtwo"],
        [
            {"leg_id": "a", "event_id": "evt", "transaction_hash": "0xone"},
            {"leg_id": "b", "event_id": "evt", "transaction_hash": "0xone"},
            {"leg_id": "c", "event_id": "other", "transaction_hash": "0xtwo"},
        ],
        event_id="evt",
    )

    assert not result["passed"]
    assert result["multiply_owned_transactions"] == ["0xone"]
    assert result["wrong_scope_transactions"] == ["0xtwo"]


def test_balance_inputs_are_not_hourly_aggregated():
    rows = build_balance_inputs(
        [
            {
                "event_id": "evt",
                "chain_id": 1,
                "tx_hash": "0xtx",
                "block_number": 1,
                "log_index": 0,
                "token_address": "0xtoken",
                "from_address": "0xattacker",
                "to_address": "0xuser",
                "value_wei": 10,
            }
        ],
        classification_by_tx={"0xtx": {"primary_label": "withdrawal"}},
        actor_by_address={"0xuser": "user"},
        leg_by_tx={"0xtx": "leg-1"},
    )

    assert rows[0]["balance_delta"] == "10"
    assert rows[0]["incident_leg_id"] == "leg-1"
    assert "hour" not in rows[0]


def test_flow_leg_rules_prioritize_registered_drain_and_keep_evidence():
    result = classify_flow_leg(
        {
            "tx_hash": "0xdrain",
            "from_address": "0xpool",
            "to_address": "0xattacker",
        },
        decoded_events=[{"event_name": "Swap"}],
        exploit_hashes=["0xdrain"],
        core_addresses=["0xpool"],
        role_by_address={"0xattacker": "primary_exploiter"},
    )

    assert result["flow_label"] == "attacker_drain"
    assert "core_to_attacker" in result["matched_rules"]
    assert result["evidence"]["registered_exploit"]


def test_flow_leg_builder_preserves_wei_and_unknown_class():
    rows = build_flow_legs(
        [
            {
                "event_id": "evt",
                "chain_id": 1,
                "tx_hash": "0xTx",
                "block_number": 12,
                "log_index": 3,
                "token_address": "0xToken",
                "from_address": "0xA",
                "to_address": "0xB",
                "value_wei": 12345678901234567890,
            }
        ]
    )

    assert rows[0]["flow_label"] == "unknown"
    assert rows[0]["value_wei"] == "12345678901234567890"
    assert rows[0]["flow_leg_id"] == "0xtx:3:0xtoken"


def test_unknown_flow_volume_is_reported_per_token():
    result = audit_flow_volume_by_token(
        [
            {"token_address": "0xaaa", "value_wei": "100", "flow_label": "unknown"},
            {"token_address": "0xaaa", "value_wei": "900", "flow_label": "swap_mev"},
            {"token_address": "0xbbb", "value_wei": "1000000000000000000", "flow_label": "unknown"},
        ]
    )

    assert result[0]["unknown_flow_share"] == 0.1
    assert not result[0]["passed"]
    assert result[1]["unknown_flow_share"] == 1.0