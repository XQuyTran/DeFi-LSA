from defi_lsa.d3_flow import (
    build_balance_inputs,
    classify_addresses,
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