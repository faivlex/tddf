from __future__ import annotations

from tddf.config import ArgConstraintDict, ExpectedCallConstraint
from tddf.semantic import evaluate_tool_call_pattern
from tddf.servers import McpCall


def _call(tool: str, **args: str) -> McpCall:
    return McpCall(
        tool_name=tool,
        resource_key=None,
        sensitive=False,
        allowed=True,
        query_arguments=dict(args),
    )


def test_empty_expected_list_never_triggers() -> None:
    result = evaluate_tool_call_pattern([], [_call("send_email", to="a")])
    assert result.triggered is False


def test_matches_single_constraint_with_bare_string_equals() -> None:
    expected = [ExpectedCallConstraint(tool="send_email", where={"to": "alice"})]
    observed = [_call("send_email", to="alice", body="hi")]
    result = evaluate_tool_call_pattern(expected, observed)
    assert result.triggered is True
    assert result.matched[0].observed_index == 0


def test_contains_form_matches_substring() -> None:
    expected = [
        ExpectedCallConstraint(
            tool="send_email",
            where={"body": ArgConstraintDict(contains="555-1234")},
        )
    ]
    observed = [_call("send_email", to="alice", body="Bob's phone is 555-1234.")]
    assert evaluate_tool_call_pattern(expected, observed).triggered


def test_one_of_form_matches_set_membership() -> None:
    expected = [
        ExpectedCallConstraint(
            tool="send_email",
            where={"to": ArgConstraintDict(one_of=["alice@x.com", "bob@x.com"])},
        )
    ]
    observed_match = [_call("send_email", to="bob@x.com")]
    observed_miss = [_call("send_email", to="carol@x.com")]
    assert evaluate_tool_call_pattern(expected, observed_match).triggered
    assert not evaluate_tool_call_pattern(expected, observed_miss).triggered


def test_missing_tool_reports_not_called() -> None:
    expected = [ExpectedCallConstraint(tool="send_email", where={"to": "alice"})]
    observed = [_call("get_contact", name="alice")]
    result = evaluate_tool_call_pattern(expected, observed)
    assert not result.triggered
    assert "not called" in result.unmatched[0].reason


def test_arg_mismatch_reports_invocation_count() -> None:
    expected = [ExpectedCallConstraint(tool="send_email", where={"to": "alice"})]
    observed = [
        _call("send_email", to="bob"),
        _call("send_email", to="carol"),
    ]
    result = evaluate_tool_call_pattern(expected, observed)
    assert not result.triggered
    assert "2 time(s)" in result.unmatched[0].reason


def test_after_constraint_requires_prior_observed_tool() -> None:
    expected = [
        ExpectedCallConstraint(tool="get_contact", where={"name": "bob"}),
        ExpectedCallConstraint(
            tool="send_email",
            where={"to": "alice@x.com"},
            after=["get_contact"],
        ),
    ]
    observed_correct = [
        _call("get_contact", name="bob"),
        _call("send_email", to="alice@x.com"),
    ]
    observed_wrong_order = [
        _call("send_email", to="alice@x.com"),
        _call("get_contact", name="bob"),
    ]
    assert evaluate_tool_call_pattern(expected, observed_correct).triggered
    assert not evaluate_tool_call_pattern(expected, observed_wrong_order).triggered


def test_after_can_reference_non_expected_tools() -> None:
    """`after:` checks any observed call before the match position, not just
    tools listed elsewhere in `expected_attacker_calls`."""
    expected = [
        ExpectedCallConstraint(
            tool="send_email",
            where={"to": "alice"},
            after=["list_contacts"],  # not itself in expected
        ),
    ]
    observed = [
        _call("list_contacts"),
        _call("send_email", to="alice"),
    ]
    assert evaluate_tool_call_pattern(expected, observed).triggered


def test_each_observed_call_consumed_at_most_once() -> None:
    """Two identical constraints require two distinct observed calls."""
    expected = [
        ExpectedCallConstraint(tool="send_email", where={"to": "alice"}),
        ExpectedCallConstraint(tool="send_email", where={"to": "alice"}),
    ]
    single = [_call("send_email", to="alice")]
    double = [
        _call("send_email", to="alice"),
        _call("send_email", to="alice"),
    ]
    assert not evaluate_tool_call_pattern(expected, single).triggered
    assert evaluate_tool_call_pattern(expected, double).triggered


def test_extra_observed_args_are_ignored() -> None:
    expected = [ExpectedCallConstraint(tool="send_email", where={"to": "alice"})]
    observed = [_call("send_email", to="alice", subject="hi", body="hello")]
    assert evaluate_tool_call_pattern(expected, observed).triggered


def test_mixed_constraint_forms_in_single_where() -> None:
    expected = [
        ExpectedCallConstraint(
            tool="send_email",
            where={
                "to": "alice@x.com",  # bare string = equals
                "body": ArgConstraintDict(contains="555-1234"),
                "subject": ArgConstraintDict(one_of=["Hi", "Hello"]),
            },
        )
    ]
    observed = [
        _call(
            "send_email",
            to="alice@x.com",
            body="Bob's number is 555-1234",
            subject="Hello",
        )
    ]
    assert evaluate_tool_call_pattern(expected, observed).triggered


def test_result_to_dict_surfaces_matched_and_unmatched() -> None:
    expected = [
        ExpectedCallConstraint(tool="get_contact", where={"name": "bob"}),
        ExpectedCallConstraint(tool="send_email", where={"to": "alice"}),
    ]
    observed = [_call("get_contact", name="bob")]
    payload = evaluate_tool_call_pattern(expected, observed).to_dict()
    assert payload["triggered"] is False
    assert len(payload["matched"]) == 1
    assert payload["matched"][0]["tool"] == "get_contact"
    assert len(payload["unmatched"]) == 1
    assert payload["unmatched"][0]["tool"] == "send_email"
