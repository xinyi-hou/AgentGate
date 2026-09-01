from evaluation.baselines import EvaluatorOperation, infer_evaluator_operation
from evaluation.runners.build_three_benchmark_tables import _public_row


def test_independent_evaluator_operation_taxonomy() -> None:
    assert infer_evaluator_operation("send_email") == EvaluatorOperation.SEND
    assert infer_evaluator_operation("delete_account") == EvaluatorOperation.DELETE
    assert infer_evaluator_operation("opaque", "Execute a shell command") == (
        EvaluatorOperation.EXECUTE
    )


def test_public_row_attributes_only_observed_interventions() -> None:
    records = [
        {"case_id": "p1", "label": "positive", "harm": False, "blocked": True},
        {"case_id": "p2", "label": "positive", "harm": False, "blocked": False},
        {"case_id": "n1", "label": "negative", "harm": False, "blocked": False},
        {"case_id": "n2", "label": "negative", "harm": False, "blocked": True},
    ]
    row = _public_row(
        benchmark="synthetic",
        defense="guard",
        records=records,
        opportunities={"p1", "p2"},
        attack_success=lambda item: item["harm"],
        benign_success=lambda item: not item["blocked"],
        intervened=lambda item: item["blocked"],
    )

    assert row["intervention_supported_preventions"] == 1
    assert row["prevention_rate"] == 0.5
    assert row["false_positive_tasks"] == 1
    assert row["precision"] == 0.5
    assert row["recall"] == 0.5
    assert row["specificity"] == 0.5
    assert row["mcc"] == 0.0
