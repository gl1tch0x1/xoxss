from benchmarks.run_benchmark import summarize_results


def test_benchmark_summary_counts_confusion_matrix_and_inconclusive_cases() -> None:
    summary = summarize_results(
        [
            {"expected": "finding", "outcome": "finding", "duration_seconds": 1.0, "requests": 3},
            {"expected": "none", "outcome": "finding", "duration_seconds": 2.0, "requests": 4},
            {"expected": "finding", "outcome": "none", "duration_seconds": 1.0, "requests": 2},
            {"expected": "none", "outcome": "none", "duration_seconds": 1.0, "requests": 1},
            {"expected": "finding", "outcome": "inconclusive", "duration_seconds": 5.0},
        ]
    )

    assert (summary["tp"], summary["fp"], summary["fn"], summary["tn"]) == (1, 1, 1, 1)
    assert summary["measured_cases"] == 4
    assert summary["inconclusive_cases"] == 1
    assert summary["precision"] == 0.5
    assert summary["recall"] == 0.5
    assert summary["specificity"] == 0.5
    assert summary["false_positive_rate"] == 0.5
    assert summary["requests"] == 10
    assert summary["duration_seconds"] == 10.0
