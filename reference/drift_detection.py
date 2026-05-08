"""
Reference drift detection.

Demonstrates the monitoring control from the benchmark checklist:
  - choose the right test for the data shape
  - emit a structured drift report (machine-readable)
  - alert on drift as a *security* signal, not just a quality one

KS test for continuous features. Chi-squared for categorical. Both are scipy
one-liners; the value is in the wiring, not the math.
"""

import json
from pathlib import Path
from typing import Iterable, Union

import pandas as pd
from scipy import stats

P_VALUE_THRESHOLD = 0.05


def _is_categorical(s: pd.Series) -> bool:
    if s.dtype == "object" or str(s.dtype).startswith("category"):
        return True
    return s.nunique(dropna=True) <= 10 and pd.api.types.is_integer_dtype(s)


def _ks_test(train: pd.Series, prod: pd.Series):
    stat, p = stats.ks_2samp(train.dropna().values, prod.dropna().values)
    return float(stat), float(p), "ks"


def _chi_square(train: pd.Series, prod: pd.Series):
    train_counts = train.value_counts()
    prod_counts = prod.value_counts()
    cats = sorted(set(train_counts.index) | set(prod_counts.index))
    obs = [[train_counts.get(c, 0), prod_counts.get(c, 0)] for c in cats]
    if len(cats) < 2 or sum(sum(r) for r in obs) == 0:
        return 0.0, 1.0, "chi2_skipped"
    chi2, p, _, _ = stats.chi2_contingency(obs)
    return float(chi2), float(p), "chi2"


def detect_drift(
    train_df: pd.DataFrame,
    prod_df: pd.DataFrame,
    feature_cols: Iterable[str],
    report_path: Union[str, Path] = "drift_report.json",
):
    results = {}
    for col in feature_cols:
        if col not in prod_df.columns:
            results[col] = {"error": "missing_in_prod"}
            continue
        train_col, prod_col = train_df[col], prod_df[col]
        if _is_categorical(train_col):
            stat, p, method = _chi_square(train_col, prod_col)
        else:
            stat, p, method = _ks_test(train_col, prod_col)
        drifted = p < P_VALUE_THRESHOLD
        results[col] = {
            "method": method,
            "stat": round(stat, 4),
            "p_value": round(p, 4),
            "drifted": bool(drifted),
        }

    drifted = [k for k, v in results.items() if v.get("drifted")]
    report = {
        "n_train": len(train_df),
        "n_prod": len(prod_df),
        "summary": f"{len(drifted)}/{len(results)} features drifted",
        "drifted_features": drifted,
        "results": results,
    }
    Path(report_path).parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    return report
