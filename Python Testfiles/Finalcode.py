import numpy as np
from scipy import special
import pandas as pd
import math

# === Base dataset from your table ===
rows = [
    {"Cryptosystem":"RSA-1024", "LogicalQ":742, "PredictedYear":2032, "YearsUntilBuilt":7,  "SafeYears":10, "YearsToMigrate":2},
    {"Cryptosystem":"RSA-2048", "LogicalQ":1399, "PredictedYear":2033, "YearsUntilBuilt":8,  "SafeYears":10, "YearsToMigrate":8},
    {"Cryptosystem":"RSA-3072", "LogicalQ":2043, "PredictedYear":2033, "YearsUntilBuilt":8,  "SafeYears":10, "YearsToMigrate":8},
    {"Cryptosystem":"RSA-4096", "LogicalQ":2692, "PredictedYear":2034, "YearsUntilBuilt":9,  "SafeYears":10, "YearsToMigrate":10},
    {"Cryptosystem":"RSA-8192", "LogicalQ":5261, "PredictedYear":2035, "YearsUntilBuilt":10, "SafeYears":10, "YearsToMigrate":12},
    {"Cryptosystem":"P-160", "LogicalQ":1466, "PredictedYear":2040, "YearsUntilBuilt":15, "SafeYears":10, "YearsToMigrate":2},
    {"Cryptosystem":"P-192", "LogicalQ":1754, "PredictedYear":2042, "YearsUntilBuilt":17, "SafeYears":10, "YearsToMigrate":5},
    {"Cryptosystem":"P-224", "LogicalQ":2042, "PredictedYear":2045, "YearsUntilBuilt":20, "SafeYears":10, "YearsToMigrate":5},
    {"Cryptosystem":"P-256", "LogicalQ":2330, "PredictedYear":2045, "YearsUntilBuilt":20, "SafeYears":10, "YearsToMigrate":8},
    {"Cryptosystem":"P-384", "LogicalQ":3484, "PredictedYear":2047, "YearsUntilBuilt":22, "SafeYears":10, "YearsToMigrate":10},
    {"Cryptosystem":"P-521", "LogicalQ":4719, "PredictedYear":2050, "YearsUntilBuilt":25, "SafeYears":10, "YearsToMigrate":12},
    {"Cryptosystem":"AES-128", "LogicalQ":2896, "PredictedYear":2080, "YearsUntilBuilt":55, "SafeYears":25, "YearsToMigrate":2},
    {"Cryptosystem":"AES-192", "LogicalQ":3216, "PredictedYear":2080, "YearsUntilBuilt":55, "SafeYears":30, "YearsToMigrate":2},
    {"Cryptosystem":"AES-256", "LogicalQ":3536, "PredictedYear":2080, "YearsUntilBuilt":55, "SafeYears":50, "YearsToMigrate":2},
    {"Cryptosystem":"SHA2-256", "LogicalQ":2402, "PredictedYear":2040, "YearsUntilBuilt":15, "SafeYears":10, "YearsToMigrate":2},
    {"Cryptosystem":"SHA3-256", "LogicalQ":3200, "PredictedYear":2040, "YearsUntilBuilt":15, "SafeYears":10, "YearsToMigrate":2},
]
df_table = pd.DataFrame(rows)


# === Model functions ===
def f(year, percentile=0.5):
    """Predict qubits for a given year."""
    m, theta, mu, K2, t0, y0 = 5, 0.63, 0.7535981217687973, 0.8019856520680299, 2021, -5.958049021130035
    dt = year - t0
    A_star = -2*theta + (1 + (2*(m-1)*theta)/m + theta**2) * (dt + dt**2/m)
    mu_in = y0 + mu * dt
    sigma2 = max(K2 * A_star / (1 + theta**2), 0)
    return np.exp(mu_in + math.sqrt(2*sigma2) * special.erfinv(2*percentile - 1))


def year_of_qubit(target_qubits, start_year=2023, max_year=2100, percentile=0.5):
    """Return the year when target qubits become achievable."""
    if target_qubits is None:
        return None
    for y in range(start_year, max_year + 1):
        try:
            if f(y, percentile) >= target_qubits:
                return y
        except Exception:
            continue
    return None


def probability_from_year(year_of_qubit_val, shelf_life, current_year=2023):
    """Linear risk ramp: higher if QC break year near/within shelf life."""
    if year_of_qubit_val is None:
        return 0.0
    target_year = current_year + shelf_life
    if year_of_qubit_val - target_year > 2 * shelf_life:
        return 0.0
    risk_increase = 1 - (year_of_qubit_val - target_year) / (2 * shelf_life)
    return float(max(0.0, min(1.0, risk_increase)))


def classify_risk(prob):
    if prob > 0.4: return "High risk"
    if prob > 0.1: return "Medium risk"
    if prob > 0.0: return "Low risk"
    return "No risk"


def compute_risk(algorithm_name, shelf_life=None, percentile=0.5, use_table_year=True, current_year=2025):
    """Main risk computation combining table info + model prediction."""
    match = df_table[df_table["Cryptosystem"].str.lower().str.contains(algorithm_name.lower(), regex=False)]
    if match.empty:
        raise ValueError(f"Algorithm '{algorithm_name}' not found.")
    row = match.iloc[0]
    logical_q = row["LogicalQ"]
    model_year = year_of_qubit(logical_q, start_year=current_year, percentile=percentile)
    table_year = row["PredictedYear"]
    chosen_year = table_year if use_table_year else model_year
    shelf = shelf_life if shelf_life is not None else row["YearsToMigrate"]
    prob = probability_from_year(chosen_year, shelf, current_year)
    return {
        "Cryptosystem": row["Cryptosystem"],
        "LogicalQ": logical_q,
        "TableYear": table_year,
        "ModelYear": model_year,
        "ChosenYear": chosen_year,
        "ShelfLife": shelf,
        "Percentile": percentile,
        "RiskProbability": round(prob, 3),
        "RiskLevel": classify_risk(prob),
    }


# === CLI Interface ===
def main():
    algo = input("Enter algorithm: ").strip()
    shelf = input("Enter custom shelf life in years (blank = default): ").strip()
    perc = input("Enter percentile for uncertainty (blank = 0.5): ").strip()

    shelf_life = int(shelf) if shelf else None
    percentile = float(perc) if perc else 0.5

    try:
        result = compute_risk(algo, shelf_life=shelf_life, percentile=percentile)
        print("\n Risk Analysis Result:")
        print("="*50)
        for k, v in result.items():
            print(f"{k:20}: {v}")
        print("="*50)
        print(f" Risk Probability Value: {result['RiskProbability']} ({result['RiskLevel']})")
        print("="*50)
    except Exception as e:
        print(f" Error: {e}")


if __name__ == "__main__":

    main()