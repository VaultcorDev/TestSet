import numpy as np
from scipy import special


# 1️⃣ Quantum Growth Model (your full original formula)

def f(year):
    m = 5
    θ = 0.63
    μ = 0.7535981217687973
    K2 = 0.8019856520680299
    t_0 = 2021
    y_0 = -5.958049021130035

    # Compute A*, mean, and variance
    A_star_input = -2 * θ + (1 + (2 * (m - 1) * θ) / m + θ ** 2) * (
        (year - t_0) + (year - t_0) ** 2 / m
    )
    μ_input = y_0 + μ * (year - t_0)
    σ2_input = K2 * A_star_input / (1 + θ ** 2)

    if σ2_input < 0:
        σ2_input = abs(σ2_input) * 0.5  # avoid negative variance

    predicted_qubits = np.exp(μ_input + np.sqrt(2 * σ2_input) * special.erfinv(0))
    return predicted_qubits


# ====================================================
# 2️⃣ Inverse Model: Find year when target qubits reached
# ====================================================
def year_of_qubit(target_qubits):
    year = 2023  # start from present year
    while f(year) < target_qubits:
        year += 1
        if year > 2100:  # safety break
            break
    return year


# ====================================================
# 3️⃣ Algorithm → Required Qubits (from Shor/Grover analysis)
# ====================================================
crypto_estimates = [
    ('RSA-1024', 742),
    ('RSA-2048', 1399),
    ('RSA-3072', 2043),
    ('RSA-4096', 2692),
    ('RSA-8192', 5261),
    ('P-160', 1466),
    ('P-192', 1754),
    ('P-224', 2042),
    ('P-256', 2330),
    ('P-384', 3484),
    ('P-521', 4719),
    ('AES-128', 2896),
    ('AES-192', 3216),
    ('AES-256', 3536),
    ('SHA2-256', 2402),
    ('SHA3-256', 3200),
]


# ====================================================
# 4️⃣ Risk Probability Calculation (Logistic Mapping)
# ====================================================
def probability(required_qubits, shelf_life, current_year=2023):
    target_year = current_year + shelf_life
    year_q = year_of_qubit(required_qubits)
    delta = year_q - target_year
    scale = max(0.5, shelf_life / 2.0)
    risk = 1.0 / (1.0 + np.exp(delta / scale))
    return round(float(np.clip(risk, 0, 1)), 2)


# ====================================================
# 5️⃣ Generate continuous results for multiple shelf lives
# ====================================================
current_year = 2023
shelf_life_list = [5, 10, 15, 20]  # multiple lifetimes

print("\n📊 Quantum Risk Probabilities (using full quantum growth model)\n")

for shelf_life in shelf_life_list:
    print(f"=== Shelf Life = {shelf_life} years ===")
    print(f"{'Algorithm':<10} {'Qubits':>8} {'BreakYear':>10} {'RiskProb':>10}")
    print("-" * 45)
    for name, q in crypto_estimates:
        break_year = year_of_qubit(q)
        risk = probability(q, shelf_life, current_year)
        print(f"{name:<10} {q:>8} {break_year:>10} {risk:>10.2f}")
    print()
