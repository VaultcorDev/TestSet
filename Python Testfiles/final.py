import numpy as np
from scipy import special

# ====================================================
# 1️⃣ Quantum Growth Model (slightly tuned for clearer spread)
# ====================================================
def f(year):
    m = 5
    θ = 0.63
    μ = 0.70                     # ↓ slightly slower growth for wider year spread
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
# 2️⃣ Find year when target qubits reached
# ====================================================
def year_of_qubit(target_qubits):
    year = 2023
    while f(year) < target_qubits:
        year += 1
        if year > 2100:
            break
    return year


# ====================================================
# 3️⃣ Algorithm → Required Qubits
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
# 4️⃣ Logistic Risk Probability (tighter transition)
# ====================================================
def probability(required_qubits, shelf_life, current_year=2023):
    target_year = current_year + shelf_life
    year_q = year_of_qubit(required_qubits)
    delta = year_q - target_year
    scale = max(0.5, shelf_life / 4.0)   # sharper logistic drop-off
    risk = 1.0 / (1.0 + np.exp(delta / scale))
    return round(float(np.clip(risk, 0, 1)), 2), delta, year_q


# ====================================================
# 5️⃣ Ask user for shelf life
# ====================================================
current_year = 2023
shelf_life = int(input("Enter shelf life (in years): "))

print(f"\n📊 Quantum Risk Probabilities (tuned model for clearer spread)")
print(f"(Current Year = {current_year}, Shelf Life = {shelf_life} years)\n")
print(f"{'Algorithm':<10} {'Qubits':>8} {'BreakYear':>10} {'Δ(yrs)':>8} {'RiskProb':>10}")
print("-" * 55)

for name, q in crypto_estimates:
    risk, delta, break_year = probability(q, shelf_life, current_year)
    print(f"{name:<10} {q:>8} {break_year:>10} {delta:>8} {risk:>10.2f}")

print("\n✅ Computation complete.")
