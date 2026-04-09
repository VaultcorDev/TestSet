import numpy as np
from scipy import special

# --- Qubit growth model ---
def f(year):
    m = 5
    θ = 0.63
    μ = 0.93
    K2 = 1.05
    t_0 = 2016
    y_0 = -2.2

    A_star_input = -2 * θ + (1 + (2 * (m - 1) * θ) / m + θ ** 2) * (
        (year - t_0) + (year - t_0) ** 2 / m
    )
    μ_input = y_0 + μ * (year - t_0)
    σ2_input = K2 * A_star_input / (1 + θ ** 2)
    if σ2_input < 0:
        σ2_input = abs(σ2_input) * 0.5
    return np.exp(μ_input + np.sqrt(2 * σ2_input) * special.erfinv(0))


def year_of_qubit(target_qubits):
    year = 2023
    while f(year) < target_qubits:
        year += 1
        if year > 2100:
            break
    return year



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


# --- Risk probability calculation ---
def probability(chosen_variant, shelf_life, current_year):
    target_year = current_year + shelf_life
    required_qubits = next(q for name, q in crypto_estimates if name == chosen_variant)
    year_of_Qubit = year_of_qubit(required_qubits)

    if year_of_Qubit - target_year > 2 * shelf_life:
        risk_probability = 0.0
    else:
        risk_increase = 1 - (year_of_Qubit - target_year) / (2 * shelf_life)
        risk_probability = max(0, min(1, risk_increase))
    return round(risk_probability, 4)


# --- Example: print only risk probabilities ---
current_year = 2023
shelf_life = 10  # years

print(f"📅 Risk Probability (Current year={current_year}, Shelf life={shelf_life} years)\n")
for variant, _ in crypto_estimates:
    p = probability(variant, shelf_life, current_year)
    print(f"{variant:<10} → {p:.3f}")
