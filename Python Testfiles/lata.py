import numpy as np
from scipy import special

# Qubit growth model parameters

μ = 0.78        # growth rate
t0 = 2016       # baseline year
y0 = -3.5       # baseline offset

# Analytic inverse model — find year when target qubits reached
def year_of_qubit(Q):
    if Q <= 0:
        return float('inf')
    year = t0 + (np.log(Q) - y0) / μ
    return int(np.ceil(year))

# Algorithm → required qubits (as from Shor’s / Grover’s estimates)
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
# Logistic risk probability model

def probability(required_qubits, shelf_life, current_year=2023):
    target_year = current_year + shelf_life
    year_q = year_of_qubit(required_qubits)
    delta = year_q - target_year
    scale = max(0.5, shelf_life / 2.0)
    risk = 1.0 / (1.0 + np.exp(delta / scale))
    return round(float(np.clip(risk, 0, 1)), 2)


# Compute risk probabilities

current_year = 2023
shelf_life = 5 # you can change this (e.g., 5, 15, 20)

print(f"\n📊 Quantum Risk Probabilities (current={current_year}, shelf={shelf_life} yrs)\n")
print(f"{'Algorithm':<10} {'Qubits':>8} {'BreakYear':>10} {'RiskProb':>10}")
print("-" * 40)

for name, q in crypto_estimates:
    risk = probability(q, shelf_life, current_year)
    break_year = year_of_qubit(q)
    print(f"{name:<10} {q:>8} {break_year:>10} {risk:>10.2f}")
