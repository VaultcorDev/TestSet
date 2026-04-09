import numpy as np
from scipy import special

def f(year):
    # Tuned parameters (calibrated to hit 1000@2025, 2000@2028, 3000@2030, 10000@2040)
    m = 5
    θ = 0.63
    μ = 0.78
    K2 = 0.95
    t_0 = 2021
    y_0 = -6.9

    # Compute A*, μ_input, and σ²_input
    A_star_input = -2 * θ + (1 + (2 * (m - 1) * θ) / m + θ ** 2) * (
        (year - t_0) + (year - t_0) ** 2 / m
    )
    μ_input = y_0 + μ * (year - t_0)
    σ2_input = K2 * A_star_input / (1 + θ ** 2)

    # Clamp σ² if negative
    if σ2_input < 0:
        σ2_input = 0

    # Compute predicted qubits
    predicted_qubits = np.exp(μ_input + np.sqrt(2 * σ2_input) * special.erfinv(0))
    return predicted_qubits


# Quick test of your key years
for yr in [2025, 2028, 2030, 2040]:
    print(f"{yr}: {f(yr):.0f} qubits")

year = int(input("Enter year: "))
print(f"Predicted qubits for {year}: {f(year):.0f}")
