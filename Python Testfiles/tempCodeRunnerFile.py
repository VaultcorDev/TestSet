import numpy as np
from scipy import special

def f(year):
    # Final tuned parameters
    m = 5
    θ = 0.63
    μ = 0.93          # tuned growth rate
    K2 = 1.05         # tuned variance factor
    t_0 = 2016        # baseline start
    y_0 = -2.2        # baseline offset

    # Model computation
    A_star_input = -2 * θ + (1 + (2 * (m - 1) * θ) / m + θ ** 2) * (
        (year - t_0) + (year - t_0) ** 2 / m
    )
    μ_input = y_0 + μ * (year - t_0)
    σ2_input = K2 * A_star_input / (1 + θ ** 2)

    # Handle negative variance safely
    if σ2_input < 0:
        σ2_input = abs(σ2_input) * 0.5

    predicted_qubits = np.exp(μ_input + np.sqrt(2 * σ2_input) * special.erfinv(0))
    return predicted_qubits

# Example usage
year = int(input("Enter year: "))
print(f"Predicted qubits for {year}: {f(year):.0f}")
