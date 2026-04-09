import numpy as np
from scipy import special
m = 5
θ = 0.63
μ = 0.93            #  growth rate 0.7 to 0.93
K2 = 1.05          # variance factor
t_0 = 2016         # baseline year
y_0 = -2.2        # offset


def f(year):
    A_star_input = -2 * θ + (1 + (2 * (m - 1) * θ) / m + θ**2) * (
        (year - t_0) + (year - t_0)**2 / m
    )
    μ_input = y_0 + μ * (year - t_0)
    σ2_input = K2 * A_star_input / (1 + θ**2)
    σ2_input = np.maximum(σ2_input, 0.0)  

   
    predicted_qubits = np.exp(μ_input + np.sqrt(2 * σ2_input) * special.erfinv(0))
    return predicted_qubits

print("Year : Predicted Qubits")
for yr in range(2016, 2041):
    print(f"{yr}: {f(yr):.0f} qubits")
