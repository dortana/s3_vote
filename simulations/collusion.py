import matplotlib.pyplot as plt

from reputation.reputation_engine import ReputationEngine
from reputation.threshold import ThresholdManager


engine = ReputationEngine()

threshold_manager = ThresholdManager()


# Initial malicious reputations

m1 = 0.5
m2 = 0.5
m3 = 0.5

# Honest authorities

honest = [0.8] * 7


rounds = []

malicious_weights = []

thresholds = []


for r in range(20):

    # Malicious authorities behave dishonestly

    m1 = engine.update_reputation(
        m1,
        participation=0.2,
        contribution=0.1,
        honesty=0.0
    )

    m2 = engine.update_reputation(
        m2,
        participation=0.2,
        contribution=0.1,
        honesty=0.0
    )

    m3 = engine.update_reputation(
        m3,
        participation=0.2,
        contribution=0.1,
        honesty=0.0
    )

    reputations = [m1, m2, m3] + honest

    total_r = sum(reputations)

    total_weight = (
        (m1 / total_r) * 10 +
        (m2 / total_r) * 10 +
        (m3 / total_r) * 10
    )

    threshold = threshold_manager.adaptive_threshold(
        4,
        reputations
    )

    rounds.append(r)

    malicious_weights.append(total_weight)

    thresholds.append(threshold)

    print(
        f"Round {r}: "
        f"W_mal={round(total_weight, 3)}, "
        f"T={round(threshold, 3)}"
    )


# Plot malicious coalition influence

plt.plot(
    rounds,
    malicious_weights,
    label="Malicious Coalition Weight"
)

# Plot adaptive threshold

plt.plot(
    rounds,
    thresholds,
    label="Adaptive Threshold"
)

plt.xlabel("Round")

plt.ylabel("Value")

plt.title("Collusion Resistance Simulation")

plt.legend()

plt.grid(True)

plt.savefig(
    "figures/collusion.png",
    dpi=300,
    bbox_inches="tight"
)

plt.show()