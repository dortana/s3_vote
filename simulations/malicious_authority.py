import matplotlib.pyplot as plt

from reputation.reputation_engine import ReputationEngine


engine = ReputationEngine()

reputation = 0.5

rounds = []

values = []


for r in range(20):

    reputation = engine.update_reputation(
        reputation,
        participation=0.2,
        contribution=0.1,
        honesty=0.0
    )

    rounds.append(r)

    values.append(reputation)

    print(
        f"Round {r}: "
        f"{round(reputation, 4)}"
    )


plt.plot(rounds, values)

plt.xlabel("Round")

plt.ylabel("Reputation")

plt.title("Malicious Authority Reputation Decay")

plt.grid(True)

plt.savefig(
    "figures/malicious_authority.png",
    dpi=300,
    bbox_inches="tight"
)

plt.show()