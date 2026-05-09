import matplotlib.pyplot as plt


# Honest authorities

honest_authorities = 5

honest_reputation = 1.0


# Maximum allowed Sybil influence
# relative to honest influence

MAX_SYBIL_RATIO = 0.10


sybil_count = []

sybil_influence = []


# Honest system influence

honest_total_influence = (
    honest_authorities *
    honest_reputation
)


for fake_nodes in range(1, 51):

    # Raw Sybil reputation

    probationary_r = 0.2

    raw_sybil_r = (
        fake_nodes *
        probationary_r
    )

    # Hard cap based ONLY on honest influence

    capped_influence = min(
        raw_sybil_r,
        MAX_SYBIL_RATIO *
        honest_total_influence
    )

    sybil_count.append(fake_nodes)

    sybil_influence.append(capped_influence)

    print(
        f"Sybil Nodes={fake_nodes}, "
        f"Influence={round(capped_influence, 3)}"
    )


plt.plot(
    sybil_count,
    sybil_influence
)

plt.xlabel("Number of Sybil Nodes")

plt.ylabel("Total Sybil Influence")

plt.title("Sybil Resistance With Fixed Influence Cap")

plt.grid(True)

plt.savefig(
    "figures/sybil_resistance.png",
    dpi=300,
    bbox_inches="tight"
)

plt.show()