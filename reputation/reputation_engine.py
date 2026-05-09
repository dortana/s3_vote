class ReputationEngine:

    def __init__(
        self,
        alpha=0.2,
        beta=0.3,
        gamma=0.5,
        lamb=0.7,
        delta=0.95
    ):

        self.alpha = alpha
        self.beta = beta
        self.gamma = gamma
        self.lamb = lamb
        self.delta = delta

    def update_reputation(
        self,
        current_r,
        participation,
        contribution,
        honesty
    ):

        weighted_score = (
            self.alpha * participation +
            self.beta * contribution +
            self.gamma * honesty
        )

        updated = (
            self.lamb * current_r +
            (1 - self.lamb) * weighted_score
        )

        return self.delta * updated

    def calculate_weight(
        self,
        authority_r,
        total_r,
        n
    ):

        if total_r == 0:
            return 1

        return (authority_r / total_r) * n