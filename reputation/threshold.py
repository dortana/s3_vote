import numpy as np


class ThresholdManager:

    def trust_evenness(self, reputations):

        avg = np.mean(reputations)

        variance = np.sum([
            (r - avg) ** 2
            for r in reputations
        ])

        return 1 - (
            variance /
            (len(reputations) * (avg ** 2))
        )

    def adaptive_threshold(
        self,
        base_threshold,
        reputations
    ):

        E = self.trust_evenness(reputations)

        return base_threshold * (
            1 + ((1 - E) / 2)
        )