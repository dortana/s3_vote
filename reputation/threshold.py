import math
import numpy as np


class ThresholdManager:

    def trust_evenness(self, reputations):
        avg = np.mean(reputations)
        if avg == 0:
            return 0.0
        variance = np.sum([(r - avg) ** 2 for r in reputations])
        return float(max(0.0, 1 - variance / (len(reputations) * avg ** 2)))

    def adaptive_threshold(self, reputations):
        """
        Two-piece linear threshold anchored at ceil(N/2) for neutral trust.

        t_neutral = ceil(N/2)         — starting point (INITIAL_REP = 2/3, equal reps)
        t_max     = N - 1             — most restrictive  (trust → 0)
        t_min     = max(2, ceil(N/3)) — most permissive   (trust → 1)

        trust in [0,   2/3] → threshold linear from t_max   down to t_neutral
        trust in [2/3, 1  ] → threshold linear from t_neutral down to t_min
        """
        n         = len(reputations)
        avg       = float(np.mean(reputations))
        E         = self.trust_evenness(reputations)
        trust     = min(1.0, avg * E)

        t_neutral = math.ceil(n / 2)
        t_max     = n - 1
        t_min     = max(2, math.ceil(n / 3))

        if trust <= 2 / 3:
            threshold = t_max - (t_max - t_neutral) * trust * 1.5
        else:
            threshold = t_neutral - (t_neutral - t_min) * (trust - 2 / 3) * 3

        return round(float(max(t_min, min(t_max, threshold))), 3)
