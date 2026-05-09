import numpy as np


class ThresholdManager:

    def trust_evenness(self, reputations):
        avg = np.mean(reputations)
        if avg == 0:
            return 0.0
        variance = np.sum([(r - avg) ** 2 for r in reputations])
        return float(max(0.0, 1 - variance / (len(reputations) * avg ** 2)))

    def adaptive_threshold(self, base_threshold, reputations):
        """
        Bidirectional adaptive threshold.

        trust = avg_rep * E  (combined level × evenness, range [0, 1])

        threshold = 5 - 3*trust  which maps to:
          trust = 1.0 (max honest, equal)   → threshold = 2  (only 2 authorities needed)
          trust = 2/3 (neutral start)       → threshold = 3  (base / initial)
          trust = 0.0 (fully dishonest)     → threshold = 5  (all 5 required)
        """
        avg = float(np.mean(reputations))
        E   = self.trust_evenness(reputations)

        trust     = min(1.0, avg * E)
        threshold = 5.0 - 3.0 * trust

        return round(max(1.0, threshold), 3)
