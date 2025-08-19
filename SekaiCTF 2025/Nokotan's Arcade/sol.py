import sys
import heapq
from collections import defaultdict

def max_popularity_fast_correct(n, players, t):
    """
    n : int - number of minutes (minutes are 1..n inclusive)
    players : list of (l, r, p) with l,r in [1..n] inclusive
    t : int - duration in minutes

    Returns maximum total popularity value.
    """

    # Events to add/remove p at end-time e.
    # A player (l,r,p) can finish at any end e in [l + t - 1, r] (inclusive).
    # We'll clamp to [1..n].
    add = [[] for _ in range(n + 3)]
    remove = [[] for _ in range(n + 3)]

    for l, r, p in players:
        start_e = l + t - 1
        end_e = r
        if start_e > end_e:
            continue
        if start_e > n or end_e < 1:
            continue
        start_e = max(start_e, 1)
        end_e = min(end_e, n)
        add[start_e].append(p)
        remove[end_e + 1].append(p)  # remove after end_e

    # Sweep to get best_p[e] = max p among players that can finish at e
    heap = []            # max-heap simulated with negatives
    cnt = {}             # counts of active p values
    best_p = [None] * (n + 1)  # use indices 1..n

    for e in range(1, n + 1):
        for p in add[e]:
            heapq.heappush(heap, -p)
            cnt[p] = cnt.get(p, 0) + 1
        for p in remove[e]:
            # lazy removal
            cnt[p] -= 1
            if cnt[p] == 0:
                del cnt[p]
        # clean top of heap if it's no longer active
        while heap and (-heap[0]) not in cnt:
            heapq.heappop(heap)
        best_p[e] = -heap[0] if heap else None

    # DP: dp[e] = best value up to minute e (minutes 1..e processed)
    dp = [0] * (n + 1)
    for e in range(1, n + 1):
        # carry forward (skip minute e)
        if dp[e - 1] > dp[e]:
            dp[e] = dp[e - 1]
        # try scheduling a game that ends at e (requires e - t >= 0)
        if e - t >= 0 and best_p[e] is not None:
            cand = dp[e - t] + best_p[e]
            if cand > dp[e]:
                dp[e] = cand

    return dp[n]


if __name__ == "__main__":
    n, m, t = map(int, sys.stdin.readline().strip().split())
    people = []
    for _ in range(m):
        l, r, p = map(int, sys.stdin.readline().strip().split())
        people.append((l, r, p))
    ans = max_popularity_fast_correct(n, people, t)
    print(ans)
