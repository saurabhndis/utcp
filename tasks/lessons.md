# Lessons

- **Test app intent (user correction, 2026-11-05):** "test against the kernel" meant *one
  application with two interchangeable TCP backends* (utcp vs kernel sockets) running the
  same workloads, not a utcp app talking to a separate kernel peer tool. Rule: when asked to
  compare against a baseline, make the baseline the same code with only the component under
  test swapped.
- **Benchmark fairness:** before comparing stacks, check that the impairment and offload
  paths are really symmetric. netem drops per skb, so GSO/GRO must be off on *both* paths for
  per-packet loss. Client-side artifacts (TIME_WAIT scans in `connect()`) can masquerade as
  server latency; capture packets to see which side is slow.
- **Simulate before going live:** a deterministic simulator with a FIFO link, plus a
  "D-SACK means bug" assertion, found four real loss-recovery bugs that live tests would
  only have shown as lower throughput.
- **Callbacks that release objects:** after any callback that can free or release the
  object, re-read the handle (stale `user` pointer bug), and defer frees to the end of an
  epoll batch.
