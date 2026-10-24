# Distributed Systems & Scalability Review Skill

## Purpose

Use this skill when designing, implementing, reviewing, debugging, or refactoring application code that may run in a distributed, multi-user, multi-tenant, asynchronous, high-throughput, latency-sensitive, or production environment.

The goal is not to overengineer every function. The goal is to identify where scale, concurrency, partial failure, retries, latency, state, or external dependencies can create production problems and to make those tradeoffs explicit.

Think like a senior engineer responsible for keeping the system fast, correct, observable, and available under load and during failure.

---

## When to Apply

Apply this skill strongly when working on:

- APIs and request handlers
- service-to-service communication
- database access
- caching
- queues and background jobs
- event-driven systems
- external API integrations
- authentication and authorization paths
- multi-tenant systems
- rate limiting
- high-volume ingestion
- crawlers and pipelines
- batch processing
- scheduled jobs
- distributed workers
- file/object storage
- search systems
- AI/LLM calls
- webhooks
- payment or billing operations
- state transitions
- deployment or migration logic

Apply lightly for local-only scripts, isolated pure functions, UI-only changes, and low-risk internal tooling unless they participate in a production path.

---

## Core Mental Model

For every meaningful production path, reason about:

1. **Latency**
2. **Load**
3. **Failure**
4. **Correctness**
5. **Consistency**
6. **Concurrency**
7. **Capacity**
8. **Isolation**
9. **Observability**
10. **Recovery**

Do not only ask whether the happy path works.

Ask what happens when the dependency is slow, unavailable, duplicated, retried, stale, overloaded, partially successful, or returns out of order.

---

## Mandatory Questions for Dependency Calls

Whenever code calls a database, cache, queue, filesystem, object store, external API, model provider, or another service, consider:

- What is the timeout?
- Is the timeout bounded?
- Is the operation safe to retry?
- Which errors are retryable?
- Is exponential backoff used where appropriate?
- Is jitter used to avoid synchronized retries?
- Is there a retry budget?
- Can retries amplify load during an outage?
- Is the operation idempotent?
- What happens if the operation succeeds but the response is lost?
- Can duplicate requests cause duplicate side effects?
- What happens if the dependency becomes slow rather than fully unavailable?
- Is there a circuit breaker or equivalent protection where needed?
- Can the caller degrade gracefully?
- Is there a fallback?
- Is stale data acceptable?
- Are failures observable?

Do not add retries blindly.

---

## Caching Review

When introducing or reviewing a cache, reason about:

- Why is the cache needed?
- What is the source of truth?
- What is the cache key?
- Could the key become a hot key?
- What is the TTL?
- Is TTL jitter useful?
- How is invalidation handled?
- Is stale data acceptable?
- What happens on cache miss?
- What happens during a cold start?
- Can a cache miss storm overload the database?
- Is request coalescing / single-flight useful?
- Should stale-while-revalidate be used?
- What happens if the cache is unavailable?
- Can cache failure take down the application?
- Is local cache, distributed cache, CDN cache, or no cache the right choice?
- Are cached values tenant-scoped correctly?
- Can sensitive information leak across tenants through cache keys?

Prefer correctness first, then performance.

---

## Retry & Idempotency Review

For any operation that may be retried:

- Determine whether it is naturally idempotent.
- If not, consider an idempotency key, deduplication key, unique constraint, or transaction boundary.
- Ensure the idempotency key is stable across retries.
- Do not generate a new key inside the retry loop.
- Preserve the original result when practical.
- Bound retries.
- Avoid retries on validation errors, auth failures, or permanent failures.
- Use exponential backoff with jitter for transient failures.
- Consider retry amplification across service layers.
- Prefer retries at one appropriate layer rather than every layer.

For queue consumers and event handlers, assume duplicate delivery can happen unless the platform explicitly guarantees otherwise.

---

## Queue & Async Work Review

When using a queue, broker, or background job system, consider:

- What are the delivery semantics?
- Can messages be duplicated?
- Can messages arrive out of order?
- Can messages be delayed?
- Can processing fail halfway through?
- Is processing idempotent?
- What happens after repeated failure?
- Is there a dead-letter queue or quarantine path?
- Is retry delay appropriate?
- Can poison messages block progress?
- Is queue depth monitored?
- Is consumer lag monitored?
- Is there a maximum acceptable lag?
- Can consumers scale horizontally?
- Is message ordering required?
- Is partitioning keyed correctly?
- Can one tenant or partition become hot?
- Is backpressure supported?
- Is there bounded queue growth?
- What happens when producers outpace consumers for hours?
- Can low-priority work be dropped or delayed?

---

## Database Review

For data access and schema design, reason about:

- What is the query pattern?
- Are the required indexes present?
- What is the expected cardinality?
- Is the query bounded?
- Could this become an N+1 query?
- Could pagination become expensive?
- Are large scans avoided?
- Is connection pooling bounded?
- Can connection pools overwhelm the database?
- Is transaction scope minimal?
- Are locks held longer than necessary?
- Can concurrent writers race?
- Is optimistic or pessimistic locking needed?
- Are uniqueness constraints enforcing invariants?
- Is replication lag acceptable?
- Is read-after-write consistency required?
- Could this data need partitioning or sharding later?
- Is the proposed partition key evenly distributed?
- Could a tenant or customer become a hot partition?
- Is schema evolution backward compatible?
- Can the migration run safely against a large table?
- Is rollback possible?

Avoid using distributed locks when a database constraint or atomic update can solve the problem more safely.

---

## Concurrency & State Review

For state-changing operations, ask:

- Can two requests modify this state concurrently?
- What invariant must never be violated?
- Is the check-and-write sequence atomic?
- Is compare-and-swap or version checking appropriate?
- Can stale writes overwrite newer writes?
- Can events arrive out of order?
- Should revisions, sequence numbers, or timestamps be checked?
- What happens if two workers process the same entity?
- Is a distributed lock truly necessary?
- What happens if a process holding a lock crashes?
- Does the lock have safe expiry and ownership semantics?

Treat race conditions as production behavior, not edge cases.

---

## Traffic & Capacity Review

For high-traffic paths, consider:

- Expected average RPS
- Expected peak RPS
- Burst behavior
- Request concurrency
- Payload sizes
- Read/write ratio
- CPU cost per request
- Memory cost per request
- network bandwidth
- database QPS
- cache QPS
- queue throughput
- external API quotas
- connection limits

Ask:

- What happens at 2x traffic?
- What happens at 10x traffic?
- Where is the first bottleneck?
- Is autoscaling based on the right signal?
- Is there enough capacity headroom?
- Can one customer create disproportionate load?
- Should traffic be rate limited?
- Should work be prioritized?
- Can noncritical work be shed?

---

## Rate Limiting, Backpressure & Load Shedding

Consider:

- per-user limits
- per-IP limits
- per-tenant limits
- endpoint-specific limits
- global limits
- downstream-specific quotas
- concurrency limits
- bounded work queues

When overloaded:

1. protect the system,
2. preserve critical work,
3. reject or defer lower-priority work,
4. recover quickly.

Do not allow unlimited buffering.

A queue is not a substitute for capacity planning.

---

## Multi-Tenant Isolation

For multi-tenant systems, verify:

- tenant identity is explicit
- every data access is tenant-scoped
- cache keys include tenant scope where required
- queue messages preserve tenant identity
- background jobs cannot cross tenant boundaries
- rate limits prevent noisy-neighbor behavior
- resource-intensive tenants are bounded
- logs and metrics preserve useful tenant context without leaking secrets
- storage prefixes/buckets/tables are isolated appropriately
- authorization is checked at the resource boundary

Scale problems and security problems often overlap in multi-tenant systems.

---

## Observability Requirements

Production-critical paths should make it possible to answer:

- Is the system healthy?
- Is it fast?
- Is it correct?
- Is it overloaded?
- Which dependency is failing?
- Which tenant or request is affected?
- When did the problem begin?
- What changed?

Prefer:

- structured logs
- correlation/request IDs
- distributed tracing
- RED metrics for services:
  - Rate
  - Errors
  - Duration
- USE metrics for resources:
  - Utilization
  - Saturation
  - Errors
- p50/p95/p99 latency
- queue depth / consumer lag
- cache hit ratio
- database pool saturation
- retry counts
- timeout counts
- rate-limit counts
- circuit-breaker state
- external dependency latency/error rate

Do not log secrets, tokens, credentials, or unnecessary sensitive data.

---

## Availability & Graceful Degradation

For noncritical dependencies, consider whether the application can:

- return stale data
- return partial results
- skip enrichment
- disable a secondary feature
- enqueue work for later
- fall back to a simpler implementation
- return a clear degraded-state response

A noncritical dependency should not automatically become a total-system dependency.

---

## Distributed Transactions

When one operation changes multiple systems, determine what happens if step N succeeds and step N+1 fails.

Consider:

- local transaction first
- transactional outbox
- inbox/deduplication
- saga pattern
- compensating actions
- reconciliation jobs
- explicit workflow state machines

Avoid pretending multiple independent systems form one atomic transaction.

---

## API Design for Scale

Review:

- pagination
- payload size
- filtering
- sorting
- request limits
- batch endpoints
- idempotency
- async operation patterns
- status polling
- webhook delivery
- versioning
- backward compatibility
- partial failure behavior
- timeout behavior

Avoid unbounded list endpoints.

Prefer cursor pagination for large, frequently changing datasets where appropriate.

---

## Deployment & Change Safety

Before changes to production systems, consider:

- backward compatibility
- forward compatibility
- mixed-version deployments
- zero-downtime migration strategy
- expand-and-contract schema changes
- feature flags
- canary releases
- rollback
- data rollback limitations
- reprocessing
- replay safety

Assume old and new application versions may run simultaneously during deployment.

---

## Failure Scenarios to Consider

At minimum, mentally test relevant paths against:

- dependency timeout
- dependency 500
- dependency rate limiting
- database slow queries
- database unavailable
- cache unavailable
- cache cold start
- queue unavailable
- queue backlog
- duplicate event
- out-of-order event
- worker crash mid-operation
- deployment during active traffic
- network partition
- partial region failure
- sudden traffic spike
- hot tenant
- malformed payload
- oversized payload
- external quota exhaustion

Do not implement every mitigation automatically. Identify the risk and use the simplest mitigation justified by the system.

---

## Review Output Format

When this skill is relevant, surface important findings using this format when practical:

### Risk
What could fail, overload, race, duplicate, become stale, or cascade?

### Impact
What happens to users or the system?

### Recommendation
What is the simplest appropriate mitigation?

### Tradeoff
What complexity, cost, latency, or operational burden does the mitigation introduce?

### Verification
How should we test or observe that the mitigation works?

Prioritize findings:

- **Critical** — correctness, security, data loss, widespread outage
- **High** — likely reliability/scalability bottleneck
- **Medium** — important at larger scale or under specific failure modes
- **Low** — optimization or future hardening

---

## Engineering Principles

1. Correctness before optimization.
2. Make failure bounded.
3. Make load bounded.
4. Make retries bounded.
5. Make queues bounded.
6. Make concurrency explicit.
7. Prefer idempotency over hoping duplicates never happen.
8. Prefer database constraints over application-only invariants.
9. Prefer graceful degradation over cascading failure.
10. Prefer observable systems over clever systems.
11. Optimize based on measured bottlenecks.
12. Avoid premature distributed complexity.
13. Design interfaces so scaling strategies can evolve later.
14. Assume networks fail.
15. Assume dependencies become slow before they become unavailable.
16. Assume requests and events can be duplicated.
17. Assume deployments contain mixed software versions.
18. Assume traffic is uneven.
19. Assume one tenant can become disproportionately large.
20. Always know how the system recovers.

---

## Final Rule

Do not merely ask:

> Does this code work?

Also ask:

> What happens when this runs concurrently, at high volume, during partial failure, while dependencies are slow, and while the system is being deployed?

That is the default production mindset.
