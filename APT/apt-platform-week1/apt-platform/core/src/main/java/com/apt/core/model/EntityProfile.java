package com.apt.core.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.UUID;

/**
 * EntityProfile — a tracked user or device with a behavioral history.
 *
 * UEBA (User and Entity Behavior Analytics) works by learning what
 * "normal" looks like for each entity, then flagging deviations.
 * This class is the anchor for all baseline data about one entity.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "entity_profiles", indexes = {
    @Index(name = "idx_entity_id", columnList = "entity_id", unique = true)
})
public class EntityProfile {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "entity_id", nullable = false, unique = true)
    private String entityId;          // Username or device hostname

    @Enumerated(EnumType.STRING)
    @Column(name = "entity_type", nullable = false)
    private EntityType entityType;

    @Column(name = "department")
    private String department;        // HR, Engineering, Finance …

    @Column(name = "risk_level")
    @Enumerated(EnumType.STRING)
    @Builder.Default
    private RiskLevel riskLevel = RiskLevel.LOW;

    @Column(name = "total_alerts")
    @Builder.Default
    private int totalAlerts = 0;

    @Column(name = "last_seen")
    private Instant lastSeen;

    @Column(name = "baseline_established")
    @Builder.Default
    private boolean baselineEstablished = false;  // True after 60-90 day window

    @Column(name = "created_at", updatable = false)
    @Builder.Default
    private Instant createdAt = Instant.now();

    public enum EntityType { USER, DEVICE, SERVICE_ACCOUNT, APPLICATION }
    public enum RiskLevel   { LOW, MEDIUM, HIGH, CRITICAL }
}


/**
 * BehavioralBaseline — the learned statistical profile for one feature of one entity.
 *
 * For each entity + feature pair (e.g. "alice" + "login_hour"), we store:
 *   - μ (mu):     the mean value seen in normal behavior
 *   - σ² (sigma): the variance (spread) of normal behavior
 *   - n:          how many samples the baseline is based on
 *
 * The detection engine uses these to score incoming events with:
 *   - Gaussian probability P(x) — flag if below threshold ε
 *   - Three-sigma rule — flag if |x - μ| > 3σ
 *
 * Why a separate table per feature?
 * Each user has ~15 features we track. Storing them as separate rows
 * lets us query "give me the login_hour baseline for all users in Finance"
 * efficiently, and update each feature independently as new data arrives.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "behavioral_baselines", indexes = {
    @Index(name = "idx_baseline_entity_feature",
           columnList = "entity_id, feature_name", unique = true)
})
class BehavioralBaseline {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "entity_id", nullable = false)
    private String entityId;

    @Column(name = "feature_name", nullable = false)
    private String featureName;   // e.g. "login_hour", "bytes_per_day", "failed_logins"

    @Column(name = "mu", nullable = false)
    private double mu;            // Running mean (updated with Welford's algorithm)

    @Column(name = "sigma_sq", nullable = false)
    private double sigmaSq;       // Running variance

    @Column(name = "sample_count", nullable = false)
    @Builder.Default
    private long sampleCount = 0L;

    @Column(name = "last_updated")
    @Builder.Default
    private Instant lastUpdated = Instant.now();
}
