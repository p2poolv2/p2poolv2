# Difficulty Adjustment in CKPool

CKPool adjusts difficulty when `add_submit` is called with new mining.submit message. The function implements a dynamic difficulty adjustment. It analyzes client hash rate performance and adjusts their assigned difficulty to optimize share submission frequency. In this page we describe the various mathematical formulas used by ckpool's difficulty adjustment.

## Key Variables and Their Purpose

- **client->ssdc**: Share submission diff counter - tracks shares since last difficulty change
- **client->diff**: Current client difficulty setting
- **client->old_diff**: Previous difficulty before a change
- **client->first_share**: Timestamp when client submitted first share
- **client->ldc**: Last difficulty change timestamp
- **client->dsps1/5/60/1440/10080**: Difficulty shares per second over different time windows (1min, 5min, 1hr, 24hr, 7day)

Note: Only client->dsps5 is used in difficulty adjustment. All the rest are used for reporting client's stats.

## Time-Based Metrics

- **bdiff**: Time elapsed (in seconds) since first share submission = current_time - first_share_time
- **tdiff**: Time elapsed (in seconds) since last difficulty change = current_time - ldc

## Share Rate Calculation Process

### 1. Exponential Decay Function

The `decay_time` function implements an exponential decay formula to weighted-average the share rates:

$f_{new} = \frac{f_{old} + \frac{diff_{share} \times fprop}{elapsed\_time}}{1 + fprop}$

Where:

- $fprop = 1 - \frac{1}{e^{elapsed\_time/interval}}$
- $interval$ is the time window (e.g., 60 seconds for 1min average)
- $diff_{share}$ is the difficulty of the current share

### 2. Share Rate Bias Calculation

$bias = 1 - \frac{1}{e^{bdiff/300}}$

This bias factor approaches 1 as time since first share increases, with a 5-minute (300s) time constant.

#### How the Time Bias Works

1. For brand new miners (tdiff = 0), the bias = 0, meaning their performance is heavily discounted
1. As time progresses, the bias approaches 1.0, giving full weight to their measured performance
1. The 300-second time constant determines how quickly this transition happens.

#### Time Bias Values

| Time since first share | Bias value | Effect on hashrate calculation |
| ---------------------- | ---------- | ------------------------------ |
| 0 seconds              | 0.000      | Complete discount (unusable)   |
| 60 seconds (1 min)     | 0.181      | Only 18.1% of observed rate    |
| 150 seconds (2.5 min)  | 0.393      | About 39.3% of observed rate   |
| 300 seconds (5 min)    | 0.632      | About 63.2% of observed rate   |
| 600 seconds (10 min)   | 0.865      | About 86.5% of observed rate   |
| 900 seconds (15 min)   | 0.950      | About 95.0% of observed rate   |
| 1200 seconds (20 min)  | 0.982      | About 98.2% of observed rate   |
| 1800 seconds (30 min)  | 0.998      | Nearly 100% of observed rate   |

### 3. Adjust dsps for bias

$dsps = \frac{client.dsps5}{bias}$

The 5-minute difficulty share rate is divided by the bias, giving newer miners a temporarily boosted rate.

### 4. Difficulty Rate Ratio

DRR is the value ckpool tries to get to an optimal value by adjusting the difficulty. CKPool tries to keep DRR close to 0.3 as we see in the next section.

$drr = \frac{dsps}{diff_{current}}$

This measures the ratio between the client's share rate and their current difficulty. As noted above, this is a made up number that normalizes the number of shares per second by the current difficulty.

If current difficulty is very high as compared to the current dsps, we'll have a very low drr, and therefore we will reduce the current difficulty, and so on. We want this ratio to be 0.3

## Optimal Difficulty Determination

The system targets a specific difficulty rate ratio (DRR):

- Optimal ratio is approximately 0.3 (shares every ~3.33 seconds)
- System uses hysteresis: only adjusts if DRR < 0.15 or DRR > 0.4
- Target difficulty is calculated as: $optimal\_diff = dsps \times 3.33$ (for standard clients)
- For clients with minimum difficulty specified: $optimal\_diff = dsps \times 2.4$. We will ignore this in our first implementation.

## Difficulty Constraint Logic

The final difficulty is bounded by:

1. Maximum of pool minimum difficulty and calculated optimal
2. Maximum of user-chosen minimum difficulty and calculated optimal
3. Minimum of calculated optimal and pool maximum difficulty
4. Minimum of calculated optimal and network difficulty

## Implementation Details

1. The system includes guards against rapid oscillation:

   - Difficulty is not adjusted until 72 shares have been collected or 240 seconds have passed since the last adjustment.
   - Instead of aiming for a precise 0.3 drr, ckpool doesn't change difficulty until drr falls out of [0.15, 0.4] range.

1. There's special handling for first shares in a session. We just need to initialize the ldc timestamp and return.

1. Retain difficulty change information for debugging purposes.
   - Old difficulty preserved in client->old_diff
   - Record job_id when difficulty was changed
