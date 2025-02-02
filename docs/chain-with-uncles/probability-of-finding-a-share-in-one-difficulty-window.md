# Probability of Finding Shares as a Small Miner

We want to determine what is the probability that a small miner finds
at least one share over the bitcoin difficulty period of two weeks.

The question was raised by Sjors Provoost at BOB Spaces Cohort 3, and
we all worked together to find an answer to this. Thanks goes also to
Gabriele Vernetti for looking at the numbers from a different
perspective to increase our confidence in P2Pool reboot.

## Motivation

Adoption of P2Poolv2 will benefit by enabling the long tail of miners
to join the pool. For such miners, we want to alleviate the fear that
there they won't get any shares in the sharechain. Knowing the
smallest hashrate that can find a share in a period helps miners know
if P2Poolv2 will work for them.

Long tail miners generally can be more tolerant of variance in finding
shares as long as the payout is fair and auditable. As long as miners
find a share once in a retarget period, they know the pool is
operating and is not scamming them.

With this motivation we present a model to find the minimal hashrate
required to find a share in a retarget period with over 99%
probability, and then compute the minimal hashrate required. We
conclude that with two S19 pros, a miner can find a share in a
retarget period in each retarget window. The model doesn't assume
uncles and this hashrate will reduce once we incorporate uncles into
to extend the model.

## Model

We make the following assumptions for the model:

1. P2Poolv2 has 1% of the bitcoin hashrate.
1. P2Poolv2 blockrate (blockrate on the share chain) = 1 / 10 second.
1. Miner hashrate on P2Pool is $m%$

This gives us the expected number of blocks in 2 week period as 
$14 * 24 * 60 * 6$ or 120,960 blocks every two weeks.

The expected number of blocks for the miner at $m%$ hashrate in two
week period to be $m/100 * 120,960$.

We use Poisson process to model the weak block generation by a miner
using lambda = 0.1 (1 block every 10s).

We look for the probability that a miner with hashrate $m$ finds at
least one block in a two week period. If a miner finds a single block
during a two week period, then it will receive at least one payout in
that two week period.

Using the Poisson distrubution we get the probability of finding no
blocks in two week period given the mean $M = m/100 * 120,960$, or
$\frac{\lambda^0 e^{-\lambda}}{0!}$.

If we plug in $m$ as $0.004%$, which corresponds to about 200 Th/s or
two S19pros, we get mean as $0.004/100 * 120,60 = 4.834$ shares in two
week periods.

Using the Poisson distribution with the above mean, we compute the
probability that no shares are found by the miner in the two week
period as: $\frac{4.834^0 e^{-4.834}}{0!} = 0.792%$

Converting that to at least one share, we get the probability as
$100 -0.792 = 99.2%$

## Conclusion

The probability that a small miner with two S19s pro will be paid out
at least once in two weeks with a 99% probability encourages us to
build P2Poolv2.

## Future Work

We have not modelled any uncles in the above model and that will be
the next step here. We expect the hashrate required to get one share
every two weeks period to further reduce.
