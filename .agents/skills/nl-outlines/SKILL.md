---
name: nl-outlines
description: Use when reading, writing, editing, or reviewing a function whose implementation strategy is not obvious at a glance, i.e. any function long enough or dense enough that a reader must trace the code to see what it does. Adds or maintains natural language outlines, which are short prose statements interleaved with code as star comments (`//*`, `#*`) that partition a function into logical sections and summarize each one. Also use when the user asks to "outline" code, when comments have gone stale relative to the code, or when propagating a change from an edited outline back into the code (or vice versa). Do NOT use for docstrings (those describe the contract, not the strategy), commit messages, design docs, or per-line commentary.
---

# Natural Language Outlines

Based on Shi et al., "Natural Language Outlines for Code: Literate Programming
in the LLM Era" (FSE Companion '25, arXiv:2408.04820).

## What an outline is

An NL outline is a set of concise prose statements that **partition** a function
into semantically coherent sections and summarize each. Interleaved with the
code, it looks like this:

```rust
fn nearest_neighbor_tour(nodes: &[Point]) -> (f64, Vec<usize>) {
    //* Compute all pairwise distances between nodes.
    let mut distances = distance_matrix(nodes);
    //* Initialize the tour at node zero.
    let mut current = 0;
    let mut tour = vec![current];
    let mut cost = 0.0;
    let distance_to_start = distances.row(current).to_vec();

    //* Iteratively add all nodes to the tour.
    for _ in 0..nodes.len() - 1 {
        //* Mark the current node as visited.
        distances.column_mut(current).fill(f64::INFINITY);
        //* Extend the tour by going to the nearest unvisited neighbor.
        let neighbor = distances.row(current).argmin();
        cost += distances[(current, neighbor)];
        tour.push(neighbor);
        current = neighbor;
    }

    //* Complete the cycle back to the starting node.
    cost += distance_to_start[current];
    (cost, tour)
}
```

Read on its own, without the code, the outline should still be a complete
account of the implementation strategy.

## What an outline is not

- **Not a docstring.** A docstring states the *contract* for callers. An outline
  states the *implementation strategy* for maintainers. A function can and often
  should have both.
- **Not a line-by-line narration.** If there is a comment on every second line,
  the outline has failed. Aim for **at most 3 statements in a short function, at
  most 5 in a long one.** Too many statements means the ideas were not abstracted.
- **Not a tutorial.** Do not explain what a `for` loop is or what a well-known
  API does.
- **Not a home for hard-won knowledge.** Subtle rationale, tricky invariants,
  and pitfalls belong in ordinary comments, which a human owns and an AI must
  not touch. Outlines are the disposable layer.
- **Not the source of truth.** The code is. Natural language is ambiguous.

## The star comment convention

Outline statements use a **star comment**: the language's line comment followed
immediately by `*`.

| Language | Syntax |
|---|---|
| Rust, C, C++, Go, Java, JS/TS | `//*` |
| Python, Shell, TOML, YAML | `#*` |
| Lisp, Emacs Lisp | `;;*` |
| SQL | `--*` |

Two rules govern star comments, and they are the whole point of the convention:

1. **A star comment is AI-generated and should be trusted cautiously.**
2. **A star comment may be freely changed, added, or removed by AI tooling.**

The corollary matters more: **a comment without a star is human-owned. Never
rewrite, reflow, or delete one.** If a human strips the `*` from a star comment,
they have adopted it -- treat it as human-owned from then on. If a human adds a
`*` to their own comment, they have released it for maintenance.

## Writing a good outline

- **Partition, don't sprinkle.** Every line of the function body should fall
  under exactly one outline statement. Place the statement above the first line
  of the section it governs, never above a blank line and never mid-statement.
- **One sentence or phrase each.** No paragraphs.
- **Summarize the idea, not the mechanics.** `//* Extend the tour by going to
  the nearest unvisited neighbor.` -- not `//* Call argmin on the distance row.`
  The reader can see `argmin`.
- **Say *why* only when the reasoning is not obvious from the code.** Otherwise
  say *what*.
- **Use domain vocabulary the code omits.** If a function is clearly doing
  headers-first sync or an ASERT retarget, name it, even if that word appears
  nowhere in the identifiers. This is a large part of an outline's value.
- **Never change code while adding an outline.** Adding an outline is a
  comment-only diff. If the code appears to want refactoring, say so separately;
  do not fold it into the outline commit.

## Calibrating detail

The paper's central quality failure is detail miscalibration, in both
directions. Before finalizing, check the outline against these:

- **Too much detail:** the reader would be faster reading the code. Statements
  restate identifiers. There is one per line. Collapse them.
- **Too little detail:** a maintainer could not predict the function's behavior
  from the outline alone. Common with strong models, which over-compress. Add
  the missing step.
- **Correct but useless:** every statement is true and none is informative
  (`//* Return the response.`). Delete it; an unoutlined section is better than
  a noisy one.

## Bidirectional sync

Outline and code are kept in sync in both directions. This is what stops the
outline from going stale, which is the failure mode that kills hand-written
section comments.

**Code changed -> update the outline.** After editing a function that carries an
outline, re-read the outline and update any statement whose section changed.
Report the outline diff alongside the code diff.

**Outline changed -> update the code.** If a human edits a star comment, treat it
as a specification of intent and propagate:

- *Reworded statement* -> adjust the logic of that section to match.
- *New statement inserted* -> write the code for it in place.
- *Statement deleted* -> remove that section and any code elsewhere that becomes
  dead as a result.
- *Statements reordered* -> refactor, handling dataflow dependencies rather than
  literally moving lines.

Then propagate outward: fix downstream types, callers, log messages, and the
docstring. Do not stop at the local edit. The most common failure is an
**incomplete propagation** -- an edit that is locally right but leaves a caller
or type annotation stale. Before finishing, walk the call graph one hop.

Resist scope creep in the other direction too: do not "improve" a docstring or
tidy adjacent code that the change did not actually invalidate.

## Steering new code

When asked to write a substantial new function, **propose the outline first,
without code, and get agreement before implementing.** A wrong outline costs
seconds to fix; wrong code costs a debugging session. If the approach is genuinely
ambiguous, offer two outlines representing different strategies.

Skip this for small or mechanical functions.

## Reviewing a diff

An outline diff is a natural-language summary of a code change. When reviewing:

- Read the outline diff before the code diff.
- If a code section changed but its outline statement did not, that is a signal:
  either the outline is now stale, or the change did not do what its author
  thought.
- For a large change touching many files, group the changes into a handful of
  named topics, describe each in one phrase, and review topic by topic rather
  than file by file.

## When not to outline

Do not outline boilerplate, trivial getters, one-liners, derive-generated code,
or functions whose body is already self-evident from the signature. An outline
on a function nobody would struggle to read is pure noise. Outlines earn their
place on long functions, dense algorithmic code, unusual APIs, and anything a
reader must currently trace to understand.
