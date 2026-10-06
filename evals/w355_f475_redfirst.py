#!/usr/bin/env python3
"""Red-first for F475: filter over-decode on mixed-type arrays (FP direction).

The bounded static JS-expression decoder coerces numeric array elements
to strings at parse time (`str(num)` in `_js_parse_primary`), losing
type provenance. Type-dependent `.filter` predicates -- `x.length>0`
(F447 form), `x.match(/[a-z]/)` and `x.charCodeAt(IDX) OP K` (F470
forms) -- are then evaluated as if every element were a string:

  ['a',1].filter(x=>x.length>0).join('')         decoder 'a1', node 'a'
  [1,2].filter(x=>x.length>0).join('')          decoder '12', node ''
  Array(2).fill(1).filter(x=>x.length>0).join('') decoder '11', node ''
  ['a',1].filter(x=>x.match(/[a-z]/)).join('')   decoder 'a',  node THROWS
  ['a',1].filter(x=>x.charCodeAt(0)>47).join('') decoder 'a1', node THROWS

(all node ground truths verified on node v24.20.0). The decoder claims
text the real engine never produces (or produces while the engine
throws) -- a false-positive-direction over-claim. Pre-existing on the
wave-354 base (surfaced by the wave-354 merge lane, not introduced by
any closure).

Type-INDEPENDENT predicates are unaffected and stay decodable:
  ['a',1].filter(x=>x!=='').join('')  'a1' both
  ['a',1].filter(Boolean).join('')    'a1' both
  ['a','b'].filter(x=>x.length>0)     'ab' both (pure-string arrays)

Prints BREAK when the over-decode is present (open tree), HELD when the
decoder fails closed (closed tree). Controls pin the unaffected shapes.
