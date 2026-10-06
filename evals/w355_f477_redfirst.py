#!/usr/bin/env python3
"""Red-first for F477: implicit String() coercion of non-string arguments.

Real JS engines coerce non-string arguments via String() in several
decoder-modeled methods, but the static decoder fails closed on all of
them:

- ['x'].concat(123456789,'y'): numeric concat args are stringified by the
  engine; the decoder's concat branch accepts only string/spread args.
- 'x'.padStart(22,['z']): padString=String(['z'])='z'; the decoder's
  padStart accepts only literal pad strings (F465).
- 'a,b'.replace(/,/g,['']): replacement=String([''])=''; the decoder's
  replace accepts only literal-string replacements (F464).
- String(['a','b']).replace(/,/g,''): the decoder models .toString() on
  arrays (F464) but not the String() constructor call.

All four node-evaluate to the credential while the decoder produces no
variant. Distinct from F473 (array RECEIVER fail-closed) and F474
(TypeError on _JSArr args -- these shapes fail closed silently, no raise).

Dropped from the first draft (2026-10-06 takeover validation): two
repeat-coercion shapes whose receivers were the verbatim credential --
they trip the raw-text rule (HELD), so they cannot demonstrate a bypass;
a non-verbatim repeat-coercion cannot build the 21-char non-periodic
credential, documented as a scope note. The draft padStart shape was
also reworked: the original used a verbatim-credential receiver (no
padding needed, coercion unexercised); the filed shape
'123456789abcdef'.padStart(21,['xoxb-0']) forces real String(['xoxb-0])
coercion to build the credential.

Prints BREAK when a payload MISSES (open tree), HELD when blocked.
