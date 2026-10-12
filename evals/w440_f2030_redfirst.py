"""Red-first battery for F2030: T.toString.apply(T,[]) -- .apply with empty args.

On the open tree, find_credential MISSES this shape (prints BREAK).
After the F2030 decoder lands, it must print HELD.
"""
import os
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import subprocess
import sys
import textwrap

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _run(text):
    code = textwrap.dedent("""
        import sys
        sys.path.insert(0, %r)
        from gov.dlp import find_credential
        text = open('/tmp/w440_f2030_input.js').read()
        result = find_credential(text)
        print('HIT' if result else 'MISS')
    """ % REPO)
    with open('/tmp/w440_f2030_input.js', 'w') as f:
        f.write(text)
    r = subprocess.run([sys.executable, '-c', code], capture_output=True,
                       text=True, cwd=REPO)
    return r.stdout.strip()


def main():
    cred = 'xoxb-' + 'c' * 15
    codes = ','.join(str(ord(c)) for c in cred)
    js = (
        "var C=[%s];\n"
        "var T=C.map(function(c){return String.fromCharCode(c);}).join('');\n"
        "var U=T.toString.apply(T,[]);\n"
        "var RESULT=U;\n" % codes
    )
    result = _run(js)
    if result == 'MISS':
        print("BREAK")
        return 0
    else:
        print("HELD")
        return 1


if __name__ == '__main__':
    sys.exit(main())
