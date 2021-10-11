"""A tool for graphing signatures between gpg keys"""

import subprocess
from sys import stdout, stderr
from itertools import chain

from .sigs_list import *

def get_list():
    data = { 'cfg': dict(), 'pubs': list() }
    with subprocess.Popen(
        ['gpg', '-k', '--fixed-list-mode', '--with-colons', '--with-sig-list'],
        stdout=subprocess.PIPE,
        universal_newlines=True
        ) as process:

        entries = map(Entry, map(lambda l: l.strip(), process.stdout))

        # Interpret
        try:
            entry = next(entries)
            while entry:
                if entry.e_type == 'tru':
                    data['tru'] = entry
                elif entry.e_type == 'cfg':
                    cfgs = data['cfg'].get(entry.cfg_field, [])
                    cfgs.append(entry)
                    data['cfg'][entry.cfg_field] = cfgs
                elif entry.e_type == 'pub':
                    key = PubKey(entry)
                    data['pubs'].append(key)
                    entry = next(entries)
                    while entry.e_type in ('fpr', 'sub', 'sig', 'uid'):
                        if entry.e_type == 'fpr':
                            key.fpr = entry.fingerprint
                            entry = next(entries)
                        elif entry.e_type == 'uid':
                            uid = Uid(entry)
                            key.uids.append(uid)
                            entry = next(entries)
                            while entry.e_type in ('sig',):
                                uid.sigs.append(Sig(entry))
                                entry = next(entries)
                        elif entry.e_type == 'sub':
                            sub = SubKey(entry)
                            key.subs.append(sub)
                            entry = next(entries)
                            while entry.e_type in ('sig', 'fpr'):
                                if entry.e_type == 'fpr':
                                    sub.fpr = entry.fingerprint
                                elif entry.e_type == 'sig':
                                    sub.sigs.append(Sig(entry))
                                entry = next(entries)
                    continue
                else:
                    print(entry.e_type)

                entry = next(entries)
        except StopIteration:
            pass

    return data

def main(out_file=stdout, **kwargs):
    """
    Pull keys and signatures from gpg and generate a graphviz graph file

    Keyword arguments:
    - out_file: the file to write to. This function will NOT close the file.
      Defaults to `sys.stdout`.
    Superflous keyword arguments are ignored.
    """

    data = get_list()

    # {key: other signatures on this keys uids}
    other_sigs = dict(
            filter(
                # Ignore anything not in a web
                # TODO there are usecases for identifying the isolated keys
                # Maybe this should be a commandline flag
                lambda t: len(t[1]) > 0,
                map(
                    lambda k: (
                        k,
                        set(
                            chain.from_iterable(
                                map(
                                    lambda u: filter(
                                        # No self sigs
                                        lambda s: s.issuer_fpr != k.fpr,
                                        u.sigs,
                                    ),
                                    k.uids,
                                )
                            )
                        )
                    ),
                    data['pubs'],
                )
            )
        )

    # TODO it'd be nice if sigs referenced the issuer's key
    fpr_to_key = dict(map(lambda k: (k.fpr, k), data['pubs']))

    out_file.write('digraph signatures {\n')
    out_file.write('\tconcentrate=true;\n')
    out_file.write('\tcompound=true;\n')
    out_file.write('\tratio=.25;\n')
    # TODO key alignment
#    out_file.write('''
#\tsubgraph "cluster_key" {
#\t\tlabel="Key";
#\t\trank=min;
#\t\tnode [shape=point] "b1"; "b2"; "u1"; "u2";
#\t\t"b1" -> "b2" [dir=none,style=bold,label="Bidirectional Signatures"];
#\t\t"u1" -> "u2" [label="Unidirectional Signature"];
#\t}
#''')
    for key, sigs in other_sigs.items():
        for sig in sigs:
            out_file.write(f'\t"{sig.uid} ({sig.issuer_fpr})"')
            out_file.write(f' -> "{key.uids[0].uid} ({key.fpr})"')
            # Bidirectonal sigs
            if any(map(lambda s: s.issuer_fpr == key.fpr, other_sigs[fpr_to_key[sig.issuer_fpr]])):
                out_file.write('[dir=none, style=bold]')
            out_file.write(';\n')
    out_file.write('}\n')
