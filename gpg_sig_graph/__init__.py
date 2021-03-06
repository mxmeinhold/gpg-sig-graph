"""A tool for graphing signatures between gpg keys"""

import subprocess
from sys import stdout

from .sigs_list import *

def main(out_file=stdout, **kwargs):
    """
    Pull keys and signatures from gpg and generate a graphviz graph file

    Keyword arguments:
    - out_file: the file to write to. This function will NOT close the file.
      Defaults to `sys.stdout`.
    Superflous keyword arguments are ignored.
    """

    process = subprocess.Popen(
        ['gpg', '-k', '--fixed-list-mode', '--with-colons', '--with-sig-list'],
        stdout=subprocess.PIPE,
        universal_newlines=True
    )
    entries = map(Entry, map(lambda l: l.strip(), process.stdout))

    data = { 'cfg': dict(), 'pubs': list() }

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


    # Map a (uid, fingerprint) to all the (uid, fingerprint)s it has signed
    fpr_sigs_map = dict()
    for key in data['pubs']:
        for uid in key.uids:
            for sig in uid.sigs:
                sigs = fpr_sigs_map.get(sig.issuer_fpr, [])
                sigs.append(key.fpr)
                fpr_sigs_map[sig.issuer_fpr] = sigs

    fpr_to_uid = dict()
    for key in data['pubs']:
        fpr_to_uid[key.fpr] = key.uids[0].uid

    out_file.write('digraph signatures {\n')
    out_file.write('\tconcentrate=true;\n')
    out_file.write('\tcompound=true;\n')
    out_file.write('\tratio=.25;\n')
    # TODO key alignment
    out_file.write('''
\tsubgraph "cluster_key" {
\t\tlabel="Key";
\t\trank=min;
\t\tnode [shape=point] "b1"; "b2"; "u1"; "u2";
\t\t"b1" -> "b2" [dir=none,style=bold,label="Bidirectional Signatures"];
\t\t"u1" -> "u2" [label="Unidirectional Signature"];
\t}
''')
    for fpr in map(lambda k: k.fpr, data['pubs']):
        try:
            for sig_fpr in fpr_sigs_map[fpr]:
                out_file.write(f'\t"{fpr_to_uid[fpr]} ({fpr})"')
                if sig_fpr != fpr: # Not a self sig
                    out_file.write(f' -> "{fpr_to_uid[sig_fpr]} ({sig_fpr})"')
                    if fpr in fpr_sigs_map[sig_fpr]: # Bidirectional
                        out_file.write('[dir=none, style=bold]')
                out_file.write(';\n')
        # pylint: disable=bare-except
        except:
            pass

    out_file.write('}\n')
