#!/usr/bin/env python3

class Entry:
    # See https://github.com/CSNW/gnupg/blob/master/doc/DETAILS
    def __init__(self, line):
        if line.startswith('tru'): # Trust base record
            self.e_type, self.staleness_reason, self.trust_model, self.create_date, self.expiration_date, self.marginals_needed, self.completes_needed, self.max_cert_depth = line.split(':')
        elif  line.startswith('spk'): # sig subpacket
            self.e_type, self.spk_number, self.flags, self.length, self.data = line.split(':')
        elif  line.startswith('cfg'): # config data
            self.e_type, self.cfg_field = line.split(':')[:2]
            data = line.split(':')[2:]
        elif line.startswith('fpr'): # fingerprint
            self.e_type, _,_,_,_,_,_,_,_,self.fingerprint = line.split(':')[:10]
        else:
            #print(line, len(line.split(':')))
            self.e_type, self.validity, self.key_len, self.algorithm, self.keyid, self.create_date, self.expiration_date, self.crt_serial_num, self.ownertrust, self.user_id, self.sig_class, self.capabilities, self.issuer_fpr_or_uid_pref, self.flag, self.token_sn, self.hash_algo, self.curve_name = line.split(':')[:17]
            #self.all_field = line.split(':')

            #self.key_len = int(self.key_len)
            #self.algorithm = int(self.algorithm)

    def __repr__(self):
        return str(self.__dict__)


class PubKey:
    pub: Entry
    fpr: str
    subs: list
    uids: list
    def __init__(self, entry):
        self.entry = entry
        self.subs = list()
        self.uids = list()

    def __repr__(self):
        return f'PubKey(fpr=\'{self.fpr}\', subs={self.subs}, uids={self.uids})'


class Uid:
    def __init__(self, entry):
        self.entry = entry
        self.sigs = list()
        self.uid = entry.user_id

    def __repr__(self):
        return f'Uid(uid=\'{self.uid}\', sigs={self.sigs})'


class SubKey:
    fpr: str
    def __init__(self, entry):
        self.entry = entry
        self.sigs = list()
    def __repr__(self):
        return f'SubKey(fpr={self.fpr}, sigs={self.sigs})'


class Sig:
    def __init__(self, entry):
        self.entry = entry
        self.uid = entry.user_id
        self.issuer_fpr = entry.issuer_fpr_or_uid_pref

    def __repr__(self):
        return f'Sig(uid=\'{self.uid}\', issuer_fpr=\'{self.issuer_fpr}\')'

# TODO revocations, trust level


import subprocess
process = subprocess.Popen(['gpg', '-k', '--fixed-list-mode', '--with-colons', '--with-sig-list'], stdout=subprocess.PIPE, universal_newlines=True)
entries = map(Entry, map(lambda l: l.strip(), process.stdout))

data = { 'cfg': dict(), 'pubs': list() }

# Interpret 
try:
    entry = next(entries)
    while(entry):
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
            while(entry.e_type in ('fpr', 'sub', 'sig', 'uid')):
                if entry.e_type == 'fpr':
                    key.fpr = entry.fingerprint
                    entry = next(entries)
                elif entry.e_type == 'uid':
                    uid = Uid(entry)
                    key.uids.append(uid)
                    entry = next(entries)
                    while(entry.e_type in ('sig',)):
                        uid.sigs.append(Sig(entry))
                        entry = next(entries)
                elif entry.e_type == 'sub':
                    sub = SubKey(entry)
                    key.subs.append(sub)
                    entry = next(entries)
                    while(entry.e_type in ('sig', 'fpr')):
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

with open('sigs.dot', 'w') as sigs_f:
    sigs_f.write('digraph signatures {\n')
    sigs_f.write('\tconcentrate=true;\n')
    sigs_f.write('\tcompound=true;\n')
    sigs_f.write('\tratio=.25;\n')
    # TODO key alignment
    sigs_f.write('''
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
                if sig_fpr == fpr:
                    sigs_f.write(f'\t"{fpr_to_uid[fpr]} ({fpr})";\n')
                    continue

                if fpr in fpr_sigs_map[sig_fpr]:
                    # Bidirectional
                    sigs_f.write(f'\t"{fpr_to_uid[fpr]} ({fpr})" -> "{fpr_to_uid[sig_fpr]} ({sig_fpr})" [dir=none, style=bold];\n')
                else:
                    sigs_f.write(f'\t"{fpr_to_uid[fpr]} ({fpr})" -> "{fpr_to_uid[sig_fpr]} ({sig_fpr})";\n')
        except:
            pass

    sigs_f.write('}')

#   - crt :: X.509 certificate
#   - crs :: X.509 certificate and private key available
#   - sec :: Secret key
#   - ssb :: Secret subkey (secondary key)
#   - uat :: User attribute (same as user id except for field 10).
#   - rev :: Revocation signature
#   - rvs :: Revocation signature (standalone) [since 2.2.9]
#   - fp2 :: SHA-256 fingerprint (fingerprint is in field 10)
#   - pkd :: Public key data [*]
#   - grp :: Keygrip
#   - rvk :: Revocation key
#   - tfs :: TOFU statistics [*]
#   - spk :: Signature subpacket [*]
