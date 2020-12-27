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
