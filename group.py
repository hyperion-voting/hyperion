import hashlib
import time

from threshold_crypto import KeyParameters
from gmpy2 import mpz, random_state, mpz_random, powmod, mul, f_mod, add, sub


class DHGroup:
    def __init__(self, p, g, q):
        self.p = mpz(p)
        self.g = mpz(g)
        self.q = mpz(q)

    def get_pars(self):
        par = {"p": self.p, "g": self.g, "q": self.q}
        return par

    def raise_g(self, exponent):
        return powmod(self.g, exponent, self.p)

    def get_random(self):
        seed = int(time.time() * 1000.0)
        rand_state = random_state(seed)
        return mpz_random(rand_state, self.q)

    def hash_to_mpz(self, input_string):
        hashed_string = hashlib.sha256(
            str(input_string).encode("UTF-8")
        ).hexdigest()
        return mpz("0x" + hashed_string)

    def get_random_n(self, n):
        rand_list = []
        for i in range(0, n):
            seed = int(time.time() * 1000.0)
            rand_state = random_state(seed)
            rand_list.append(mpz_random(rand_state, self.q))
        return rand_list

    def mul_mod_q(self, a, b):
        return f_mod(mul(a, b), self.q)

    def mul_mod_p(self, a, b):
        return f_mod(mul(a, b), self.p)

    def add_mod_q(self, a, b):
        return f_mod(add(a, b), self.q)

    def add_mod_p(self, a, b):
        return f_mod(add(a, b), self.p)

    def sub_mod_q(self, a, b):
        return f_mod(sub(a, b), self.q)

    def sub_mod_p(self, a, b):
        return f_mod(sub(a, b), self.p)


def pars_2048() -> KeyParameters:
    p = 23212718211223336338623627838297100776348251929620990379728283835586523792270058342736889343686329215866504815269621432837232866115176558791245177843865619800054694216410724161112387921814581439932684940829078821020334889504819701090331694359957187190718536416722072406964020706889652604053429180342877396752981788683550014616919088840960588789961265593202889897289440512729446717086636778861641962452234234749520554076827998086713716064567509795174004362093332781629567107659669538251983058846087973406038448310636920957272362896111174395380333124525480621632817319411246384029082243736043887693002745763858256560227
    q = 11606359105611668169311813919148550388174125964810495189864141917793261896135029171368444671843164607933252407634810716418616433057588279395622588921932809900027347108205362080556193960907290719966342470414539410510167444752409850545165847179978593595359268208361036203482010353444826302026714590171438698376490894341775007308459544420480294394980632796601444948644720256364723358543318389430820981226117117374760277038413999043356858032283754897587002181046666390814783553829834769125991529423043986703019224155318460478636181448055587197690166562262740310816408659705623192014541121868021943846501372881929128280113
    g = 3
    return KeyParameters(p=p, q=q, g=g)
