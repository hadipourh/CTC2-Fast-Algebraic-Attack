"""
@H. Hadipour
April 13, 2019
24 Farvardin, 1398
"""
from random import randint

class CTC:
    """
    A python class implementing the Courtois Toy Cipher (CTC2),
    equipped with some methods for extracting algebraic equations
    of CTC(B, Nr, Hk) over finite field GF(2).

    CTC1 presented in https://eprint.iacr.org/2006/168,
    and it's revision which is called CTC2, presented in
    https://eprint.iacr.org/2007/152. This class is an
    implementation of CTC2.
    """
    sbox = [7, 6, 0, 4, 2, 5, 1, 3]

    def __init__(self, B, Nr, Hk):
        self.B = B   # number of sboxes in each round
        self.Bs = B * 3
        self.Nr = Nr # number of rounds
        self.Hk = Hk # size of key
        self.sbox_polynomials = ['u1*u2 + u1 + u2 + u3 + v1 + 1',
                                 'u1*u3 + u2 + v2 + 1',
                                 'u1*v1 + u2 + v2 + 1',
                                 'u1*v2 + u3 + v1 + v2',
                                 'u1 + u2*u3 + u2 + v1 + v2 + v3 + 1',
                                 'u1 + u2*v1 + u2 + v1 + v2 + v3 + 1',
                                 'u1*v3 + u1 + u2*v2',
                                 'u1*v3 + u2*v3 + u2 + u3 + v1 + 1',
                                 'u1*v3 + u3*v1 + v1 + v3',
                                 'u1 + u3*v2 + u3 + v1 + v3',
                                 'u1*v3 + u1 + u2 + u3*v3 + v2 + 1',
                                 'u1 + v1*v2 + v3',
                                 'u1 + u2 + v1*v3 + v2 + v3 + 1',
                                 'u1 + u3 + v1 + v2*v3 + v2 + v3']
        # u1 : input's lsb
        # v1 : output's lsb        
        self.sbox_input_vars = ["u1", "u2", "u3"]
        self.sbox_output_vars = ["v1", "v2", "v3"]        
        """
        variable's template:
        key :
        k_(bit_number) 
        k_0 : lsb
        k_0, k_1, k_2, ..., k_(Hk)

        input of sbox layer:
        x_(instant_number)_(round_number)_(bit_number)
        0 <= instant_number, 1 <= round_number <= Nr, 
        0 <= bit_number <= Bs
        x_ins_r_0 : lsb

        output of sbox layer:
        y_(instant_number)_(round_number)_(bit_number)
        0 <= instant_number, 1 <= round_number <= Nr, 
        0 <= bit_number <= Bs
        y_ins_r_0 : lsb

        output of diffusion layer:
        z_(instant_number)_(round_number)_(bit_number)
        0 <= instant_number, 1 <= round_number <= Nr, 
        0 <= bit_number <= Bs
        z_ins_r_0 : lsb

        example: 
        let B = 2, Nr = 2, Hk = 6, and inst = 1, then the following variablees are generated:

        plaintext:
        Z0 |z_0_0_0 z_0_0_1  z_0_0_2| |z_0_0_3  z_0_0_4  z_0_0_5|
        z_0_0_5 : msb              
        ------------------------------------------------------
        K0 |k_0     k_1      k_2    | |k_3      k_4      k_5    |

        X1 |x_0_1_0 x_0_1_1  x_0_1_2| |x_0_1_3  x_0_1_4  x_0_1_5|
           |   S       S        S   | |   S        S        S   |
        Y1 |y_0_1_0 y_0_1_1  y_0_1_2| |y_0_1_3  y_0_1_4  y_0_1_5|
           |DDDDDDDDDDDDDDDDDDDDDDDD| |DDDDDDDDDDDDDDDDDDDDDDDDD|
        Z1 |z_0_1_0 z_0_1_1  z_0_1_2| |z_0_1_3  z_0_1_4  z_0_1_5|
        K1 |k_5     k_0      k_1    | |k_2      k_3      k_4    |

        X2 |x_0_2_0 x_0_2_1  x_0_2_2| |x_0_2_3  x_0_2_4  x_0_2_5|
           |   S       S        S   | |   S        S        S   |
        Y2 |y_0_2_0 y_0_2_1  y_0_2_2| |y_0_2_3  y_0_2_4  y_0_2_5|
           |DDDDDDDDDDDDDDDDDDDDDDDD| |DDDDDDDDDDDDDDDDDDDDDDDDD|
        Z2 |z_0_2_0 z_0_2_1  z_0_2_2| |z_0_2_3  z_0_2_4  z_0_2_5|
        K2 |k_4     k_5      k_0    | |k_1      k_2      k_3    |
        ------------------------------------------------------
        ciphertext:
        X3 |x_0_3_0 x_0_3_1  x_0_3_2| |x_0_3_3  x_0_3_4  x_0_3_5|
        x_0_3_5 : msb
        """
        self.__variables = []
        
    def __repr__(self):
        return "CTC(B = %d, Nr = %d)" % (self.B, self.Nr)
    
    def get_variables(self):
        return self.__variables

    def xor_round_key(self, state, round_key):
        return state ^ round_key
    
    def s_layer(self, state):
        output = 0
        for i in range(self.B):
            output |= self.sbox[(state >> (i * 3)) & 0x7] << (i * 3)
        return output

    def d_layer(self, state):
        # (257 * 1987 + 257) = 510916
        # 137 + 257 = 394
        # 257 + 274 = 531        
        output = (((state >> (257 % self.Bs)) & 0x01) ^ ((state >> (394 % self.Bs)) & 0x1) ^ \
        ((state >> (531 % self.Bs)) & 0x1)) << (510916 % self.Bs)
        indices = list(range(self.Bs))
        indices.remove(257 % self.Bs)
        for j in indices:
            output |= (((state >> j) & 0x1) ^ ((state >> (j + 137) % self.Bs) & 0x1))\
             << ((j * 1987 + 257) % self.Bs)
        return output

    def round_key_gen(self, k, i):
        round_key = 0
        for j in range(self.Bs):
                round_key |= ((k >> (j + i * 509) % self.Hk) & 0x1) << j
        return round_key
            
    def __call__(self, k, p):
        # encrypt plaintext "p" with the key "k"
        state  = self.xor_round_key(p, k)
        for i in range(1, self.Nr + 1):
            state = self.s_layer(state)
            state = self.d_layer(state)
            round_key = self.round_key_gen(k, i)
            state = self.xor_round_key(state, round_key)
        return state
    
    def random_plaintext(self):
        plain = randint(0, (1 << self.Bs) - 1)
        return plain
    
    def random_key(self):
        key = randint(0, (1 << self.Hk) - 1)
        return key

    def number2vector(self, s):
        output = bin(s)[2:].zfill(self.Bs)
        output = [int(output[i]) for i in range(self.Bs)]
        output.reverse()
        return output

    def display(self, data, format, length = None):
        assert (format in  {"bin", "hex"}), "format should be one of these : \"bin\" or \"hex\""
        if (length == None):
            length = self.Bs
        if (format == "bin"):
            return bin(data)[2:].zfill(length)
        else:
            return hex(data)[2:].zfill(length)        
    
    def variable_generator(self, r, prefix, inst_number):
        # r = round number
        # prefix_(inst_number)_(round_number)_(bit_number)_()
        output = [prefix + "_" + str(inst_number) + "_" + str(r) + "_" + str(bit_number)                        
            for bit_number in range(self.Bs)]
        self.__variables.extend(output)
        return output
    
    def key_vars_generator(self, i):
        # i = round number
        output = ["k_" + str((j + (i * 509)) % self.Hk) for j in range(self.Hk)]        
        return output
        
    def single_sbox_poly_gen(self, vi, vo):
        output = []
        for f in self.sbox_polynomials:
            for i in range(3):
                f = f.replace(self.sbox_input_vars[i], vi[i])
                f = f.replace(self.sbox_output_vars[i], vo[i])
            output.append(f)
        return output
            
    def slayer_polynomials(self, input_vars, output_vars):
        equations = []
        for i in range(self.B):
            temp_input = input_vars[3 * i : 3 * i + 3]
            temp_output = output_vars[3 * i : 3 * i + 3]
            equations.extend(self.single_sbox_poly_gen(temp_input, temp_output))
        return equations
    
    def dlayer_polynomials(self, input_vars, output_vars):
        equations = []
        for j in range(self.Bs):
            if (j  == (257 % self.Bs)):
                equations.append(output_vars[(j * 1987 + 257) % self.Bs] + " + " +  input_vars[j] + " + " +  input_vars[(j + 137) % self.Bs] 
                + " + " + input_vars[(j + 274) % self.Bs])
            else:
                equations.append(output_vars[(j * 1987 + 257) % self.Bs] + " + " + input_vars[j] + " + " + input_vars[(j + 137) % self.Bs])
        return equations
    
    def key_mixing_polynomials(self, key_vars, input_vars, output_vars):
        equations = [0]*self.Bs
        for i in range(self.Bs):
            equations[i] = key_vars[i] + " + " + input_vars[i] + " + " + output_vars[i]
        return equations
    
    def boundary_condition(self, vars, values):
        output = [0]*self.Bs
        for i in range(self.Bs):
            output[i] = vars[i] + " + " + str(values[i])
        return output

    def polynomials(self, plaintexts = None, ciphertexts = None, number_of_instances = 1):
        self.__variables = []
        if ((plaintexts != None) and (ciphertexts != None)):
            number_of_instances = len(plaintexts)
            assert (number_of_instances == len(ciphertexts)), "plaintexts and ciphertexts\
            must have the same size"            
            case = 0
        elif ((plaintexts == None) and (ciphertexts == None)):
            plaintexts = [self.random_plaintext() for i in range(number_of_instances)]
            key = self.random_key()
            ciphertexts = [self.__call__(key, plaintexts[i]) for i in range(number_of_instances)]
            case = 1
        else:
            return "both plaintexts and ciphertexts must be given!"
        plaintexts = [self.number2vector(plaintexts[i]) for i in range(number_of_instances)]
        ciphertexts = [self.number2vector(ciphertexts[i]) for i in range(number_of_instances)]
        key_vars = self.key_vars_generator(0)
        self.__variables.extend(key_vars)
        system_of_equations = []
        for instance_number in range(number_of_instances):
            plain_vars = self.variable_generator(0, "z", instance_number)
            system_of_equations.extend(self.boundary_condition(plain_vars, plaintexts[instance_number]))            
            sbox_input_vars = self.variable_generator(1, "x", instance_number)
            system_of_equations.extend(self.key_mixing_polynomials(key_vars, plain_vars, sbox_input_vars))
            for r in range(1, self.Nr + 1):                                
                sbox_output_vars = self.variable_generator(r, "y", instance_number)
                system_of_equations.extend(self.slayer_polynomials(sbox_input_vars, sbox_output_vars))
                dlayer_output_vars = self.variable_generator(r, "z", instance_number)
                system_of_equations.extend(self.dlayer_polynomials(sbox_output_vars, dlayer_output_vars))
                round_key_vars = self.key_vars_generator(r)
                sbox_input_vars = self.variable_generator(r + 1, "x", instance_number)
                system_of_equations.extend(self.key_mixing_polynomials(round_key_vars, dlayer_output_vars, sbox_input_vars))
            system_of_equations.extend(self.boundary_condition(sbox_input_vars, ciphertexts[instance_number]))
        
        if (case == 0):
            return system_of_equations
        else:
            return key, system_of_equations

if __name__== '__main__':
    #######################
    B = 2
    Nr = 3
    Hk = B * 3
    ctc = CTC(B, Nr, Hk)
    key = ctc.random_key()
    p = ctc.random_plaintext()    
    c = ctc(key, p)                    
    ps = ctc.polynomials(plaintexts=[p], ciphertexts=[c])
    print(ctc)    
    print("key = %s" % ctc.display(key, "bin", length = ctc.Hk))
    print(ps)
    #######################
    B = 3
    Nr = 5
    Hk = B * 3
    ctc = CTC(B, Nr, Hk)    
    key, ps = ctc.polynomials(number_of_instances=2)
    print(ctc)    
    print(ctc.display(key, "bin", length = ctc.Hk))
    print(ps)
