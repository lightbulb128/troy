import pytroy

pytroy.initialize_kernel()

poly_modulus_degree = 1<<14
coeff_modulus_bits = [40, 40, 40, 40, 40, 40]

parameters = pytroy.EncryptionParameters(pytroy.SchemeType.ckks)
parameters.set_poly_modulus_degree(poly_modulus_degree)
parameters.set_coeff_modulus(pytroy.CoeffModulus.create(poly_modulus_degree, coeff_modulus_bits))

context = pytroy.SEALContext(parameters)

encoder = pytroy.CKKSEncoder(context)

message = [1, 2, 3, 4]
plaintext = pytroy.Plaintext()

encoder.encode(message, 1<<30, plaintext)
output = encoder.decode(plaintext)

print(output[:4])

keygen = pytroy.KeyGenerator(context)

