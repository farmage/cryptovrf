Crypto VRF module
Installation:
```
python3 setup.py install
```

Usage:

```
import cryptovrf
secret_key, public_key = cryptovrf.create_random_vrf_keys()

# now sign the data with secret key
# we're got proof and beta_string as result
proofs, beta_string = cryptovrf.vrf_sign_data(secret_key, "bla bla bla")

# let's verify just singed data
print(cryptovrf.vrf_data_verify(public_key, proof, beta_string, "bla bla bla"))
# True

# try to change the data and check will it work
print(cryptovrf.vrf_data_verify(public_key, proof, beta_string, "spoofed data"))
# False

```