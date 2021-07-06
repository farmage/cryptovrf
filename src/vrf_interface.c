#include <Python.h>

#include <sys/random.h>
#include "convert.h"
#include "vrf.h"
#include "crypto_vrf.h"

void bin_to_hex(const unsigned char* bin_data, int data_size, char* buf) {
    const char * hex = "0123456789abcdef";

    const unsigned char * p_in = bin_data;
    char * p_out = buf;
    int bin_size = data_size;
    while(bin_size-- > 0) {
        *p_out++ = hex[(*p_in>>4) & 0xF];
        *p_out++ = hex[ *p_in     & 0xF];
        p_in++;
    }
    *p_out = 0;    
}


int hex_to_bin(const char* hex_str, unsigned char* out_buf) {
    unsigned char c;
    unsigned char d;
    while(*hex_str) {
        c = (unsigned char) *hex_str++;
        if (c >='0' && c <='9') {
            d = (c - '0') << 4;
        }else if ( c >= 'A' && c <= 'F') {
            d = (c - 'A' + 10) << 4;
        }else if ( c >= 'a' && c <= 'f') {
            d = (c - 'a' + 10) << 4;
        }else {
            return 0;
        };

        c = (unsigned char) *hex_str++;
        if (c >='0' && c <='9') {
            d |= c - '0';
        }else if ( c >= 'A' && c <= 'F') {
            d |= c - 'A' + 10;
        }else if ( c >= 'a' && c <= 'f') {
            d |= c - 'a' + 10;
        }else {
            return 0;
        };

        *out_buf++ = d;
    }
    return 1;
}


static PyObject *method_create_random_vrf_keys(PyObject *self, PyObject *args) {
// int create_random_VRF_keys(unsigned char *public_key, unsigned char *secret_key) {

    unsigned char vrf_secret_key_data[crypto_vrf_SECRETKEYBYTES+1];
    unsigned char vrf_public_key_data[crypto_vrf_PUBLICKEYBYTES+1];

    char vrf_secret_key[crypto_vrf_SECRETKEYBYTES*2+1];
    char vrf_public_key[crypto_vrf_PUBLICKEYBYTES*2+1];

    unsigned char seed_data[crypto_vrf_SEEDBYTES+1];

    // memset(vrf_secret_key,0,sizeof(vrf_secret_key)); 
    // memset(vrf_public_key,0,sizeof(vrf_public_key)); 
    memset(vrf_secret_key_data,0,sizeof(vrf_secret_key_data)); 
    memset(vrf_public_key_data,0,sizeof(vrf_public_key_data)); 

    // generate seed
    if (getrandom(seed_data,crypto_vrf_SEEDBYTES,0) != crypto_vrf_SEEDBYTES)
    {

        PyErr_SetString(PyExc_RuntimeError, "Can' generate seed data");
        return NULL;
    }

    // create the VRF private and secret key
    crypto_vrf_keypair_from_seed(vrf_public_key_data, vrf_secret_key_data, seed_data);
  
    if (!crypto_vrf_is_valid_key((const unsigned char*)vrf_public_key_data))
    {
        PyErr_SetString(PyExc_RuntimeError, "Can't verify generated keys");
        return NULL;
    }

    bin_to_hex(vrf_secret_key_data, crypto_vrf_SECRETKEYBYTES, vrf_secret_key);
    bin_to_hex(vrf_public_key_data, crypto_vrf_PUBLICKEYBYTES, vrf_public_key);
    
    return Py_BuildValue("(ss)", vrf_secret_key, vrf_public_key);
}


static PyObject *method_vrf_sign_data(PyObject *self, PyObject *args) {
// int vrf_sign_data(char *beta_string, char *proof, const char* data) {
    unsigned char proof_data[crypto_vrf_PROOFBYTES+1];
    unsigned char beta_string_data[crypto_vrf_OUTPUTBYTES+1];
    unsigned char secret_key_data[crypto_vrf_SECRETKEYBYTES];

    char proof_data_str[crypto_vrf_PROOFBYTES*2+1];
    char beta_string_data_str[crypto_vrf_OUTPUTBYTES*2+1];

    char *secret_key, *data_str = NULL;
    memset(proof_data,0,sizeof(proof_data));
    memset(beta_string_data,0,sizeof(beta_string_data));



    if(!PyArg_ParseTuple(args, "ss", &secret_key, &data_str)) {
        PyErr_SetString(PyExc_ValueError, "Can't parse arguments");
        return NULL;
    }

    if (strlen(secret_key)/2 != crypto_vrf_SECRETKEYBYTES) {
        PyErr_SetString(PyExc_ValueError, "Invalid secret key length");
        return NULL;
    }

    // convert hext string to bin data
    if (!hex_to_bin(secret_key, secret_key_data)){
        PyErr_SetString(PyExc_ValueError, "Invalid secret key data");
        return NULL;
    }

    // sign data
    if (crypto_vrf_prove(proof_data,
                        (const unsigned char*)secret_key_data,
                        (const unsigned char*)data_str,
                        (unsigned long long)strlen(data_str)) != 0 || 
        crypto_vrf_proof_to_hash((unsigned char*)beta_string_data,(const unsigned char*)proof_data) != 0)
    {
        PyErr_SetString(PyExc_RuntimeError, "Can't sign data");
        return NULL;
    }

    // convert bin data to hex string
    bin_to_hex(proof_data, crypto_vrf_PROOFBYTES, proof_data_str);
    bin_to_hex(beta_string_data, crypto_vrf_OUTPUTBYTES, beta_string_data_str);

    return Py_BuildValue("(ss)", proof_data_str, beta_string_data_str);

}

static PyObject *method_vrf_data_verify(PyObject *self, PyObject *args) {
// arguments: public_key, proof_data_str, beta_string, data_str
// int VRF_data_verify(const char* BLOCK_VERIFIERS_PUBLIC_KEY, const char* BLOCK_VERIFIERS_DATA_SIGNATURE, const char* DATA) {
    unsigned char public_key_data[crypto_vrf_PUBLICKEYBYTES+1];
    unsigned char proof_data[crypto_vrf_PROOFBYTES+1];
    unsigned char beta_string_data[crypto_vrf_OUTPUTBYTES+1];

    char *public_key, *proof_data_str, *beta_string,  *data_str = NULL;

    memset(public_key_data,0,sizeof(public_key_data));
    memset(proof_data,0,sizeof(proof_data));
    memset(beta_string_data,0,sizeof(beta_string_data));


    if(!PyArg_ParseTuple(args, "ssss", &public_key, &proof_data_str, &beta_string, &data_str)) {
        PyErr_SetString(PyExc_ValueError, "Can't parse arguments");
        return NULL;
    }

    if (strlen(public_key)/2 != crypto_vrf_PUBLICKEYBYTES) {
        PyErr_SetString(PyExc_ValueError, "Invalid public_key length");
        return NULL;
    }

    if (strlen(proof_data_str)/2 != crypto_vrf_PROOFBYTES) {
        PyErr_SetString(PyExc_ValueError, "Invalid proof_data length");
        return NULL;
    }

    if (strlen(beta_string)/2 != crypto_vrf_OUTPUTBYTES) {
        PyErr_SetString(PyExc_ValueError, "Invalid beta_string length");
        return NULL;
    }

    // convert hext string to bin data
    if (!hex_to_bin(public_key, public_key_data)){
        PyErr_SetString(PyExc_ValueError, "Invalid public_key data");
        return NULL;
    }

    // convert hext string to bin data
    if (!hex_to_bin(proof_data_str, proof_data)){
        PyErr_SetString(PyExc_ValueError, "Invalid proof_data data");
        return NULL;
    }

    // convert hext string to bin data
    if (!hex_to_bin(beta_string, beta_string_data)){
        PyErr_SetString(PyExc_ValueError, "Invalid beta_string data");
        return NULL;
    }

    if (crypto_vrf_verify(beta_string_data,
                            public_key_data,
                            proof_data,
                            (const unsigned char*)data_str,
                            (unsigned long long)strlen(data_str)))
    {                        
        // verification is not passed
        Py_RETURN_FALSE;
    }

    Py_RETURN_TRUE;
}

static PyMethodDef VrfMethods[] = {
    {"create_random_vrf_keys", method_create_random_vrf_keys, METH_VARARGS, "Retruns tuple of secret and public random generated keys"},
    // {"generate_key", method_generate_key, METH_VARARGS, "Python interface for vrf... unction"},
    // {"sign_network_block_string", method_sign_network_block_string, METH_VARARGS, "Python interface for vrf... unction"},
    {"vrf_sign_data", method_vrf_sign_data, METH_VARARGS, "Return tuple proof_data_str, beta_string_data_str"},
    {"vrf_data_verify", method_vrf_data_verify, METH_VARARGS, "arguments: public_key, proof_data_str, beta_string, data_str"},
    {NULL, NULL, 0, NULL}
};


static struct PyModuleDef vrfmodule = {
    PyModuleDef_HEAD_INIT,
    "cryptovrf",
    "Python interface for the crypto VRF functions",
    -1,
    VrfMethods
};

PyMODINIT_FUNC PyInit_cryptovrf(void) {
    return PyModule_Create(&vrfmodule);
}
