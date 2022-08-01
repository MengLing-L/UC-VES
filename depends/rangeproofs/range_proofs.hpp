/****************************************************************************
this hpp implements NIZKPoK for discrete logarithm equality 
*****************************************************************************
* @author     This file is part of PGC, developed by Yu Chen
* @paper      https://eprint.iacr.org/2019/319
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/
#ifndef __RANGE__
#define __RANGE__
/*#include <HsFFI.h>
#include "/root/Three-Square/3squares-ffi_stub.h"
#ifdef __GLASGOW_HASKELL__
#include </root/Three-Square/3squares-ffi_stub.h>
#endif*/
#define BHJL_HE_MR_INTERATIONS 16
#include "../common/global.hpp"
#include "../common/hash.hpp"
#include "../common/print.hpp"
#include "../common/routines.hpp"
#include <map>
#include <gmp.h>


void mods(mpz_srcptr a, mpz_srcptr n, mpz_ptr aout){
    mpz_t tmp;
    mpz_init(tmp);
    mpz_set (aout, a);
    mpz_mod (aout, aout, n);
    mpz_mul_ui (tmp, aout, 2);

    if(mpz_cmp (tmp, n) > 0){
        mpz_sub (aout, aout, n);
    }
    mpz_clear(tmp);
}

/*
def powmods(a, r, n):
    out = 1
    while r > 0:
        if (r % 2) == 1:
            r -= 1
            out = mods(out * a, n)
        r //= 2
        a = mods(a * a, n)
    return out*/
void powmods(mpz_srcptr a, mpz_srcptr r, mpz_srcptr n, mpz_ptr out){
    mpz_t rem, tmp_r, out_a, tmp_a, a_a;
    mpz_init(rem);
    mpz_init(tmp_r);
    mpz_init(out_a);
    mpz_init(tmp_a);
    mpz_init(a_a);
    mpz_set (tmp_r, r);
    mpz_set_ui (out, 1);
    mpz_set (tmp_a, a);
    while(mpz_cmp_ui (tmp_r, 0) > 0){
        mpz_mod_ui (rem, tmp_r, 2);
        if(mpz_cmp_ui (rem, 1) == 0){
            mpz_sub_ui (tmp_r, tmp_r, 1);
            mpz_mul (out_a, out, tmp_a);
            mods(out_a, n, out);
        }
        mpz_fdiv_q_ui (tmp_r, tmp_r, 2);
        mpz_mul (a_a, tmp_a, tmp_a);
        mods(a_a, n, tmp_a);
    }
    mpz_clear(rem);
    mpz_clear(tmp_r);
    mpz_clear(out_a);
    mpz_clear(tmp_a);
    mpz_clear(a_a);
}
/*
def quos(a, n):
    if n <= 0:
        return "negative modulus"
    return (a - mods(a, n))//n
*/

void quos(mpz_srcptr a, mpz_srcptr n, mpz_ptr out){

    if (mpz_cmp_ui (n, 0) <= 0){
        cout << "quos n <=0" << endl;
    }

    mods(a, n, out);

    mpz_sub (out, a, out);

    mpz_fdiv_q (out, out, n);    

}

/*
def grem(w, z):
    # remainder in Gaussian integers when dividing w by z
    (w0, w1) = w
    (z0, z1) = z
    n = z0 * z0 + z1 * z1
    if n == 0:
        return "division by zero"
    u0 = quos(w0 * z0 + w1 * z1, n)
    u1 = quos(w1 * z0 - w0 * z1, n)
    return(w0 - z0 * u0 + z1 * u1,
           w1 - z0 * u1 - z1 * u0)
*/

void grem(mpz_srcptr w0, mpz_srcptr w1, mpz_srcptr z0, mpz_srcptr z1, mpz_ptr x1, mpz_ptr x2){
    mpz_t tmp_n, tmp_z0z0, tmp_z1z1, tmp_w0z0, tmp_w1z1, tmp_w1z0, tmp_w0z1, tmp_add, tmp_add1, u0, u1, z0u0, z1u1, z0u1, z1u0;
    mpz_init(tmp_n);
    mpz_init(tmp_z0z0);
    mpz_init(tmp_z1z1);
    mpz_init(tmp_w0z0);
    mpz_init(tmp_w1z1);
    mpz_init(tmp_w1z0);
    mpz_init(tmp_w0z1);
    mpz_init(tmp_add);
    mpz_init(tmp_add1);
    mpz_init(u0);
    mpz_init(u1);
    mpz_init(z0u0);
    mpz_init(z1u1);
    mpz_init(z0u1);
    mpz_init(z1u0);

    mpz_mul (tmp_z0z0, z0, z0);
    mpz_mul (tmp_z1z1, z1, z1);

    mpz_add (tmp_n, tmp_z0z0, tmp_z1z1);

    if (mpz_cmp_ui (tmp_n, 0) == 0){
        cout << "grem n ==0" << endl;
    }

    mpz_mul (tmp_w0z0, w0, z0);
    mpz_mul (tmp_w1z1, w1, z1);

    mpz_add (tmp_add, tmp_w0z0, tmp_w1z1);

    mpz_mul (tmp_w1z0, w1, z0);
    mpz_mul (tmp_w0z1, w0, z1);

    mpz_sub (tmp_add1, tmp_w1z0, tmp_w0z1);

    quos(tmp_add, tmp_n, u0);
    quos(tmp_add1, tmp_n, u1);

    mpz_mul (z0u0, z0, u0);
    mpz_mul (z1u1, z1, u1);
    mpz_mul (z0u1, z0, u1);
    mpz_mul (z1u0, z1, u0);

    mpz_sub (x1, w0, z0u0);
    mpz_add (x1, x1, z1u1);

    mpz_sub (x2, w1, z0u1);
    mpz_add (x2, x2, z1u0);

    mpz_clear(tmp_n);
    mpz_clear(tmp_z0z0);
    mpz_clear(tmp_z1z1);
    mpz_clear(tmp_w0z0);
    mpz_clear(tmp_w1z1);
    mpz_clear(tmp_w1z0);
    mpz_clear(tmp_w0z1);
    mpz_clear(tmp_add);
    mpz_clear(tmp_add1);
    mpz_clear(u0);
    mpz_clear(u1);
    mpz_clear(z0u0);
    mpz_clear(z1u1);
    mpz_clear(z0u1);
    mpz_clear(z1u0);
}

/*
def ggcd(w, z):
    while z != (0,0):
        w, z = z, grem(w, z)
    return w
*/

void ggcd(mpz_srcptr w0, mpz_srcptr w1, mpz_srcptr z0, mpz_srcptr z1, mpz_ptr out_w0, mpz_ptr out_w1){
    mpz_t tmp_z0, tmp_z1, tmp_w0, tmp_w1, out_z0, out_z1;
    mpz_init(tmp_z0);
    mpz_init(tmp_z1);
    mpz_init(tmp_w0);
    mpz_init(tmp_w1);
    mpz_init(out_z0);
    mpz_init(out_z1);
    mpz_set (tmp_z0, z0);
    mpz_set (tmp_z1, z1);
    mpz_set (tmp_w0, w0);
    mpz_set (tmp_w1, w1);

    while(mpz_cmp_ui (tmp_z0, 0) != 0  && mpz_cmp_ui (tmp_z1, 0) != 0){
        grem(tmp_w0, tmp_w1, tmp_z0, tmp_z1, out_z0, out_z1);
        mpz_set (out_w0, tmp_z0);
        mpz_set (out_w1, tmp_z1);

        mpz_set (tmp_z0, out_z0);
        mpz_set (tmp_z1, out_z1);
        mpz_set (tmp_w1, out_w1);
        mpz_set (tmp_w0, out_w0);
    }
    mpz_clear(tmp_z0);
    mpz_clear(tmp_z1);
    mpz_clear(tmp_w0);
    mpz_clear(tmp_w1);
    mpz_clear(out_z0);
    mpz_clear(out_z1);
}

/*
def root4(p):
    # 4th root of 1 modulo p
    if p <= 1:
        return "too small"
    if (p % 4) != 1:
        return "not congruent to 1"
    k = p//4
    j = 2
    while True:
        a = powmods(j, k, p)
        b = mods(a * a, p)
        if b == -1:
            return a
        if b != 1:
            return "not prime"
        j += 1
*/

void root4(mpz_srcptr p, mpz_ptr a){
    mpz_t k,j,a_a, b;
    mpz_init(k);
    mpz_init(j);
    mpz_init(a_a);
    mpz_init(b);
    mpz_fdiv_q_ui (k, p, 4);
    mpz_set_ui (j, 2);

    while (true)
    {
        powmods(j, k, p, a);
        mpz_mul (a_a, a, a);
        mods(a_a, p, b);
        if(mpz_cmp_si (b, -1) == 0){
            break;
        }
        if(mpz_cmp_ui (b, 1) != 0){
            cout << "root4 not prime" << endl;
            break;
        }
        mpz_add_ui (j, j, 1);
    }

    mpz_clear(k);
    mpz_clear(j);
    mpz_clear(a_a);
    mpz_clear(b);
}

void find_three_squares(mpz_srcptr n, mpz_ptr x0, mpz_ptr x1, mpz_ptr x2){
    mpz_t a, zero, one, seed, p, rem, root;
    mpz_init(a);
    mpz_init(zero);
    mpz_init(one);
    mpz_init(p);
    mpz_init(rem);
    mpz_init(seed);
    mpz_init(root);

    gmp_randstate_t prng;
    gmp_randinit_mt(prng);
    //mpz_set_ui(seed, 5489L);
    mpz_set_ui(seed, 45634L);
    gmp_randseed(prng, seed);

    mpz_set_ui (zero, 0);
    mpz_set_ui (one, 1);

    mpz_sqrt (root, n);
    size_t bits = mpz_sizeinbase(root, 2);
    int i=1;
    
    do{
        while(true){
            //mpz_set_ui(seed, 84 + i);
            //gmp_randseed_ui (prng, time(NULL));
            mpz_urandomb(x0, prng, bits);
            //gmp_printf ("%Zd:", x0);
            if (mpz_cmp(x0, root) < 0) {
                break;
            }
        }
        mpz_mul (p, x0, x0);
        mpz_sub (p, n, p);
        mpz_mod_ui (rem, p, 4);
    }while(!mpz_probab_prime_p(p, BHJL_HE_MR_INTERATIONS) || mpz_cmp_ui (rem, 1) != 0 || mpz_cmp_ui (p, 0) <= 0);

    root4(p, a);

    ggcd(p, zero, a, one, x1, x2);
    
    mpz_clear(a);
    mpz_clear(zero);
    mpz_clear(one);
    mpz_clear(p);
    mpz_clear(rem);
    mpz_clear(seed);
    mpz_clear(root);
    gmp_randclear (prng);
}

/*
def mods(a, n):
    if n <= 0:
        return "negative modulus"
    a = a % n
    if (2 * a > n):
        a -= n
    return a
*/

void mods(const BIGNUM * a, const BIGNUM * n, BIGNUM * aout){
    BIGNUM * tmp = BN_new();
    
    BN_copy (aout, a);
    BN_mod (aout, aout, n, bn_ctx);
    BN_mul (tmp, aout, BN_2, bn_ctx);

    if(BN_cmp (tmp, n) > 0){
        BN_sub (aout, aout, n);
    }
    BN_free(tmp);
}

/*
def powmods(a, r, n):
    out = 1
    while r > 0:
        if (r % 2) == 1:
            r -= 1
            out = mods(out * a, n)
        r //= 2
        a = mods(a * a, n)
    return out*/
void powmods(const BIGNUM * a, const BIGNUM * r, const BIGNUM * n, BIGNUM * out){
    BIGNUM * rem = BN_new();
    BIGNUM * tmp_r = BN_new();
    BIGNUM * out_a = BN_new(); 
    BIGNUM * tmp_a= BN_new();
    BIGNUM * a_a= BN_new();
    BIGNUM * ignore_r= BN_new();
    BN_copy (tmp_r, r);
    BN_set_word (out, 1);
    BN_copy (tmp_a, a);
    while(BN_cmp (tmp_r, BN_0) > 0){
        BN_mod (rem, tmp_r, BN_2, bn_ctx);
        if(BN_cmp (rem, BN_1) == 0){
            BN_sub (tmp_r, tmp_r, BN_1);
            BN_mul (out_a, out, tmp_a, bn_ctx);
            mods(out_a, n, out);
        }
        BN_div (tmp_r, ignore_r, tmp_r, BN_2, bn_ctx);
        BN_mul (a_a, tmp_a, tmp_a, bn_ctx);
        mods(a_a, n, tmp_a);
    }
    BN_free(rem);
    BN_free(tmp_r);
    BN_free(out_a);
    BN_free(tmp_a);
    BN_free(a_a);
    BN_free(ignore_r);
}
/*
def quos(a, n):
    if n <= 0:
        return "negative modulus"
    return (a - mods(a, n))//n
*/

void quos(const BIGNUM * a, const BIGNUM * n, BIGNUM * out){
    BIGNUM * ignore_r= BN_new();

    mods(a, n, out);

    BN_sub (out, a, out);

    BN_div (out, ignore_r, out, n, bn_ctx);    

    BN_free(ignore_r);
}

/*
def grem(w, z):
    # remainder in Gaussian integers when dividing w by z
    (w0, w1) = w
    (z0, z1) = z
    n = z0 * z0 + z1 * z1
    if n == 0:
        return "division by zero"
    u0 = quos(w0 * z0 + w1 * z1, n)
    u1 = quos(w1 * z0 - w0 * z1, n)
    return(w0 - z0 * u0 + z1 * u1,
           w1 - z0 * u1 - z1 * u0)
*/

void grem(const BIGNUM * w0, const BIGNUM * w1, const BIGNUM * z0, const BIGNUM * z1, BIGNUM * x1, BIGNUM * x2){
    BIGNUM * tmp_n = BN_new();
    BIGNUM * tmp_z0z0 = BN_new(); 
    BIGNUM * tmp_z1z1 = BN_new(); 
    BIGNUM * tmp_w0z0 = BN_new(); 
    BIGNUM * tmp_w1z1 = BN_new(); 
    BIGNUM * tmp_w1z0= BN_new(); 
    BIGNUM * tmp_w0z1= BN_new(); 
    BIGNUM * tmp_add= BN_new(); 
    BIGNUM * tmp_add1= BN_new(); 
    BIGNUM * u0= BN_new(); 
    BIGNUM * u1= BN_new();  
    BIGNUM * z0u0= BN_new(); 
    BIGNUM * z1u1= BN_new(); 
    BIGNUM * z0u1= BN_new(); 
    BIGNUM * z1u0= BN_new(); 
   

    BN_mul (tmp_z0z0, z0, z0, bn_ctx);
    BN_mul (tmp_z1z1, z1, z1, bn_ctx);

    BN_add (tmp_n, tmp_z0z0, tmp_z1z1);

    BN_mul (tmp_w0z0, w0, z0, bn_ctx);
    BN_mul (tmp_w1z1, w1, z1, bn_ctx);

    BN_add (tmp_add, tmp_w0z0, tmp_w1z1);

    BN_mul (tmp_w1z0, w1, z0, bn_ctx);
    BN_mul (tmp_w0z1, w0, z1, bn_ctx);

    BN_sub (tmp_add1, tmp_w1z0, tmp_w0z1);

    quos(tmp_add, tmp_n, u0);
    quos(tmp_add1, tmp_n, u1);

    BN_mul (z0u0, z0, u0, bn_ctx);
    BN_mul (z1u1, z1, u1, bn_ctx);
    BN_mul (z0u1, z0, u1, bn_ctx);
    BN_mul (z1u0, z1, u0, bn_ctx);

    BN_sub (x1, w0, z0u0);
    BN_add (x1, x1, z1u1);

    BN_sub (x2, w1, z0u1);
    BN_add (x2, x2, z1u0);

    BN_free(tmp_n);
    BN_free(tmp_z0z0);
    BN_free(tmp_z1z1);
    BN_free(tmp_w0z0);
    BN_free(tmp_w1z1);
    BN_free(tmp_w1z0);
    BN_free(tmp_w0z1);
    BN_free(tmp_add);
    BN_free(tmp_add1);
    BN_free(u0);
    BN_free(u1);
    BN_free(z0u0);
    BN_free(z1u1);
    BN_free(z0u1);
    BN_free(z1u0);
}

/*
def ggcd(w, z):
    while z != (0,0):
        w, z = z, grem(w, z)
    return w
*/

void ggcd(const BIGNUM * w0, const BIGNUM * w1, const BIGNUM * z0, const BIGNUM * z1, BIGNUM * out_w0, BIGNUM * out_w1){
    BIGNUM * tmp_z0 = BN_new();
    BIGNUM * tmp_z1 = BN_new();
    BIGNUM * tmp_w0 = BN_new(); 
    BIGNUM * tmp_w1 = BN_new();
    BIGNUM * out_z0 = BN_new(); 
    BIGNUM * out_z1 = BN_new();

    BN_copy (tmp_z0, z0);
    BN_copy (tmp_z1, z1);
    BN_copy (tmp_w0, w0);
    BN_copy (tmp_w1, w1);

    while(BN_cmp (tmp_z0, BN_0) != 0  && BN_cmp (tmp_z1, BN_0) != 0){
        grem(tmp_w0, tmp_w1, tmp_z0, tmp_z1, out_z0, out_z1);
        BN_copy (out_w0, tmp_z0);
        BN_copy (out_w1, tmp_z1);

        BN_copy (tmp_z0, out_z0);
        BN_copy (tmp_z1, out_z1);
        BN_copy (tmp_w1, out_w1);
        BN_copy (tmp_w0, out_w0);
    }
    BN_free(tmp_z0);
    BN_free(tmp_z1);
    BN_free(tmp_w0);
    BN_free(tmp_w1);
    BN_free(out_z0);
    BN_free(out_z1);
}

/*
def root4(p):
    # 4th root of 1 modulo p
    if p <= 1:
        return "too small"
    if (p % 4) != 1:
        return "not congruent to 1"
    k = p//4
    j = 2
    while True:
        a = powmods(j, k, p)
        b = mods(a * a, p)
        if b == -1:
            return a
        if b != 1:
            return "not prime"
        j += 1
*/

void root4(const BIGNUM * p, BIGNUM * a){
    BIGNUM * k = BN_new();
    BIGNUM * j = BN_new();
    BIGNUM * a_a = BN_new();
    BIGNUM * b = BN_new();
    BIGNUM * ignore_r = BN_new();
    BIGNUM * BN_4 = BN_new();
    BIGNUM * NEGONE = BN_new();
    BN_set_word (BN_4, 4);
    BN_set_word (NEGONE, 1);
    BN_set_negative (NEGONE, 1);

    BN_div (k, ignore_r, p, BN_4, bn_ctx);
    BN_set_word (j, 2);

    while (true)
    {
        powmods(j, k, p, a);
        BN_mul (a_a, a, a, bn_ctx);
        mods(a_a, p, b);
        if(BN_cmp (b, NEGONE) == 0){
            break;
        }
        BN_add (j, j, BN_1);
    }

    BN_free(k);
    BN_free(j);
    BN_free(a_a);
    BN_free(b);
}

void find_three_squares(const BIGNUM * n, BIGNUM * x0, BIGNUM * x1, BIGNUM * x2){
    BIGNUM *a = BN_new();
    BIGNUM *zero = BN_new();
    BIGNUM *one = BN_new();
    BIGNUM *seed = BN_new();
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *rem = BN_new();
    BIGNUM *root = BN_new();
    BIGNUM *BN_4 = BN_new();
    

    BN_set_word (zero, 0);
    BN_set_word (BN_4, 4);
    BN_set_word (one, 1);

    int bits = BN_num_bits(n);
    BN_generate_prime(q, bits+2, false, NULL, NULL, NULL, NULL);
    BN_mod_sqrt (root, n, q, bn_ctx);
    
    do{
        while(true){
            BN_random(x0);
            BN_mod (x0, x0, root, bn_ctx);
            if (BN_cmp(x0, root) < 0) {
                break;
            }
        }
        BN_mul (p, x0, x0, bn_ctx);
        BN_sub (p, n, p);
        BN_mod (rem, p, BN_4, bn_ctx);
    }while(!BN_is_prime(p, 128, NULL, bn_ctx, NULL) || BN_cmp (rem, BN_1) != 0 || BN_cmp(p, BN_0) <= 0);

    root4(p, a);

    ggcd(p, zero, a, one, x1, x2);

    BN_free(a);
    BN_free(zero);
    BN_free(one);
    BN_free(p);
    BN_free(rem);
    BN_free(seed);
    BN_free(root);
}

unsigned long int hex2int(const char *hex) {
    unsigned long int val = 0;
    while (*hex) {
        // get current character then increment
        uint8_t byte = *hex++; 
        // transform hex character to the 4bit equivalent number, using the ascii table indexes
        if (byte >= '0' && byte <= '9') byte = byte - '0';
        else if (byte >= 'a' && byte <='f') byte = byte - 'a' + 10;
        else if (byte >= 'A' && byte <='F') byte = byte - 'A' + 10;    
        // shift 4 to make space for new digit, and add the 4 bits of the new digit 
        val = (val << 4) | (byte & 0xF);
    }
    return val;
}

size_t VECTOR_LEN = 4;

struct Range_PP
{
    EC_POINT *g, *h; 
     // VECTOR_LEN = 4;
};

struct Range_Instance
{
    EC_POINT *C; // c = g^x h^r;
    
}; 

struct Range_Witness
{
    BIGNUM *w; 
    BIGNUM *r; // r = twisted elgamal encryption's random value beta
}; 
 
struct Range_Proof
{
    //string delta;     
    vector<EC_POINT *> c;
    //BIGNUM *chl;
    vector<BIGNUM *> z; 
    vector<BIGNUM *> t;
    BIGNUM *tau;
    vector<EC_POINT *> d;
    EC_POINT *D;

    vector<BIGNUM *> x;
    vector<BIGNUM *> r;
    vector<BIGNUM *> m;
    vector<BIGNUM *> s;

    BIGNUM *sigma;

};

void Range_PP_new(Range_PP &pp){
    pp.g = EC_POINT_new(group);
    pp.h = EC_POINT_new(group);
}

void Range_PP_free(Range_PP &pp)
{ 
    EC_POINT_free(pp.g); 
    EC_POINT_free(pp.h); 
}

void Range_Instance_new(Range_Instance &instance)
{
    
    instance.C = EC_POINT_new(group);
}

void Range_Instance_free(Range_Instance &instance)
{
    EC_POINT_free(instance.C);
}

void Range_Witness_new(Range_Witness &witness)
{
    witness.w = BN_new();
    witness.r = BN_new();
}

void Range_Witness_free(Range_Witness &witness)
{
    BN_free(witness.w);
    BN_free(witness.r);
}

void Range_Proof_new(Range_Proof &proof)
{
    //chl = "";
    proof.tau = BN_new();
    proof.c.resize(VECTOR_LEN); 
    proof.z.resize(VECTOR_LEN); 
    proof.t.resize(VECTOR_LEN); 
    proof.d.resize(VECTOR_LEN); 
    ECP_vec_new(proof.c);
    ECP_vec_new(proof.d);
    BN_vec_new(proof.z); 
    BN_vec_new(proof.t);
    proof.D = EC_POINT_new(group);  

    proof.x.resize(VECTOR_LEN); 
    proof.r.resize(VECTOR_LEN); 
    proof.m.resize(VECTOR_LEN); 
    proof.s.resize(VECTOR_LEN);
    BN_vec_new(proof.x);
    BN_vec_new(proof.r); 
    BN_vec_new(proof.m);
    BN_vec_new(proof.s);

    proof.sigma = BN_new();
}

void Range_Proof_free(Range_Proof &proof)
{
  
    ECP_vec_free(proof.c);
    ECP_vec_free(proof.d);
    BN_free(proof.tau);
    BN_vec_free(proof.z); 
    BN_vec_free(proof.t);
    proof.c.resize(0);

    BN_vec_free(proof.x);
    BN_vec_free(proof.r);
    BN_vec_free(proof.m);
    BN_vec_free(proof.s);
}

void Range_PP_print(Range_PP &pp)
{
    cout << "Range Proofs Public parameters >>> " << endl;
    ECP_print(pp.g, "pp.g"); 
    ECP_print(pp.h, "pp.h"); 
    cout << "VECTOR_LEN: " << VECTOR_LEN << endl;
}

void Range_Instance_print(Range_Instance &instance)
{
    cout << "Range Proofs Instance >>> " << endl;  
    ECP_print(instance.C, "instance.c"); 
    
} 

void Range_Witness_print(Range_Witness &witness)
{
    cout << "Range Proofs Witness >>> " << endl; 
    BN_print(witness.w, "w"); 
    BN_print(witness.r, "r"); 
} 

void Range_Proof_print(Range_Proof &proof)
{
    SplitLine_print('-'); 
    cout << "NIZKPoK for Range Proofs >>> " << endl; 
    //cout << "chl: " << chl << endl;
    ECP_vec_print(proof.c, "proof.c");
    BN_print(proof.tau, "proof.tau");
    BN_vec_print(proof.z, "proof.z");
    BN_vec_print(proof.t, "proof.t");
}

void Range_Proof_serialize(Range_Proof &proof, ofstream &fout)
{ 
    ECP_vec_serialize(proof.c, fout);

    BN_serialize(proof.tau,  fout);
} 

void Range_Proof_deserialize(Range_Proof &proof, ifstream &fin)
{
    
    ECP_vec_deserialize(proof.c, fin);

    BN_deserialize(proof.tau,  fin);
} 


void Range_Setup(Range_PP &pp, EC_POINT* &h){
    EC_POINT_copy(pp.g, h); 
    //EC_POINT_copy(pp.h, h);
    EC_POINT_copy(pp.h, generator);
}

void Range_Prove_Commit(Range_PP &pp, 
                            Range_Instance &instance, 
                            Range_Witness &witness, 
                            //string &chl,
                            Range_Proof &proof){
    //hard code C
    //auto start_time = chrono::steady_clock::now();
    const EC_POINT *vec_A[5]; 
    const BIGNUM *vec_x[5];
/*
    vec_A[0] = pp.g; 
    vec_A[1] = pp.h;
    vec_x[0] = witness.w; 
    vec_x[1] = witness.r;
    EC_POINTs_mul(group, instance.C, NULL, 2, vec_A, vec_x, bn_ctx);*/
    BIGNUM *negone = BN_new();
    BN_copy(negone, BN_1);
    BN_set_negative(negone, 1);
    BIGNUM *sum = BN_new(); 
    BIGNUM *tmp_sum = BN_new();
    BIGNUM *tmp_sum0 = BN_new();
    BIGNUM *tmp_sum1 = BN_new(); 
    BIGNUM *tmp_sum2 = BN_new();
    BIGNUM *tmp_sum3 = BN_new();
    BIGNUM *B = BN_new();
    //BIGNUM *sigma = BN_new();
    BIGNUM *FOUR = BN_new();
    BIGNUM *x_r_sum = BN_new();
    EC_POINT *Cinv = EC_POINT_new(group);
    //EC_POINT *D = EC_POINT_new(group);
    EC_POINT *D_tmp = EC_POINT_new(group);
    EC_POINT *Cinvm_sum = EC_POINT_new(group);
    
    //vector<EC_POINT *> d(VECTOR_LEN);
    //ECP_vec_new(d);
    //vector<EC_POINT *> c(VECTOR_LEN);
    //ECP_vec_new(c);
    vector<EC_POINT *> c_minv(VECTOR_LEN);
    ECP_vec_new(c_minv);

    BN_set_word(FOUR, 4);

    //BN_set_word(B, uint64_t(pow(2, BN_LEN*8))); 
    BN_set_word(B, uint64_t(pow(2, 32))); 
    //BN_print(B, "B");
    BN_sub (proof.x[0], B, witness.w); //B-x
    //BN_print(proof.x[0], "B-x");

    BN_mul (sum, proof.x[0], witness.w, bn_ctx); //x(B-x)
    //BN_mod (sum, sum, B, bn_ctx);
    
    BN_mul (sum, sum, FOUR, bn_ctx); //4x(B-x)
    //BN_mod (sum, sum, B, bn_ctx);

    BN_add (sum, sum, BN_1);
    //BN_mod (sum, sum, B, bn_ctx);

    //BN_set_word (sum, 30);
    //BN_print(sum, "sum");
    //BN_mul (tmp_sum0, proof.x[0], proof.x[0], bn_ctx); // x_0^2


                
/*
    while(BN_cmp(proof.x[1], sum) == -1){
        BN_mul (tmp_sum1, proof.x[1], proof.x[1], bn_ctx); //x_1^2
    //  BN_mod (tmp_sum1, tmp_sum1, B, bn_ctx);
        while(BN_cmp(proof.x[2], sum) == -1){
            BN_mul (tmp_sum2, proof.x[2], proof.x[2], bn_ctx); //x_2^2
    //      BN_mod (tmp_sum2, tmp_sum2, B, bn_ctx);
            while(BN_cmp(proof.x[3], sum) == -1){
                    BN_mul (tmp_sum3, proof.x[3], proof.x[3], bn_ctx); //x_3^2
    //          BN_mod (tmp_sum3, tmp_sum3, B, bn_ctx);
                    BN_add (tmp_sum, tmp_sum1, tmp_sum2); //x_1^2 + x_2^2
                    BN_add (tmp_sum, tmp_sum, tmp_sum3); //x_3^2 + x_1^2 + x_2^2
    //          BN_mod (tmp_sum, tmp_sum, B, bn_ctx);

                    if (BN_cmp(tmp_sum, sum) == 0){
                    BN_print(proof.x[1], "proof.x[1]");
                    BN_print(proof.x[2], "proof.x[2]");
                    BN_print(proof.x[3], "proof.x[3]");
                        break;
                    }
                    BN_add (proof.x[3], proof.x[3], BN_1);
        }
                if (BN_cmp(tmp_sum, sum) == 0){
                    break;
            }
            BN_add (proof.x[2], proof.x[2], BN_1);
            BN_set_word (proof.x[3], 0);
        }
        if (BN_cmp(tmp_sum, sum) == 0){
            break;
        }
        BN_add (proof.x[1], proof.x[1], BN_1);
        BN_set_word (proof.x[2], 0);
    }
    
    BN_print(sum, "sum");
    int size = BN_num_bits(sum);
    if(size>=65) cout << size << endl;
    string index = BN_bn2string(sum);
    index = "./3squares " + index + " +RTS -N8 -RTS";
    auto start_time = chrono::steady_clock::now();
    string res = exec(index.c_str());
    auto end_time = chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    cout << "Three square takes time = "
        << chrono::duration <double, milli> (running_time).count() << " ms" << endl;
    vector<string> elems = stringSplit(res, ' ');
    vector<unsigned long int> inter(elems.size());

    
    for (int i = 0; i < elems.size()-1; ++i)
    {
        inter[i] = std::stoul (elems[i], 0, 10);
        //cout << inter[i] << endl;
        BN_set_word (proof.x[i+1], inter[i]);
    }*/
    //BN_set_word (proof.x[1], 2504069926);
    //BN_set_word (proof.x[2], 869357514);
    //BN_set_word (proof.x[3], 3067414581);
    /*BN_print(sum, "sum");
    const char *buffer = BN_bn2hex(sum); 
    uint64_t target = hex2int(buffer);
    unsigned long int *index;
    auto start_time = chrono::steady_clock::now();
    index = static_cast<unsigned long int *>(get_three_squares(target));
    auto end_time = chrono::steady_clock::now();  // end to count the time
    auto running_time = end_time - start_time;
    cout << "Three square takes time = "
       << chrono::duration <double, milli> (running_time).count() << " ms" << endl;
    BN_set_word (proof.x[1], *(index) );
    BN_set_word (proof.x[2], *(index+1));
    BN_set_word (proof.x[3], *(index+2));*/
    //BN_print(sum, "sum");
    mpz_t n, x0, x1, x2;
    mpz_init(n);
    mpz_init(x0);
    mpz_init(x1);
    mpz_init(x2);
    const char *buffer = BN_bn2hex(sum); 
    unsigned long int target = hex2int(buffer);
    mpz_set_ui (n, target);
    find_three_squares(n, x0, x1, x2);
    BN_set_word (proof.x[1], mpz_get_ui(x0));
    BN_set_word (proof.x[2], mpz_get_ui(x1));
    BN_set_word (proof.x[3], mpz_get_ui(x2));
    mpz_clear(n);
    mpz_clear(x0);
    mpz_clear(x1);
    mpz_clear(x2);
    #ifdef DEBUG
    BN_mul (tmp_sum1, proof.x[1], proof.x[1], bn_ctx); //x_1^2
    BN_mul (tmp_sum2, proof.x[2], proof.x[2], bn_ctx); //x_2^2
    BN_mul (tmp_sum3, proof.x[3], proof.x[3], bn_ctx); //x_3^2
    BN_add (tmp_sum, tmp_sum1, tmp_sum2); //x_1^2 + x_2^2
    BN_add (tmp_sum, tmp_sum, tmp_sum3); //x_3^2 + x_1^2 + x_2^2
    //BN_print(tmp_sum, "tmp_sum");
    if (BN_cmp(tmp_sum, sum) == 0){
        
            BN_print(proof.x[1], "proof.x[1]");
            BN_print(proof.x[2], "proof.x[2]");
            BN_print(proof.x[3], "proof.x[3]");
        
    }
    #endif

    BN_copy(proof.r[0], witness.r);
    BN_set_negative(proof.r[0], 1);
    //BN_print(proof.r[0],"proof.r[0]");

    EC_POINT_copy(Cinv, instance.C);
    EC_POINT_invert(group, Cinv, bn_ctx);

    vec_A[0] = Cinv; 
    vec_A[1] = pp.g;
    vec_x[0] = BN_1; 
    vec_x[1] = B;
    EC_POINTs_mul(group, proof.c[0], NULL, 2, vec_A, vec_x, bn_ctx);// c^-1 g^B
    //ECP_print(proof.c[0], "proof.c[0]");
    
    for (int i=1; i < VECTOR_LEN; i++){
        BN_random (proof.r[i]);
        BN_mod (proof.r[i], proof.r[i], B, bn_ctx);
        vec_A[0] = pp.g; 
        vec_A[1] = pp.h;
        vec_x[0] = proof.x[i]; 
        vec_x[1] = proof.r[i];
        EC_POINTs_mul(group, proof.c[i], NULL, 2, vec_A, vec_x, bn_ctx); // g^x_i h^r_i
    }
    
    for (int i=0; i < VECTOR_LEN; i++){
        BN_random (proof.m[i]);
        BN_mod (proof.m[i], proof.m[i], B, bn_ctx);
        BN_random (proof.s[i]);
        BN_mod (proof.s[i], proof.s[i], B, bn_ctx);
        vec_A[0] = pp.g; 
        vec_A[1] = pp.h;
        vec_x[0] = proof.m[i]; 
        vec_x[1] = proof.s[i];
        EC_POINTs_mul(group, proof.d[i], NULL, 2, vec_A, vec_x, bn_ctx); // g^m_i h^s_i 
    }

    BN_random (proof.sigma);
    BN_mod (proof.sigma, proof.sigma, B, bn_ctx);
    

    for (int i=0; i < VECTOR_LEN; i++){
        EC_POINT_mul(group, c_minv[i], NULL, proof.c[i], proof.m[i], bn_ctx);// c_i^m_i
        EC_POINT_invert(group, c_minv[i], bn_ctx);// c_i^-m_i
    }
    

    BN_mul (tmp_sum1, proof.m[0], FOUR, bn_ctx);
    vec_A[0] = c_minv[1]; 
    vec_A[1] = c_minv[2];
    vec_A[2] = c_minv[3];
    vec_A[3] = pp.h;
    vec_A[4] = instance.C;
    vec_x[0] = BN_1;
    vec_x[1] = BN_1;
    vec_x[2] = BN_1;
    vec_x[3] = proof.sigma;
    vec_x[4] = tmp_sum1;
    EC_POINTs_mul(group, proof.D, NULL, 5, vec_A, vec_x, bn_ctx); // h^sigma c^4m_0 c_1^-m_1 c_2^-m_2 c_3^-m_3
    

    //for (int i=0; i < VECTOR_LEN; i++){
        //chl += ECP_ep2string(d[i]);
    //}

    //chl += ECP_ep2string(D);
    
    //Compute challenge

    //Range_Proof_print(proof);
    

    BN_free(sum); 
    BN_free(tmp_sum);
    BN_free(tmp_sum0);
    BN_free(tmp_sum1);
    BN_free(tmp_sum2);
    //BN_free(sigma); 
    BN_free(B);
    //EC_POINT_free(D);
    EC_POINT_free(D_tmp);
    EC_POINT_free(Cinvm_sum);
    BN_free(FOUR);
    BN_free(x_r_sum);
    EC_POINT_free(Cinv);

    //ECP_vec_free(d);
    //ECP_vec_free(c);
    ECP_vec_free(c_minv);
}

void Range_Prove_Copy(Range_PP &pp, 
                            Range_Proof &org_proof,
                            //string &chl,
                            Range_Proof &tar_proof){
    
    BN_copy (tar_proof.x[0], org_proof.x[0]);
    BN_copy (tar_proof.x[1], org_proof.x[1]);
    BN_copy (tar_proof.x[2], org_proof.x[2]);
    BN_copy (tar_proof.x[3], org_proof.x[3]);
    
    BN_copy (tar_proof.r[0], org_proof.r[0]);

    EC_POINT_copy (tar_proof.c[0], org_proof.c[0]);
    
    //ECP_print(proof.c[0], "proof.c[0]");
    
    for (int i=1; i < VECTOR_LEN; i++){
        BN_copy (tar_proof.r[i], org_proof.r[i]);
        EC_POINT_copy (tar_proof.c[i], org_proof.c[i]);
    }
    
    for (int i=0; i < VECTOR_LEN; i++){
        BN_copy (tar_proof.m[i], org_proof.m[i]);
        BN_copy (tar_proof.s[i], org_proof.s[i]);
        EC_POINT_copy (tar_proof.d[i], org_proof.d[i]);
    }

    BN_copy (tar_proof.sigma, org_proof.sigma);
    
    EC_POINT_copy (tar_proof.D, org_proof.D);


    

    //for (int i=0; i < VECTOR_LEN; i++){
        //chl += ECP_ep2string(d[i]);
    //}

    //chl += ECP_ep2string(D);
    
    //Compute challenge

    //Range_Proof_print(proof);
    
}

void Range_Prove_Res(Range_PP &pp, 
                            Range_Instance &instance, 
                            Range_Witness &witness,
                            string &chl, 
                            Range_Proof &proof){

    
    BIGNUM *e = BN_new();
    BIGNUM *tmp_sum = BN_new();
    BIGNUM *tmp_sum1 = BN_new();
    BIGNUM *x_r_sum = BN_new();
    BIGNUM *FOUR = BN_new();

    BN_set_word(FOUR, 4);
    
    //Compute challenge

    Hash_String_to_BN(chl, e);


    for (int i=0; i < VECTOR_LEN; i++){
        BN_mul (proof.z[i], e, proof.x[i], bn_ctx); // chl*x_i
        BN_add (proof.z[i], proof.z[i], proof.m[i]); // m_i + chl*x_i

        BN_mul (proof.t[i], e, proof.r[i], bn_ctx); // chl*r_i
        BN_add (proof.t[i], proof.t[i], proof.s[i]); // s_i + chl*r_i
    }

    BN_set_word (x_r_sum, 0);
    for (int i=1; i < VECTOR_LEN; i++){
        BN_set_word (tmp_sum1, 1);
        BN_mul (tmp_sum1, tmp_sum1, proof.x[i], bn_ctx);
        BN_mul (tmp_sum1, tmp_sum1, proof.r[i], bn_ctx); // x_ir_i

        BN_add (x_r_sum, x_r_sum, tmp_sum1);
    }

    BN_set_word (tmp_sum, 1);
    BN_mul (tmp_sum, tmp_sum, proof.x[0], bn_ctx);
    BN_mul (tmp_sum, tmp_sum, proof.r[0], bn_ctx);
    BN_mul (tmp_sum, tmp_sum, FOUR, bn_ctx);

    BN_add (proof.tau, tmp_sum, x_r_sum); // x_1r_1 + x_2r_3 + x_3r_3 + 4x_0r_0

    BN_mul (proof.tau, proof.tau, e, bn_ctx);

    BN_add (proof.tau, proof.tau, proof.sigma);

    #ifdef DEBUG
        Range_Proof_print(proof);
    #endif

    BN_free(FOUR);
    BN_free(tmp_sum);
    BN_free(tmp_sum1);
    BN_free(e);
    BN_free(x_r_sum);
}

void Range_Prove_Res(Range_PP &pp, 
                            Range_Instance &instance, 
                            Range_Witness &witness,
                            BIGNUM *&e, 
                            Range_Proof &proof){

    
    //BIGNUM *e = BN_new();
    BIGNUM *tmp_sum = BN_new();
    BIGNUM *tmp_sum1 = BN_new();
    BIGNUM *x_r_sum = BN_new();
    BIGNUM *FOUR = BN_new();

    BN_set_word(FOUR, 4);
    
    //Compute challenge

    //Hash_String_to_BN(chl, e);


    for (int i=0; i < VECTOR_LEN; i++){
        BN_mul (proof.z[i], e, proof.x[i], bn_ctx); // chl*x_i
        BN_add (proof.z[i], proof.z[i], proof.m[i]); // m_i + chl*x_i

        BN_mul (proof.t[i], e, proof.r[i], bn_ctx); // chl*r_i
        BN_add (proof.t[i], proof.t[i], proof.s[i]); // s_i + chl*r_i
    }

    BN_set_word (x_r_sum, 0);
    for (int i=1; i < VECTOR_LEN; i++){
        BN_set_word (tmp_sum1, 1);
        BN_mul (tmp_sum1, tmp_sum1, proof.x[i], bn_ctx);
        BN_mul (tmp_sum1, tmp_sum1, proof.r[i], bn_ctx); // x_ir_i

        BN_add (x_r_sum, x_r_sum, tmp_sum1);
    }

    BN_set_word (tmp_sum, 1);
    BN_mul (tmp_sum, tmp_sum, proof.x[0], bn_ctx);
    BN_mul (tmp_sum, tmp_sum, proof.r[0], bn_ctx);
    BN_mul (tmp_sum, tmp_sum, FOUR, bn_ctx);

    BN_add (proof.tau, tmp_sum, x_r_sum); // x_1r_1 + x_2r_3 + x_3r_3 + 4x_0r_0

    BN_mul (proof.tau, proof.tau, e, bn_ctx);

    BN_add (proof.tau, proof.tau, proof.sigma);

    #ifdef DEBUG
        Range_Proof_print(proof);
    #endif

    BN_free(FOUR);
    BN_free(tmp_sum);
    BN_free(tmp_sum1);
//    BN_free(e);
    BN_free(x_r_sum);
}


void Range_Verify(Range_PP &pp, 
                            Range_Instance &instance, 
                            string &chl,
                            Range_Proof &proof,
                            string &res){

    const EC_POINT *vec_A[3]; 
    const BIGNUM *vec_x[3];

    vector<EC_POINT *> c_invchl(VECTOR_LEN);
    ECP_vec_new(c_invchl);
    vector<EC_POINT *> f(VECTOR_LEN);
    ECP_vec_new(f);
    EC_POINT *F = EC_POINT_new(group);
    vector<EC_POINT *> c_zinv(VECTOR_LEN);
    ECP_vec_new(c_zinv);
    EC_POINT *Cinvz_sum = EC_POINT_new(group);
    BIGNUM *FOUR_z_0 = BN_new();
    BIGNUM *FOUR = BN_new();

    BIGNUM *e = BN_new();
    
    //Compute challenge

    Hash_String_to_BN(chl, e);

    BN_set_word (FOUR, 4);



    for (int i=0; i < VECTOR_LEN; i++){
        EC_POINT_mul (group, c_invchl[i], NULL, proof.c[i], e, bn_ctx);
        EC_POINT_invert (group, c_invchl[i], bn_ctx);

        vec_A[0] = pp.g; 
        vec_A[1] = pp.h;
        vec_A[2] = c_invchl[i];
        vec_x[0] = proof.z[i]; 
        vec_x[1] = proof.t[i];
        vec_x[2] = BN_1;
        EC_POINTs_mul(group, f[i], NULL, 3, vec_A, vec_x, bn_ctx);

    }
    

    for (int i=1; i < VECTOR_LEN; i++){
        EC_POINT_mul(group, c_zinv[i], NULL, proof.c[i], proof.z[i], bn_ctx);// c_i^z_i
        EC_POINT_invert(group, c_zinv[i], bn_ctx);// c_i^-z_i
    }


    vec_A[0] = c_zinv[1]; 
    vec_A[1] = c_zinv[2];
    vec_A[2] = c_zinv[3];
    vec_x[0] = BN_1; 
    vec_x[1] = BN_1;
    vec_x[2] = BN_1;
    EC_POINTs_mul(group, Cinvz_sum, NULL, 3, vec_A, vec_x, bn_ctx); //c_1^-z_1 c_2^-z_2 c_3^-z_3

    BN_mul (FOUR_z_0, FOUR, proof.z[0], bn_ctx);

    vec_A[0] = pp.h; 
    vec_A[1] = pp.g;
    vec_A[2] = instance.C;
    vec_x[0] = proof.tau; 
    vec_x[1] = e;
    vec_x[2] = FOUR_z_0;
    EC_POINTs_mul(group, F, NULL, 3, vec_A, vec_x, bn_ctx);

    vec_A[0] = F; 
    vec_A[1] = Cinvz_sum;
    vec_x[0] = BN_1; 
    vec_x[1] = BN_1;
    EC_POINTs_mul(group, F, NULL, 2, vec_A, vec_x, bn_ctx);

    //string res = "";

    for (int i=0; i < VECTOR_LEN; i++){
        res = res + ECP_ep2string(f[i]);
    }

    res = res + ECP_ep2string(F);


    /*bool Validity = (res == chl);


    #ifdef DEBUG
    
    if (Validity) 
    { 
        cout<< "Range Proof accepts >>>" << endl; 
        cout<< "H({d_i}i=0..3, d): " << chl << endl;
        cout<< "H({f_i}i=0..3, f): " << res << endl;
    }
    else 
    {
        cout<< "Range Proof rejects >>>" << endl; 
        cout<< "H({d_i}i=0..3, d): " << res << endl;
        cout<< "H({f_i}i=0..3, f): " << chl << endl;
       
    }
    #endif*/

    ECP_vec_free (c_invchl);
    ECP_vec_free (f);
    EC_POINT_free (F);
    EC_POINT_free (Cinvz_sum);
    ECP_vec_free (c_zinv);
    BN_free (FOUR_z_0);
    BN_free (FOUR);
    BN_free (e);
    //return Validity;

}

bool Range_Verify(Range_PP &pp, 
                            Range_Instance &instance, 
                            BIGNUM *&e,
                            Range_Proof &proof){

    const EC_POINT *vec_A[8]; 
    const BIGNUM *vec_x[8];

    vector<EC_POINT *> c_invchl(VECTOR_LEN);
    ECP_vec_new(c_invchl);
    vector<EC_POINT *> f(VECTOR_LEN);
    ECP_vec_new(f);
    EC_POINT *F = EC_POINT_new(group);
    vector<EC_POINT *> c_zinv(VECTOR_LEN);
    ECP_vec_new(c_zinv);
    EC_POINT *Cinvz_sum = EC_POINT_new(group);
    BIGNUM *FOUR_z_0 = BN_new();
    BIGNUM *FOUR = BN_new();

    //BIGNUM *e = BN_new();
    
    //Compute challenge

    //Hash_String_to_BN(chl, e);

    BN_set_word (FOUR, 4);



    for (int i=0; i < VECTOR_LEN; i++){
        EC_POINT_mul (group, c_invchl[i], NULL, proof.c[i], e, bn_ctx);
        EC_POINT_invert (group, c_invchl[i], bn_ctx);

        vec_A[0] = pp.g; 
        vec_A[1] = pp.h;
        vec_A[2] = c_invchl[i];
        vec_x[0] = proof.z[i]; 
        vec_x[1] = proof.t[i];
        vec_x[2] = BN_1;
        EC_POINTs_mul(group, f[i], NULL, 3, vec_A, vec_x, bn_ctx);
    }
    

    for (int i=1; i < VECTOR_LEN; i++){
        EC_POINT_mul(group, c_zinv[i], NULL, proof.c[i], proof.z[i], bn_ctx);// c_i^z_i
        EC_POINT_invert(group, c_zinv[i], bn_ctx);// c_i^-z_i
    }


   /* vec_A[0] = c_zinv[1]; 
    vec_A[1] = c_zinv[2];
    vec_A[2] = c_zinv[3];
    vec_x[0] = BN_1; 
    vec_x[1] = BN_1;
    vec_x[2] = BN_1;
    EC_POINTs_mul(group, Cinvz_sum, NULL, 3, vec_A, vec_x, bn_ctx); //c_1^-z_1 c_2^-z_2 c_3^-z_3

    BN_mul (FOUR_z_0, FOUR, proof.z[0], bn_ctx);

    vec_A[0] = pp.h; 
    vec_A[1] = pp.g;
    vec_A[2] = instance.C;
    vec_x[0] = proof.tau; 
    vec_x[1] = e;
    vec_x[2] = FOUR_z_0;
    EC_POINTs_mul(group, F, NULL, 3, vec_A, vec_x, bn_ctx);

    vec_A[0] = F; 
    vec_A[1] = Cinvz_sum;
    vec_x[0] = BN_1; 
    vec_x[1] = BN_1;
    EC_POINTs_mul(group, F, NULL, 2, vec_A, vec_x, bn_ctx);*/
    BN_mul (FOUR_z_0, FOUR, proof.z[0], bn_ctx);
    vec_A[0] = c_zinv[1]; 
    vec_A[1] = c_zinv[2];
    vec_A[2] = c_zinv[3];
    vec_A[3] = pp.h; 
    vec_A[4] = pp.g;
    vec_A[5] = instance.C;
    vec_x[0] = BN_1; 
    vec_x[1] = BN_1;
    vec_x[2] = BN_1;
    vec_x[3] = proof.tau; 
    vec_x[4] = e;
    vec_x[5] = FOUR_z_0;
    EC_POINTs_mul(group, F, NULL, 6, vec_A, vec_x, bn_ctx);

    //string res = "";
    bool validity = true;
    for (int i=0; i<VECTOR_LEN ; i++){
        validity = validity && (EC_POINT_cmp(group, proof.d[i], f[i], bn_ctx) == 0);
    }

    return validity && (EC_POINT_cmp(group, proof.D, F, bn_ctx) == 0);
    /*bool Validity = (res == chl);


    #ifdef DEBUG
    
    if (Validity) 
    { 
        cout<< "Range Proof accepts >>>" << endl; 
        cout<< "H({d_i}i=0..3, d): " << chl << endl;
        cout<< "H({f_i}i=0..3, f): " << res << endl;
    }
    else 
    {
        cout<< "Range Proof rejects >>>" << endl; 
        cout<< "H({d_i}i=0..3, d): " << res << endl;
        cout<< "H({f_i}i=0..3, f): " << chl << endl;
       
    }
    #endif*/

    ECP_vec_free (c_invchl);
    ECP_vec_free (f);
    EC_POINT_free (F);
    EC_POINT_free (Cinvz_sum);
    ECP_vec_free (c_zinv);
    BN_free (FOUR_z_0);
    BN_free (FOUR);
    //return Validity;

}

#endif
