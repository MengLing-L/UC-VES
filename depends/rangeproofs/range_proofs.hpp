/****************************************************************************
this hpp implements NIZKPoK for discrete logarithm equality 
*****************************************************************************
* @author     This file is part of PGC, developed by Yu Chen
* @paper      https://eprint.iacr.org/2019/319
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/
#ifndef __RANGE__
#define __RANGE__

#include "../common/global.hpp"
#include "../common/hash.hpp"
#include "../common/print.hpp"
#include "../common/routines.hpp"

struct Range_PP
{
    EC_POINT *g, *h; 
    size_t VECTOR_LEN; // VECTOR_LEN = 3;
}

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
    EC_POINT *delta;     
    vector<EC_POINT *> c;
    BIGNUM *chl;
    vector<BIGNUM *> z; 
    vector<BIGNUM *> t;
};

void NIZK_Range_PP_new(Range_PP &pp){
    pp.g = EC_POINT_new(group);
    pp.h = EC_POINT_new(group);
}

void NIZK_Range_PP_free(Range_PP &pp)
{ 
    EC_POINT_free(pp.g); 
    EC_POINT_free(pp.h); 
}

void NIZK_Range_Instance_new(Range_Instance &instance)
{
    
    instance.C = EC_POINT_new(group);
}

void NIZK_Range_Instance_free(Range_Instance &instance)
{
    EC_POINT_free(instance.C);
}

void NIZK_Range_Witness_new(Range_Witness &witness)
{
    witness.w = BN_new();
    witness.r = BN_new();
}

void NIZK_Range_Witness_free(Range_Witness &witness)
{
    BN_free(witness.w);
    BN_free(witness.r);
}

void NIZK_Range_Proof_new(Range_Proof &proof, Range_PP &pp)
{
    proof.delta = EC_POINT_new(group);
    proof.chl = BN_new();
    proof.z.resize(pp.VECTOR_LEN); 
    proof.t.resize(pp.VECTOR_LEN); 
    BN_vec_new(proof.z); 
    BN_vec_new(proof.t);
}

void NIZK_Range_Proof_free(Range_Proof &proof)
{
    EC_POINT_free(proof.delta);
    ECP_vec_free(proof.c);
    BN_free(proof.chl);
    BN_vec_free(proof.z); 
    BN_vec_free(proof.t);
    proof.c.resize(0);
}

void Range_PP_print(Range_PP &pp)
{
    cout << "Range Proofs Public parameters >>> " << endl;
    ECP_print(pp.g, "pp.g"); 
    ECP_print(pp.h, "pp.h"); 
    cout << "VECTOR_LEN: " << pp.VECTOR_LEN << endl;
}

void Range_Instance_print(Range_Instance &instance)
{
    cout << "Range Proofs Instance >>> " << endl;  
    ECP_print(instance.c, "instance.c"); 
    
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
    ECP_print(proof.delta, "proof.delta");
    ECP_vec_print(proof.c, "proof.c");
    BN_print(proof.chl, "proof.chl"); 
    BN_vec_print(proof.z, "proof.z");
    BN_vec_print(proof.t, "proof.t");
}

void Range_Proof_serialize(Range_Proof &proof, ofstream &fout)
{
    ECP_serialize(proof.delta, fout); 
    ECP_vec_serialize(proof.c, fout);

    BN_serialize(proof.chl,  fout);
} 

void Range_Proof_deserialize(Range_Proof &proof, ifstream &fin)
{
    ECP_deserialize(proof.delta, fin); 
    ECP_vec_deserialize(proof.c, fin);

    BN_deserialize(proof.chl,  fin);
} 


void NIZK_Range_Setup(Range_PP &pp, size_t VECTOR_LEN){
    EC_POINT_copy(pp.g, generator); 
    //EC_POINT_copy(pp.h, h);
    Hash_ECP_to_ECP(pp.g, pp.h);
    pp.VECTOR_LEN = VECTOR_LEN;
}

void NIZK_Range_Init(Range_PP &pp, 
                            Range_Instance &instance, 
                            Range_Witness &witness, 
                            Range_Proof &proof){
    BIGNUM *sum = BN_new(); 
    BIGNUM *tmp_sum = BN_new();
    BIGNUM *tmp_sum0 = BN_new();
    BIGNUM *tmp_sum1 = BN_new(); 
    BIGNUM *tmp_sum2 = BN_new();
    BIGNUM *B = BN_new();
    BIGNUM *sigma = BN_new();
    BIGNUM *FOUR = BN_new();
    vector<BIGNUM *> x(pp.VECTOR_LEN);
    BN_vec_new(x);
    vector<BIGNUM *> r(pp.VECTOR_LEN);
    BN_vec_new(r);
    vector<BIGNUM *> m(pp.VECTOR_LEN);
    BN_vec_new(m);
    vector<BIGNUM *> s(pp.VECTOR_LEN);
    BN_vec_new(s);
    vector<EC_POINT *> d(pp.VECTOR_LEN);
    BN_vec_new(d);

    BN_set_word(FOUR, 4);

    BN_exp (B, BN_2, exp, bn_ctx);
    BN_set_word(B, uint64_t(pow(2, BN_LEN*8))); 
    BN_sub (x[0], B, witness.w); //B-x

    BN_mul (sum, x[0], witness.w, bn_ctx); //x(B-x)
    BN_mul (sum, sum, FOUR, bn_ctx); //x(B-x)

    BN_add (sum, sum, BN_1);

    BN_mul (tmp_sum0, x[0], x[0], bn_ctx); // x_0^2

    while(BN_cmp(x[1], sum) == -1){
        BN_mul (tmp_sum1, x[1], x[1], bn_ctx); //x_1^2
        while(BN_cmp(x[2], sum) == -1){
            BN_mul (tmp_sum2, x[2], x[2], bn_ctx); //x_2^2
            BN_add (tmp_sum, tmp_sum1, tmp_sum2); //x_1^2 + x_2^2
            BN_add (tmp_sum, tmp_sum, tmp_sum0); //x_0^2 + x_1^2 + x_2^2

            if (BN_cmp(tmp_sum, sum) == 0){
                BN_print(tmp_sum, "tmp_sum");
                BN_print(sum, "sum");
                break;
            }
            BN_add (x[2], x[2], BN_1);
        }
        if (BN_cmp(tmp_sum, sum) == 0){
            break;
        }
        BN_add (x[1], x[1], BN_1);
    }

    BN_free(sum); 
    BN_free(tmp_sum);
    BN_free(tmp_sum0);
    BN_free(tmp_sum1);
    BN_free(tmp_sum2);
    BN_free(sigma); 
    BN_free(B);
    BN_free(FOUR);
    BN_vec_free(x);
    BN_vec_free(r);
    BN_vec_free(m);
    BN_vec_free(s);
    ECP_vec_free(d);
}



#endif