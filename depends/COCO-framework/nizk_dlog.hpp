/****************************************************************************
this hpp implements NIZKPoK for discrete logarithm equality 
*****************************************************************************
* @author     This file is part of PGC, developed by Yu Chen
* @paper      https://eprint.iacr.org/2019/319
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/
#ifndef __DLOG__
#define __DLOG__

#include "../common/global.hpp"
#include "../common/hash.hpp"
#include "../common/print.hpp"
#include "../common/routines.hpp"

// define structure of DLOG_EQ_Proof 
struct DLOG_PP
{
    EC_POINT *g, *h;         
    EC_POINT *EK;
    bool Sig_flag;
};

struct DLOG_Instance
{
    EC_POINT *U; 
    EC_POINT *V; 
    EC_POINT *A;
    EC_POINT *B;
}; 

struct DLOG_Witness
{
    BIGNUM *w; 
    BIGNUM *gamma; 
}; 

struct DLOG_Proof
{
    
    BIGNUM *z1, *z2;
    string chl;    
};

void NIZK_DLOG_PP_new(DLOG_PP &pp){
    pp.g = EC_POINT_new(group);
    pp.h = EC_POINT_new(group);
    pp.EK = EC_POINT_new(group);
}


void NIZK_DLOG_PP_free(DLOG_PP &pp)
{ 
    EC_POINT_free(pp.g); 
    EC_POINT_free(pp.h); 
    EC_POINT_free(pp.EK);
}

void NIZK_DLOG_Instance_new(DLOG_Instance &instance)
{
    instance.U = EC_POINT_new(group);
    instance.V = EC_POINT_new(group);
    
    instance.A = EC_POINT_new(group);
    instance.B = EC_POINT_new(group);
    
}

void NIZK_DLOG_Instance_free(DLOG_Instance &instance)
{
    EC_POINT_free(instance.U);
    EC_POINT_free(instance.V);
    
    EC_POINT_free(instance.A);
    EC_POINT_free(instance.B);
    
}

void NIZK_DLOG_Witness_new(DLOG_Witness &witness)
{
    witness.w = BN_new();
    witness.gamma = BN_new();
}

void NIZK_DLOG_Witness_free(DLOG_Witness &witness)
{
    BN_free(witness.w);
    BN_free(witness.gamma);
}

void NIZK_DLOG_Proof_new(DLOG_Proof &proof)
{
    proof.z1 = BN_new();
    proof.z2 = BN_new();
    proof.chl = "";
}

void NIZK_DLOG_Proof_free(DLOG_Proof &proof)
{
    BN_free(proof.z1);
    BN_free(proof.z2);
}

void DLOG_PP_print(DLOG_PP &pp)
{
    cout << "DLOG Proofs Public parameters >>> " << endl;
    ECP_print(pp.g, "pp.g"); 
    ECP_print(pp.h, "pp.h"); 
    ECP_print(pp.EK, "pp.EK");
}

void DLOG_Instance_print(DLOG_Instance &instance)
{
    cout << "DLOG Instance >>> " << endl; 
    ECP_print(instance.U, "instance.U"); 
    ECP_print(instance.V, "instance.V"); 
    
    ECP_print(instance.A, "instance.A"); 
    ECP_print(instance.B, "instance.B");
    
    
} 

void DLOG_Witness_print(DLOG_Witness &witness)
{
    cout << "DLOG Witness >>> " << endl; 
    BN_print(witness.w, "witness.w"); 
    BN_print(witness.gamma, "witness.gamma"); 
} 

void DLOG_Proof_print(DLOG_Proof &proof)
{
    SplitLine_print('-'); 
    cout << "NIZKPoK for DLOG >>> " << endl; 
    BN_print(proof.z1,  "proof.z1");
    BN_print(proof.z2,  "proof.z2");
    cout << "proof.chl: " << proof.chl << endl;
    
}

void DLOG_Proof_serialize(DLOG_Proof &proof, ofstream &fout)
{
    BN_serialize(proof.z1, fout);
    BN_serialize(proof.z2, fout);
    
} 

void DLOG_Proof_deserialize(DLOG_Proof &proof, ifstream &fin)
{
    BN_deserialize(proof.z1,  fin);
    BN_deserialize(proof.z2,  fin);
    
} 


/* Setup algorithm: do nothing */ 
void NIZK_DLOG_Setup(DLOG_PP &pp, EC_POINT* &h, EC_POINT* &EK, bool Sig_flag)
{ 
    EC_POINT_copy(pp.g, h); 
    EC_POINT_copy(pp.h, generator);
    //Hash_ECP_to_ECP(pp.g, pp.h);
    EC_POINT_copy(pp.EK, EK);
    pp.Sig_flag = Sig_flag;

    #ifdef DEBUG
    DLOG_PP_print(pp); 
    #endif
}


// Generate a NIZK proof PI for g1^w = h1 and g2^w = h2
void NIZK_DLOG_Prove(DLOG_PP &pp, 
                              DLOG_Instance &instance, 
                              DLOG_Witness &witness,  
                              DLOG_Proof &proof)
{
    
    // begin to generate proof
    BIGNUM *phi_w = BN_new(); 
    BN_random(phi_w); 
    BIGNUM *phi_gamma = BN_new(); 
    BN_random(phi_gamma);

    EC_POINT *Y1 = EC_POINT_new(group);
    EC_POINT *Y2 = EC_POINT_new(group);
    EC_POINT *Y3 = EC_POINT_new(group);

    //EC_POINT_mul(group, Y1, phi_w, pp.h, phi_gamma, bn_ctx); 
    const EC_POINT *vec_A[2]; 
    const BIGNUM *vec_x[2];
    vec_A[0] = pp.g; 
    vec_A[1] = pp.h; 
    vec_x[0] = phi_w; 
    vec_x[1] = phi_gamma; 
    EC_POINTs_mul(group, Y1, NULL, 2, vec_A, vec_x, bn_ctx); // Y1 = g^p_s h^p_beta
    
    EC_POINT_mul(group, Y2, NULL, pp.EK, phi_gamma, bn_ctx);
    
    if(pp.Sig_flag){
        EC_POINT_mul(group, Y3, NULL, instance.B, phi_w, bn_ctx);
    } 

    // update the transcript 
    proof.chl += ECP_ep2string(Y1) + ECP_ep2string(Y2); 

    if(pp.Sig_flag){
        proof.chl += ECP_ep2string(Y3);
    }
    // compute the challenge

    BIGNUM *e = BN_new(); 
    Hash_String_to_BN(proof.chl, e); // V's challenge in Zq; 

    // compute the response
    BN_mul (proof.z1, e, witness.w, bn_ctx); 
    BN_sub (proof.z1, phi_w, proof.z1);

    BN_mul (proof.z2, e, witness.gamma, bn_ctx); 
    BN_sub (proof.z2, phi_gamma, proof.z2);


    #ifdef DEBUG
    DLOG_Proof_print(proof); 
    #endif

    BN_free(phi_w); 
    BN_free(phi_gamma); 
    BN_free(e);
    EC_POINT_free(Y1);
    EC_POINT_free(Y2);
    EC_POINT_free(Y3);
}

/*
    Check if PI is a valid NIZK proof for statenent (G1^w = H1 and G2^w = H2)
*/

bool NIZK_DLOG_Verify(DLOG_PP &pp, 
                               DLOG_Instance &instance,
                               DLOG_Proof &proof)
{
    // initialize the transcript with instance 

    EC_POINT *Y1 = EC_POINT_new(group);
    EC_POINT *Y2 = EC_POINT_new(group);
    EC_POINT *Y3 = EC_POINT_new(group);

    
    // compute the challenge
    BIGNUM *e = BN_new(); 
    Hash_String_to_BN(proof.chl, e); // V's challenge in Zq; 

     
    const EC_POINT *vec_A[3]; 
    const BIGNUM *vec_x[3]; 
    
    
    vec_A[0] = instance.U; 
    vec_A[1] = pp.g;
    vec_A[2] = pp.h;
    vec_x[0] = e; 
    vec_x[1] = proof.z1;
    vec_x[2] = proof.z2;
    EC_POINTs_mul(group, Y1, NULL, 3, vec_A, vec_x, bn_ctx);  
    

    vec_A[0] = instance.V; 
    vec_A[1] = pp.EK;
    vec_x[0] = e; 
    vec_x[1] = proof.z2;
    EC_POINTs_mul(group, Y2, NULL, 2, vec_A, vec_x, bn_ctx);  

    if(pp.Sig_flag){
        vec_A[0] = instance.A; 
        vec_A[1] = instance.B;
        vec_x[0] = e; 
        vec_x[1] = proof.z1;
        EC_POINTs_mul(group, Y3, NULL, 2, vec_A, vec_x, bn_ctx); 
    }

    string res = "";
    res += ECP_ep2string(Y1) + ECP_ep2string(Y2);

    if(pp.Sig_flag){
        res += ECP_ep2string(Y3);
    }

    bool Validity = (res == proof.chl); 

    #ifdef DEBUG
    
    if (Validity){ 
        cout<< "DLOG Proof Accepts >>>" << endl; 
        cout<< "proof.chl: " << proof.chl << endl;
        cout<< "H(Y1|Y2): " << res << endl;
    }
    else{
        cout<< "DLOG Proof Rejects >>>" << endl; 
        cout<< "proof.chl: " << proof.chl << endl;
        cout<< "H(Y1|Y2): " << res << endl;
    }
    #endif

    BN_free(e); 

    EC_POINT_free(Y1);
    EC_POINT_free(Y2);
    EC_POINT_free(Y3);

    return Validity;
}

#endif
