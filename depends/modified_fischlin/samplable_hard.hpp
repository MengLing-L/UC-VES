/****************************************************************************
this hpp implements NIZKPoK for discrete logarithm equality 
*****************************************************************************
* @author     This file is part of PGC, developed by Yu Chen
* @paper      https://eprint.iacr.org/2019/319
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/
#ifndef __SAMPLABLE_HARD__
#define __SAMPLABLE_HARD__

#include "../common/global.hpp"
#include "../common/hash.hpp"
#include "../common/print.hpp"
#include "../common/routines.hpp"

// define structure of DLOG_EQ_Proof 
struct SAMPLABLE_HARD_PP
{
    EC_POINT *g;         
    
};

struct SAMPLABLE_HARD_Instance
{
    EC_POINT *Q; 
}; 

struct SAMPLABLE_HARD_Witness
{
    BIGNUM *w; 
}; 

struct SAMPLABLE_HARD_Proof
{
    
    EC_POINT *Y;

    BIGNUM *z;
    //string chl;    
    BIGNUM *phi_w;  

};

void SAMPLABLE_HARD_PP_new(SAMPLABLE_HARD_PP &pp){
    pp.g = EC_POINT_new(group);
    //pp.EK = EC_POINT_new(group);
}


void SAMPLABLE_HARD_PP_free(SAMPLABLE_HARD_PP &pp)
{ 
    EC_POINT_free(pp.g); 
    //EC_POINT_free(pp.EK);
}

void SAMPLABLE_HARD_Instance_new(SAMPLABLE_HARD_Instance &instance)
{
    instance.Q = EC_POINT_new(group);
    
}

void SAMPLABLE_HARD_Instance_free(SAMPLABLE_HARD_Instance &instance)
{
    EC_POINT_free(instance.Q);
    
}

void SAMPLABLE_HARD_Witness_new(SAMPLABLE_HARD_Witness &witness)
{
    witness.w = BN_new();
}

void SAMPLABLE_HARD_Witness_free(SAMPLABLE_HARD_Witness &witness)
{
    BN_free(witness.w);
}

void SAMPLABLE_HARD_Proof_new(SAMPLABLE_HARD_Proof &proof)
{
    proof.Y = EC_POINT_new(group);
    proof.z = BN_new();
    proof.phi_w = BN_new();
}

void SAMPLABLE_HARD_Proof_free(SAMPLABLE_HARD_Proof &proof)
{
    BN_free(proof.z);
    BN_free(proof.phi_w);

    EC_POINT_free(proof.Y);
}

void SAMPLABLE_HARD_PP_print(SAMPLABLE_HARD_PP &pp)
{
    cout << "DLOG Proofs Public parameters >>> " << endl;
    ECP_print(pp.g, "pp.g"); 
    //ECP_print(pp.EK, "pp.EK");
}

void SAMPLABLE_HARD_Instance_print(SAMPLABLE_HARD_Instance &instance)
{
    cout << "DLOG Instance >>> " << endl; 
    ECP_print(instance.Q, "instance.Q"); 
    
    
} 

void SAMPLABLE_HARD_Witness_print(SAMPLABLE_HARD_Witness &witness)
{
    cout << "DLOG Witness >>> " << endl; 
    BN_print(witness.w, "witness.w"); 
} 

void SAMPLABLE_HARD_Proof_print(SAMPLABLE_HARD_Proof &proof)
{
    SplitLine_print('-'); 
    cout << "NIZKPoK for DLOG >>> " << endl; 
    BN_print(proof.z,  "proof.z");
    ECP_print(proof.Y, "proof.Y");
    //cout << "chl: " << chl << endl;
    
}

void SAMPLABLE_HARD_Proof_serialize(SAMPLABLE_HARD_Proof &proof, ofstream &fout)
{

    BN_serialize(proof.z, fout);
    BN_serialize(proof.phi_w, fout); 
    ECP_serialize(proof.Y, fout);  

} 

void SAMPLABLE_HARD_Proof_deserialize(SAMPLABLE_HARD_Proof &proof, ifstream &fin)
{

    BN_deserialize(proof.z,  fin);
    BN_deserialize(proof.phi_w, fin); 
    ECP_deserialize(proof.Y, fin); 
    
} 


/* Setup algorithm: do nothing */ 
void SAMPLABLE_HARD_Setup(SAMPLABLE_HARD_PP &pp)
{ 
    EC_POINT_copy(pp.g, generator); 
    //Hash_ECP_to_ECP(pp.g, pp.h);
    //EC_POINT_copy(pp.EK, EK);

    #ifdef DEBUG
    SAMPLABLE_HARD_PP_print(pp); 
    #endif
}

void SAMPLABLE_HARD_Commit(SAMPLABLE_HARD_PP &pp, 
                              SAMPLABLE_HARD_Instance &instance, 
                              SAMPLABLE_HARD_Witness &witness,
                              string &chl,
                              SAMPLABLE_HARD_Proof &proof)
{
    
    // begin to generate proof
    //BIGNUM *phi_w = BN_new(); 
    BN_random(proof.phi_w); 
    //BIGNUM *phi_gamma = BN_new();

    EC_POINT_mul(group, proof.Y, NULL, pp.g, proof.phi_w, bn_ctx);

    chl += ECP_ep2string(proof.Y); 

}

void SAMPLABLE_HARD_Res(SAMPLABLE_HARD_PP &pp, 
                              SAMPLABLE_HARD_Instance &instance, 
                              SAMPLABLE_HARD_Witness &witness,
                              string &chl,  
                              SAMPLABLE_HARD_Proof &proof)
{
       
    BIGNUM *e = BN_new(); 
    String_to_BN(chl, e); // V's challenge in Zq; 

    BN_mul (proof.z, e, witness.w, bn_ctx); 
    BN_sub (proof.z, proof.phi_w, proof.z);

    #ifdef DEBUG
        SAMPLABLE_HARD_Proof_print(proof); 
    #endif

    BN_free(e);
    
}


void SAMPLABLE_HARD_Prove(SAMPLABLE_HARD_PP &pp, 
                              SAMPLABLE_HARD_Instance &instance, 
                              SAMPLABLE_HARD_Witness &witness,
                              string &chl,  
                              SAMPLABLE_HARD_Proof &proof)
{
    
    // begin to generate proof
    //BIGNUM *phi_w = BN_new(); 
    BN_random(proof.phi_w); 
    //BIGNUM *phi_gamma = BN_new(); 
    
    EC_POINT_mul(group, proof.Y, NULL, pp.g, proof.phi_w, bn_ctx);

    BIGNUM *e = BN_new(); 
    String_to_BN(chl, e); // V's challenge in Zq; 

    BN_mul (proof.z, e, witness.w, bn_ctx); 
    BN_sub (proof.z, proof.phi_w, proof.z);

    #ifdef DEBUG
    SAMPLABLE_HARD_Proof_print(proof); 
    #endif

    BN_free(e);
}


void SAMPLABLE_HARD_Simulate_Proof(SAMPLABLE_HARD_PP &pp, 
                              SAMPLABLE_HARD_Instance &instance,  
                              string &chl, 
                              string &chl1,
                              SAMPLABLE_HARD_Proof &proof)
{

    BIGNUM *e = BN_new(); 
    String_to_BN(chl1, e);
    
    BN_random (proof.z);

    const EC_POINT *vec_A[2]; 
    const BIGNUM *vec_x[2]; 
    
    
    vec_A[0] = instance.Q; 
    vec_A[1] = pp.g;
    vec_x[0] = e; 
    vec_x[1] = proof.z;
    EC_POINTs_mul(group, proof.Y, NULL, 2, vec_A, vec_x, bn_ctx);  

    chl += ECP_ep2string(proof.Y); 

    #ifdef DEBUG
    SAMPLABLE_HARD_Proof_print(proof); 
    #endif
    BN_free(e);
}

/*
    Check if PI is a valid NIZK proof for statenent (G1^w = H1 and G2^w = H2)
*/

void SAMPLABLE_HARD_Verify(SAMPLABLE_HARD_PP &pp, 
                               SAMPLABLE_HARD_Instance &instance,
                               string &chl, 
                               SAMPLABLE_HARD_Proof &proof,
                               EC_POINT* &EK)
{
    // initialize the transcript with instance 

    EC_POINT *Y = EC_POINT_new(group);

    
    // compute the challenge
    BIGNUM *e = BN_new(); 
    String_to_BN(chl, e); // V's challenge in Zq; 

     
    const EC_POINT *vec_A[2]; 
    const BIGNUM *vec_x[2]; 
    
    
    vec_A[0] = instance.Q; 
    vec_A[1] = pp.g;
    vec_x[0] = e; 
    vec_x[1] = proof.z;
    EC_POINTs_mul(group, Y, NULL, 2, vec_A, vec_x, bn_ctx);  
    

    bool V1;

    V1 = (EC_POINT_cmp(group, proof.Y, Y, bn_ctx) == 0); 

    if (V1){
        cout<< "Y == proof.Y" << endl;
    }else{
        cout<< "Y != proof.Y" << endl;
        ECP_print(proof.Y, "proof.Y");
        ECP_print(Y, "Y");
    }

    /*bool Validity = (res == chl); 

    #ifdef DEBUG
    
    if (Validity){ 
        cout<< "DLOG Proof Accepts >>>" << endl; 
        cout<< "chl: " << chl << endl;
        cout<< "H(*): " << res << endl;
    }
    else{
        cout<< "DLOG Proof Rejects >>>" << endl; 
        cout<< "chl: " << chl << endl;
        cout<< "H(*): " << res << endl;
    }
    #endif*/

    BN_free(e); 

    EC_POINT_free(Y);

    //return Validity;
}

void SAMPLABLE_HARD_Verify(SAMPLABLE_HARD_PP &pp, 
                               SAMPLABLE_HARD_Instance &instance,
                               string &chl, 
                               SAMPLABLE_HARD_Proof &proof,
                               string &res)
{
    // initialize the transcript with instance 

    EC_POINT *Y = EC_POINT_new(group);

    // compute the challenge
    BIGNUM *e = BN_new(); 
    String_to_BN(chl, e); // V's challenge in Zq; 

     
    const EC_POINT *vec_A[2]; 
    const BIGNUM *vec_x[2]; 
    
    
    vec_A[0] = instance.Q; 
    vec_A[1] = pp.g;
    vec_x[0] = e; 
    vec_x[1] = proof.z;
    EC_POINTs_mul(group, Y, NULL, 2, vec_A, vec_x, bn_ctx);  

    res += ECP_ep2string(Y);


    BN_free(e); 

    EC_POINT_free(Y);

    //return Validity;
}

#endif
