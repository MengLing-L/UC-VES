/****************************************************************************
this hpp implements NIZKPoK for discrete logarithm equality 
*****************************************************************************
* @author     This file is part of PGC, developed by Yu Chen
* @paper      https://eprint.iacr.org/2019/319
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/
#ifndef __SIGMADLOG__
#define __SIGMADLOG__

#include "../common/global.hpp"
#include "../common/hash.hpp"
#include "../common/print.hpp"
#include "../common/routines.hpp"

// define structure of DLOG_EQ_Proof 
struct SIGMA_DLOG_PP
{
    EC_POINT *g, *h;         
    EC_POINT *EK;
    bool Sig_flag;
};

struct SIGMA_DLOG_Instance
{
    EC_POINT *U; 
    EC_POINT *V; 
    EC_POINT *A;
    EC_POINT *B;
}; 

struct SIGMA_DLOG_Witness
{
    BIGNUM *w; 
    BIGNUM *gamma; 
}; 

struct SIGMA_DLOG_Proof
{
    
    EC_POINT *Y1,*Y2,*Y3;

    BIGNUM *z1, *z2;
    //string chl;    
    BIGNUM *phi_w,*phi_gamma;  

};

void SIGMA_DLOG_PP_new(SIGMA_DLOG_PP &pp){
    pp.g = EC_POINT_new(group);
    pp.h = EC_POINT_new(group);
    pp.EK = EC_POINT_new(group);
}


void SIGMA_DLOG_PP_free(SIGMA_DLOG_PP &pp)
{ 
    EC_POINT_free(pp.g); 
    EC_POINT_free(pp.h); 
    EC_POINT_free(pp.EK);
}

void SIGMA_DLOG_Instance_new(SIGMA_DLOG_Instance &instance)
{
    instance.U = EC_POINT_new(group);
    instance.V = EC_POINT_new(group);
    
    instance.A = EC_POINT_new(group);
    instance.B = EC_POINT_new(group);
    
}

void SIGMA_DLOG_Instance_free(SIGMA_DLOG_Instance &instance)
{
    EC_POINT_free(instance.U);
    EC_POINT_free(instance.V);
    
    EC_POINT_free(instance.A);
    EC_POINT_free(instance.B);
    
}

void SIGMA_DLOG_Witness_new(SIGMA_DLOG_Witness &witness)
{
    witness.w = BN_new();
    witness.gamma = BN_new();
}

void SIGMA_DLOG_Witness_free(SIGMA_DLOG_Witness &witness)
{
    BN_free(witness.w);
    BN_free(witness.gamma);
}

void SIGMA_DLOG_Proof_new(SIGMA_DLOG_Proof &proof)
{
    proof.Y1 = EC_POINT_new(group);
    proof.Y2 = EC_POINT_new(group);
    proof.Y3 = EC_POINT_new(group);
    proof.z1 = BN_new();
    proof.z2 = BN_new();
    proof.phi_w = BN_new();
    proof.phi_gamma = BN_new();
}

void SIGMA_DLOG_Proof_free(SIGMA_DLOG_Proof &proof)
{
    BN_free(proof.z1);
    BN_free(proof.z2);
    BN_free(proof.phi_gamma);
    BN_free(proof.phi_w);

    EC_POINT_free(proof.Y1);
    EC_POINT_free(proof.Y2);
    EC_POINT_free(proof.Y3);
}

void SIGMA_DLOG_PP_print(SIGMA_DLOG_PP &pp)
{
    cout << "DLOG Proofs Public parameters >>> " << endl;
    ECP_print(pp.g, "pp.g"); 
    ECP_print(pp.h, "pp.h"); 
    ECP_print(pp.EK, "pp.EK");
}

void SIGMA_DLOG_Instance_print(SIGMA_DLOG_Instance &instance)
{
    cout << "DLOG Instance >>> " << endl; 
    ECP_print(instance.U, "instance.U"); 
    ECP_print(instance.V, "instance.V"); 
    
    ECP_print(instance.A, "instance.A"); 
    ECP_print(instance.B, "instance.B");
    
    
} 

void SIGMA_DLOG_Witness_print(SIGMA_DLOG_Witness &witness)
{
    cout << "DLOG Witness >>> " << endl; 
    BN_print(witness.w, "witness.w"); 
    BN_print(witness.gamma, "witness.gamma"); 
} 

void SIGMA_DLOG_Proof_print(SIGMA_DLOG_Proof &proof)
{
    SplitLine_print('-'); 
    cout << "NIZKPoK for DLOG >>> " << endl; 
    BN_print(proof.z1,  "proof.z1");
    BN_print(proof.z2,  "proof.z2");
    ECP_print(proof.Y1, "proof.Y1");
    ECP_print(proof.Y2, "proof.Y2");
    ECP_print(proof.Y3, "proof.Y3");
    //cout << "chl: " << chl << endl;
    
}

void SIGMA_DLOG_Proof_serialize(SIGMA_DLOG_Proof &proof, ofstream &fout)
{

    BN_serialize(proof.z1, fout);
    BN_serialize(proof.z2, fout);
    BN_serialize(proof.phi_w, fout); 
    BN_serialize(proof.phi_gamma, fout); 
    ECP_serialize(proof.Y1, fout); 
    ECP_serialize(proof.Y2, fout);
    ECP_serialize(proof.Y3, fout);  

} 

void SIGMA_DLOG_Proof_deserialize(SIGMA_DLOG_Proof &proof, ifstream &fin)
{

    BN_deserialize(proof.z1,  fin);
    BN_deserialize(proof.z2,  fin);
    BN_deserialize(proof.phi_w, fin); 
    BN_deserialize(proof.phi_gamma, fin); 
    ECP_deserialize(proof.Y1, fin); 
    ECP_deserialize(proof.Y2, fin);
    ECP_deserialize(proof.Y3, fin);  
    
} 


/* Setup algorithm: do nothing */ 
void SIGMA_DLOG_Setup(SIGMA_DLOG_PP &pp, EC_POINT* &h, EC_POINT* &EK, bool Sig_flag)
{ 
    EC_POINT_copy(pp.g, h); 
    EC_POINT_copy(pp.h, generator);
    //Hash_ECP_to_ECP(pp.g, pp.h);
    EC_POINT_copy(pp.EK, EK);
    pp.Sig_flag = Sig_flag;

    #ifdef DEBUG
    SIGMA_DLOG_PP_print(pp); 
    #endif
}


void SIGMA_DLOG_Prove(SIGMA_DLOG_PP &pp, 
                              SIGMA_DLOG_Instance &instance, 
                              SIGMA_DLOG_Witness &witness,
                              string &chl,  
                              SIGMA_DLOG_Proof &proof)
{
    
    // begin to generate proof
    //BIGNUM *phi_w = BN_new(); 
    BN_random(proof.phi_w); 
    //BIGNUM *phi_gamma = BN_new(); 
    BN_random(proof.phi_gamma);

    //EC_POINT_mul(group, Y1, phi_w, pp.h, phi_gamma, bn_ctx); 
    const EC_POINT *vec_A[2]; 
    const BIGNUM *vec_x[2];
    vec_A[0] = pp.g; 
    vec_A[1] = pp.h; 
    vec_x[0] = proof.phi_w; 
    vec_x[1] = proof.phi_gamma; 
    EC_POINTs_mul(group, proof.Y1, NULL, 2, vec_A, vec_x, bn_ctx); // Y1 = g^p_s h^p_beta
    
    EC_POINT_mul(group, proof.Y2, NULL, pp.EK, proof.phi_gamma, bn_ctx);
    
    if(pp.Sig_flag){
        EC_POINT_mul(group, proof.Y3, NULL, instance.B, proof.phi_w, bn_ctx);
    } 

    
    BIGNUM *e = BN_new(); 
    Hash_String_to_BN(chl, e); // V's challenge in Zq; 

    
    BN_mul (proof.z1, e, witness.w, bn_ctx); 
    BN_sub (proof.z1, proof.phi_w, proof.z1);

    BN_mul (proof.z2, e, witness.gamma, bn_ctx); 
    BN_sub (proof.z2, proof.phi_gamma, proof.z2);


    #ifdef DEBUG
    SIGMA_DLOG_Proof_print(proof); 
    #endif

    
    BN_free(e);
    
 
}


void SIGMA_DLOG_Simulate_Proof(SIGMA_DLOG_PP &pp, 
                              SIGMA_DLOG_Instance &instance,  
                              string &chl, 
                              SIGMA_DLOG_Proof &proof)
{

    BIGNUM *e = BN_new(); 
    Hash_String_to_BN(chl, e);
    
    BN_random (proof.z1);
    BN_random (proof.z2);

    const EC_POINT *vec_A[3]; 
    const BIGNUM *vec_x[3]; 
    
    
    vec_A[0] = instance.U; 
    vec_A[1] = pp.g;
    vec_A[2] = pp.h;
    vec_x[0] = e; 
    vec_x[1] = proof.z1;
    vec_x[2] = proof.z2;
    EC_POINTs_mul(group, proof.Y1, NULL, 3, vec_A, vec_x, bn_ctx);  
    

    vec_A[0] = instance.V; 
    vec_A[1] = pp.EK;
    vec_x[0] = e; 
    vec_x[1] = proof.z2;
    EC_POINTs_mul(group, proof.Y2, NULL, 2, vec_A, vec_x, bn_ctx);  

    if(pp.Sig_flag){
        vec_A[0] = instance.A; 
        vec_A[1] = instance.B;
        vec_x[0] = e; 
        vec_x[1] = proof.z1;
        EC_POINTs_mul(group, proof.Y3, NULL, 2, vec_A, vec_x, bn_ctx); 
    }

    #ifdef DEBUG
    SIGMA_DLOG_Proof_print(proof); 
    #endif
    BN_free(e);
}

/*
    Check if PI is a valid NIZK proof for statenent (G1^w = H1 and G2^w = H2)
*/

void SIGMA_DLOG_Verify(SIGMA_DLOG_PP &pp, 
                               SIGMA_DLOG_Instance &instance,
                               string &chl, 
                               SIGMA_DLOG_Proof &proof)
{
    // initialize the transcript with instance 

    EC_POINT *Y1 = EC_POINT_new(group);
    EC_POINT *Y2 = EC_POINT_new(group);
    EC_POINT *Y3 = EC_POINT_new(group);

    
    // compute the challenge
    BIGNUM *e = BN_new(); 
    Hash_String_to_BN(chl, e); // V's challenge in Zq; 

     
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

    bool V1, V2, V3;

    V1 = (EC_POINT_cmp(group, proof.Y1, Y1, bn_ctx) == 0); 

    V2 = (EC_POINT_cmp(group, proof.Y2, Y2, bn_ctx) == 0); 

    if(pp.Sig_flag){
        V3 = (EC_POINT_cmp(group, proof.Y3, Y3, bn_ctx) == 0);
    }

    if (V1){
        cout<< "Y1 == proof.Y1" << endl;
    }else{
        cout<< "Y1 != proof.Y1" << endl;
        ECP_print(proof.Y1, "proof.Y1");
        ECP_print(Y1, "Y1");
    }

    if (V2){
        cout<< "Y2 == proof.Y2" << endl;
    }else{
        cout<< "Y2 != proof.Y2" << endl;
        ECP_print(proof.Y2, "proof.Y2");
        ECP_print(Y2, "Y2");
    }

    if (pp.Sig_flag){
        if (V3){
            cout<< "Y3 == proof.Y3" << endl;
        }else{
            cout<< "Y3 != proof.Y3" << endl;
            ECP_print(proof.Y3, "proof.Y3");
            ECP_print(Y3, "Y3");
        }
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

    EC_POINT_free(Y1);
    EC_POINT_free(Y2);
    EC_POINT_free(Y3);

    //return Validity;
}

#endif
