/****************************************************************************
this hpp implements NIZKPoK for discrete logarithm equality 
*****************************************************************************
* @author     This file is part of PGC, developed by Yu Chen
* @paper      https://eprint.iacr.org/2019/319
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/
#ifndef __COCO_Framework__
#define __COCO_Framework__

#include "../common/global.hpp"
#include "../common/hash.hpp"
#include "../common/print.hpp"
#include "../common/routines.hpp"

struct COCO_Framework_PP
{
    EC_POINT *g, *h; 
    size_t VECTOR_LEN; // VECTOR_LEN = 4;
    EC_POINT *EK_R;
    EC_POINT *EK_COCO;
    EC_POINT *PK;
    EC_POINT *SK;
};

struct COCO_Framework_Instance
{ 
    EC_POINT *A, *B;
    vector<EC_POINT *> U;
    vector<EC_POINT *> V;
}; 

struct COCO_Framework_Witness
{
    
    vector<BIGNUM *> r; // r = twisted elgamal encryption's random value beta
    vector<BIGNUM *> w; // v = signature.s
}; 
 
struct COCO_Framework_Proof
{
    Range_Proof range_proof;
};

void NIZK_COCO_Framework_PP_new(COCO_Framework_PP &pp){
    pp.g = EC_POINT_new(group);
    pp.h = EC_POINT_new(group);
}

void NIZK_COCO_Framework_PP_free(COCO_Framework_PP &pp)
{ 
    EC_POINT_free(pp.g); 
    EC_POINT_free(pp.h); 
}

void NIZK_COCO_Framework_Instance_new(COCO_Framework_Instance &instance)
{
    
    instance.C = EC_POINT_new(group);
}

void NIZK_COCO_Framework_Instance_free(COCO_Framework_Instance &instance)
{
    EC_POINT_free(instance.C);
}

void NIZK_COCO_Framework_Witness_new(COCO_Framework_Witness &witness)
{
    witness.w = BN_new();
    witness.r = BN_new();
}

void NIZK_COCO_Framework_Witness_free(COCO_Framework_Witness &witness)
{
    BN_free(witness.w);
    BN_free(witness.r);
}

void NIZK_COCO_Framework_Proof_new(COCO_Framework_Proof &proof, COCO_Framework_PP &pp)
{
    proof.delta = "";
    proof.chl = BN_new();
    proof.tau = BN_new();
    proof.c.resize(pp.VECTOR_LEN); 
    proof.z.resize(pp.VECTOR_LEN); 
    proof.t.resize(pp.VECTOR_LEN); 
    ECP_vec_new(proof.c);
    BN_vec_new(proof.z); 
    BN_vec_new(proof.t);
}

void NIZK_COCO_Framework_Proof_free(COCO_Framework_Proof &proof)
{
  
    ECP_vec_free(proof.c);
    BN_free(proof.chl);
    BN_free(proof.tau);
    BN_vec_free(proof.z); 
    BN_vec_free(proof.t);
    proof.c.resize(0);
}

void COCO_Framework_PP_print(COCO_Framework_PP &pp)
{
    cout << "COCO_Framework Proofs Public parameters >>> " << endl;
    ECP_print(pp.g, "pp.g"); 
    ECP_print(pp.h, "pp.h"); 
    cout << "VECTOR_LEN: " << pp.VECTOR_LEN << endl;
}

void COCO_Framework_Instance_print(COCO_Framework_Instance &instance)
{
    cout << "COCO_Framework Proofs Instance >>> " << endl;  
    ECP_print(instance.C, "instance.c"); 
    
} 

void COCO_Framework_Witness_print(COCO_Framework_Witness &witness)
{
    cout << "COCO_Framework Proofs Witness >>> " << endl; 
    BN_print(witness.w, "w"); 
    BN_print(witness.r, "r"); 
} 

void COCO_Framework_Proof_print(COCO_Framework_Proof &proof)
{
    SplitLine_print('-'); 
    cout << "NIZKPoK for COCO_Framework Proofs >>> " << endl; 
    cout << "proof.delta: " << proof.delta << endl;
    ECP_vec_print(proof.c, "proof.c");
    BN_print(proof.chl, "proof.chl"); 
    BN_print(proof.tau, "proof.tau");
    BN_vec_print(proof.z, "proof.z");
    BN_vec_print(proof.t, "proof.t");
}

void COCO_Framework_Proof_serialize(COCO_Framework_Proof &proof, ofstream &fout)
{ 
    ECP_vec_serialize(proof.c, fout);

    BN_serialize(proof.tau,  fout);
    BN_serialize(proof.chl,  fout);
} 

void COCO_Framework_Proof_deserialize(COCO_Framework_Proof &proof, ifstream &fin)
{
    
    ECP_vec_deserialize(proof.c, fin);

    BN_deserialize(proof.tau,  fin);
    BN_deserialize(proof.chl,  fin);
} 


void NIZK_COCO_Framework_Setup(COCO_Framework_PP &pp, size_t VECTOR_LEN){
    EC_POINT_copy(pp.g, generator); 
    //EC_POINT_copy(pp.h, h);
    Hash_ECP_to_ECP(pp.g, pp.h);
    pp.VECTOR_LEN = VECTOR_LEN;
}

void NIZK_COCO_Framework_Prove(COCO_Framework_PP &pp, 
                            COCO_Framework_Instance &instance, 
                            COCO_Framework_Witness &witness, 
                            COCO_Framework_Proof &proof){
    //hard code C

    
}


bool NIZK_COCO_Framework_Verify(COCO_Framework_PP &pp, 
                            COCO_Framework_Instance &instance, 
                            COCO_Framework_Witness &witness, 
                            COCO_Framework_Proof &proof){

    

}

#endif
