/****************************************************************************
this hpp implements NIZKPoK for discrete logarithm equality 
*****************************************************************************
* @author     This file is part of PGC, developed by Yu Chen
* @paper      https://eprint.iacr.org/2019/319
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/
#ifndef __Witness_Encryption_AndR__
#define __Witness_Encryption_AndR__

#include "../common/global.hpp"
#include "../common/hash.hpp"
#include "../common/print.hpp"
#include "../common/routines.hpp"

struct Witness_Encryption_AndR_PP
{
    EC_POINT *g, *h; 
    size_t VECTOR_LEN; // VECTOR_LEN = 4;
    EC_POINT *EK_R;
    EC_POINT *EK_COCO;
};

struct Witness_Encryption_AndR_Instance
{ 
    
}; 

struct Witness_Encryption_AndR_Witness
{
    vector<Range_Witness> range_witness;
}; 
 
struct Witness_Encryption_AndR_Proof
{
    
};

void NIZK_Witness_Encryption_AndR_PP_new(Witness_Encryption_AndR_PP &pp){
    pp.g = EC_POINT_new(group);
    pp.h = EC_POINT_new(group);
}

void NIZK_Witness_Encryption_AndR_PP_free(Witness_Encryption_AndR_PP &pp)
{ 
    EC_POINT_free(pp.g); 
    EC_POINT_free(pp.h); 
}

void NIZK_Witness_Encryption_AndR_Instance_new(Witness_Encryption_AndR_Instance &instance)
{
    
    instance.C = EC_POINT_new(group);
}

void NIZK_Witness_Encryption_AndR_Instance_free(Witness_Encryption_AndR_Instance &instance)
{
    EC_POINT_free(instance.C);
}

void NIZK_Witness_Encryption_AndR_Witness_new(Witness_Encryption_AndR_Witness &witness)
{
    witness.w = BN_new();
    witness.r = BN_new();
}

void NIZK_Witness_Encryption_AndR_Witness_free(Witness_Encryption_AndR_Witness &witness)
{
    BN_free(witness.w);
    BN_free(witness.r);
}

void NIZK_Witness_Encryption_AndR_Proof_new(Witness_Encryption_AndR_Proof &proof, Witness_Encryption_AndR_PP &pp)
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

void NIZK_Witness_Encryption_AndR_Proof_free(Witness_Encryption_AndR_Proof &proof)
{
  
    ECP_vec_free(proof.c);
    BN_free(proof.chl);
    BN_free(proof.tau);
    BN_vec_free(proof.z); 
    BN_vec_free(proof.t);
    proof.c.resize(0);
}

void Witness_Encryption_AndR_PP_print(Witness_Encryption_AndR_PP &pp)
{
    cout << "Witness_Encryption_AndR Proofs Public parameters >>> " << endl;
    ECP_print(pp.g, "pp.g"); 
    ECP_print(pp.h, "pp.h"); 
    cout << "VECTOR_LEN: " << pp.VECTOR_LEN << endl;
}

void Witness_Encryption_AndR_Instance_print(Witness_Encryption_AndR_Instance &instance)
{
    cout << "Witness_Encryption_AndR Proofs Instance >>> " << endl;  
    ECP_print(instance.C, "instance.c"); 
    
} 

void Witness_Encryption_AndR_Witness_print(Witness_Encryption_AndR_Witness &witness)
{
    cout << "Witness_Encryption_AndR Proofs Witness >>> " << endl; 
    BN_print(witness.w, "w"); 
    BN_print(witness.r, "r"); 
} 

void Witness_Encryption_AndR_Proof_print(Witness_Encryption_AndR_Proof &proof)
{
    SplitLine_print('-'); 
    cout << "NIZKPoK for Witness_Encryption_AndR Proofs >>> " << endl; 
    cout << "proof.delta: " << proof.delta << endl;
    ECP_vec_print(proof.c, "proof.c");
    BN_print(proof.chl, "proof.chl"); 
    BN_print(proof.tau, "proof.tau");
    BN_vec_print(proof.z, "proof.z");
    BN_vec_print(proof.t, "proof.t");
}

void Witness_Encryption_AndR_Proof_serialize(Witness_Encryption_AndR_Proof &proof, ofstream &fout)
{ 
    ECP_vec_serialize(proof.c, fout);

    BN_serialize(proof.tau,  fout);
    BN_serialize(proof.chl,  fout);
} 

void Witness_Encryption_AndR_Proof_deserialize(Witness_Encryption_AndR_Proof &proof, ifstream &fin)
{
    
    ECP_vec_deserialize(proof.c, fin);

    BN_deserialize(proof.tau,  fin);
    BN_deserialize(proof.chl,  fin);
} 


void NIZK_Witness_Encryption_AndR_Setup(Witness_Encryption_AndR_PP &pp, size_t VECTOR_LEN){
    EC_POINT_copy(pp.g, generator); 
    //EC_POINT_copy(pp.h, h);
    Hash_ECP_to_ECP(pp.g, pp.h);
    pp.VECTOR_LEN = VECTOR_LEN;
}

void NIZK_Witness_Encryption_AndR_Prove(Witness_Encryption_AndR_PP &pp, 
                            Witness_Encryption_AndR_Instance &instance, 
                            Witness_Encryption_AndR_Witness &witness, 
                            Witness_Encryption_AndR_Proof &proof){
    //hard code C

    
}


bool NIZK_Witness_Encryption_AndR_Verify(Witness_Encryption_AndR_PP &pp, 
                            Witness_Encryption_AndR_Instance &instance, 
                            Witness_Encryption_AndR_Witness &witness, 
                            Witness_Encryption_AndR_Proof &proof){

    

}

#endif
