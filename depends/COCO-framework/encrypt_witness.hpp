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
#include "../COCO-framework/nizk_dlog.hpp"
#include "../twisted_elgamal/twisted_elgamal.hpp"

const size_t DLOG_SIZE = 3;

struct Witness_Encryption_AndR_PP
{
    DLOG_PP dlog_pp_unsig;
    DLOG_PP dlog_pp_sig;
};

struct Witness_Encryption_AndR_Instance
{ 
    vector<DLOG_Instance> dlog_instance;
}; 

struct Witness_Encryption_AndR_Witness
{
    vector<DLOG_Witness> dlog_witness;
}; 
 
struct Witness_Encryption_AndR_Proof
{   
    vector<DLOG_Proof> dlog_proof;
    
};

void NIZK_Witness_Encryption_AndR_PP_new(Witness_Encryption_AndR_PP &pp){
    NIZK_DLOG_PP_new(pp.dlog_pp_unsig);
    NIZK_DLOG_PP_new(pp.dlog_pp_sig);
}

void NIZK_Witness_Encryption_AndR_PP_free(Witness_Encryption_AndR_PP &pp)
{ 
    NIZK_DLOG_PP_free(pp.dlog_pp_unsig);
    NIZK_DLOG_PP_free(pp.dlog_pp_sig);
}

void NIZK_Witness_Encryption_AndR_Instance_new(Witness_Encryption_AndR_Instance &instance)
{   
    for (int i=0; i < DLOG_SIZE; i++){
        NIZK_DLOG_Instance_new(instance.dlog_instance[i]);
    }
}

void NIZK_Witness_Encryption_AndR_Instance_free(Witness_Encryption_AndR_Instance &instance)
{
    for (int i=0; i < DLOG_SIZE; i++){
        NIZK_DLOG_Instance_free(instance.dlog_instance[i]);
    }
}

void NIZK_Witness_Encryption_AndR_Witness_new(Witness_Encryption_AndR_Witness &witness)
{
    for (int i=0; i < DLOG_SIZE; i++){
        NIZK_DLOG_Witness_new(witness.dlog_witness[i]);
    }
}

void NIZK_Witness_Encryption_AndR_Witness_free(Witness_Encryption_AndR_Witness &witness)
{
    for (int i=0; i < DLOG_SIZE; i++){
        NIZK_DLOG_Witness_free(witness.dlog_witness[i]);
    }
}

void NIZK_Witness_Encryption_AndR_Proof_new(Witness_Encryption_AndR_Proof &proof)
{
    for (int i=0; i < DLOG_SIZE; i++){
        NIZK_DLOG_Proof_new(proof.dlog_proof[i]);
    }
}

void NIZK_Witness_Encryption_AndR_Proof_free(Witness_Encryption_AndR_Proof &proof)
{
  
    for (int i=0; i < DLOG_SIZE; i++){
        NIZK_DLOG_Proof_free(proof.dlog_proof[i]);
    }
}

void Witness_Encryption_AndR_PP_print(Witness_Encryption_AndR_PP &pp)
{
    DLOG_PP_print(pp.dlog_pp_unsig);
    DLOG_PP_print(pp.dlog_pp_sig);
}

void Witness_Encryption_AndR_Instance_print(Witness_Encryption_AndR_Instance &instance)
{
    for (int i=0; i < DLOG_SIZE; i++){
        DLOG_Instance_print(instance.dlog_instance[i]);
    } 
    
} 

void Witness_Encryption_AndR_Witness_print(Witness_Encryption_AndR_Witness &witness)
{
    for (int i=0; i < DLOG_SIZE; i++){
        DLOG_Witness_print(witness.dlog_witness[i]);
    } 
} 

void Witness_Encryption_AndR_Proof_print(Witness_Encryption_AndR_Proof &proof)
{
    for (int i=0; i < DLOG_SIZE; i++){
        DLOG_Proof_print(proof.dlog_proof[i]);
    } 
}



void NIZK_Witness_Encryption_AndR_Setup(Witness_Encryption_AndR_PP &pp, EC_POINT* &h, EC_POINT* &EK){
    NIZK_DLOG_Setup(pp.dlog_pp_sig, h, EK, true);
    NIZK_DLOG_Setup(pp.dlog_pp_unsig, h, EK, false);
}

void NIZK_Witness_Encryption_AndR_Prove_Compute_Chl(Witness_Encryption_AndR_PP &pp, 
                            Witness_Encryption_AndR_Instance &instance, 
                            Witness_Encryption_AndR_Witness &witness,
                            string &chl, 
                            Witness_Encryption_AndR_Proof &proof){
    
    NIZK_DLOG_Prove_Compute_Chl(pp.dlog_pp_unsig, instance.dlog_instance[0], witness.dlog_witness[0], chl, proof.dlog_proof[0]);
    NIZK_DLOG_Prove_Compute_Chl(pp.dlog_pp_unsig, instance.dlog_instance[1], witness.dlog_witness[1], chl, proof.dlog_proof[1]);
    NIZK_DLOG_Prove_Compute_Chl(pp.dlog_pp_sig, instance.dlog_instance[2], witness.dlog_witness[2], chl, proof.dlog_proof[2]);

}

void NIZK_Witness_Encryption_AndR_Prove_Compute_Proof(Witness_Encryption_AndR_PP &pp, 
                            Witness_Encryption_AndR_Instance &instance, 
                            Witness_Encryption_AndR_Witness &witness,
                            string &chl, 
                            Witness_Encryption_AndR_Proof &proof){
    
    NIZK_DLOG_Prove_Compute_Proof(pp.dlog_pp_unsig, instance.dlog_instance[0], witness.dlog_witness[0], chl, proof.dlog_proof[0]);
    NIZK_DLOG_Prove_Compute_Proof(pp.dlog_pp_unsig, instance.dlog_instance[1], witness.dlog_witness[1], chl, proof.dlog_proof[1]);
    NIZK_DLOG_Prove_Compute_Proof(pp.dlog_pp_sig, instance.dlog_instance[2], witness.dlog_witness[2], chl, proof.dlog_proof[2]);

}


bool NIZK_Witness_Encryption_AndR_Verify(Witness_Encryption_AndR_PP &pp, 
                            Witness_Encryption_AndR_Instance &instance, 
                            Witness_Encryption_AndR_Witness &witness, 
                            string &chl, 
                            Witness_Encryption_AndR_Proof &proof,
                            string &res){

    
    NIZK_DLOG_Verify(pp.dlog_pp_unsig, instance.dlog_instance[0], chl, proof.dlog_proof[0], res);
    NIZK_DLOG_Verify(pp.dlog_pp_unsig, instance.dlog_instance[1], chl, proof.dlog_proof[1], res);
    NIZK_DLOG_Verify(pp.dlog_pp_sig, instance.dlog_instance[2], chl, proof.dlog_proof[2], res);

}

#endif
