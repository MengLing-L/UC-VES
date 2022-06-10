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
#include "../COCO-framework/sigma_dlog.hpp"
#include "../twisted_elgamal/twisted_elgamal.hpp"

const size_t SIGMA_DLOG_SIZE = 3;

struct Witness_Encryption_AndR_PP
{
    SIGMA_DLOG_PP dlog_pp_unsig;
    SIGMA_DLOG_PP dlog_pp_sig;
};

struct Witness_Encryption_AndR_Instance
{ 
    vector<SIGMA_DLOG_Instance> dlog_instance;
}; 

struct Witness_Encryption_AndR_Witness
{
    vector<SIGMA_DLOG_Witness> dlog_witness;
}; 
 
struct Witness_Encryption_AndR_Proof
{   
    vector<SIGMA_DLOG_Proof> dlog_proof;
    
};

void Witness_Encryption_AndR_PP_new(Witness_Encryption_AndR_PP &pp){
    SIGMA_DLOG_PP_new(pp.dlog_pp_unsig);
    SIGMA_DLOG_PP_new(pp.dlog_pp_sig);
}

void Witness_Encryption_AndR_PP_free(Witness_Encryption_AndR_PP &pp)
{ 
    SIGMA_DLOG_PP_free(pp.dlog_pp_unsig);
    SIGMA_DLOG_PP_free(pp.dlog_pp_sig);
}

void Witness_Encryption_AndR_Instance_new(Witness_Encryption_AndR_Instance &instance)
{
    instance.dlog_instance.resize(SIGMA_DLOG_SIZE);
    for (int i=0; i < SIGMA_DLOG_SIZE; i++){
        SIGMA_DLOG_Instance_new(instance.dlog_instance[i]);
    }
}

void Witness_Encryption_AndR_Instance_free(Witness_Encryption_AndR_Instance &instance)
{
    for (int i=0; i < SIGMA_DLOG_SIZE; i++){
        SIGMA_DLOG_Instance_free(instance.dlog_instance[i]);
    }
}

void Witness_Encryption_AndR_Witness_new(Witness_Encryption_AndR_Witness &witness)
{ 
    witness.dlog_witness.resize(SIGMA_DLOG_SIZE);
    for (int i=0; i < SIGMA_DLOG_SIZE; i++){
        SIGMA_DLOG_Witness_new(witness.dlog_witness[i]);
    }
}

void Witness_Encryption_AndR_Witness_free(Witness_Encryption_AndR_Witness &witness)
{
    for (int i=0; i < SIGMA_DLOG_SIZE; i++){
        SIGMA_DLOG_Witness_free(witness.dlog_witness[i]);
    }
}

void Witness_Encryption_AndR_Proof_new(Witness_Encryption_AndR_Proof &proof)
{
    proof.dlog_proof.resize(SIGMA_DLOG_SIZE);
    for (int i=0; i < SIGMA_DLOG_SIZE; i++){
        SIGMA_DLOG_Proof_new(proof.dlog_proof[i]);
    }
}

void Witness_Encryption_AndR_Proof_free(Witness_Encryption_AndR_Proof &proof)
{
  
    for (int i=0; i < SIGMA_DLOG_SIZE; i++){
        SIGMA_DLOG_Proof_free(proof.dlog_proof[i]);
    }
}

void Witness_Encryption_AndR_PP_print(Witness_Encryption_AndR_PP &pp)
{
    SIGMA_DLOG_PP_print(pp.dlog_pp_unsig);
    SIGMA_DLOG_PP_print(pp.dlog_pp_sig);
}

void Witness_Encryption_AndR_Instance_print(Witness_Encryption_AndR_Instance &instance)
{
    for (int i=0; i < SIGMA_DLOG_SIZE; i++){
        SIGMA_DLOG_Instance_print(instance.dlog_instance[i]);
    } 
    
} 

void Witness_Encryption_AndR_Witness_print(Witness_Encryption_AndR_Witness &witness)
{
    for (int i=0; i < SIGMA_DLOG_SIZE; i++){
        SIGMA_DLOG_Witness_print(witness.dlog_witness[i]);
    } 
} 

void Witness_Encryption_AndR_Proof_print(Witness_Encryption_AndR_Proof &proof)
{
    for (int i=0; i < SIGMA_DLOG_SIZE; i++){
        SIGMA_DLOG_Proof_print(proof.dlog_proof[i]);
    } 
}



void Witness_Encryption_AndR_Setup(Witness_Encryption_AndR_PP &pp, EC_POINT* &h, EC_POINT* &EK){
    SIGMA_DLOG_Setup(pp.dlog_pp_sig, h, EK, true);
    SIGMA_DLOG_Setup(pp.dlog_pp_unsig, h, EK, false);
}

void Witness_Encryption_AndR_Commit(Witness_Encryption_AndR_PP &pp, 
                            Witness_Encryption_AndR_Instance &instance, 
                            Witness_Encryption_AndR_Witness &witness,
                            string &chl,
                            Witness_Encryption_AndR_Proof &proof){
    
    SIGMA_DLOG_Commit(pp.dlog_pp_unsig, instance.dlog_instance[0], witness.dlog_witness[0], chl, proof.dlog_proof[0]);
    SIGMA_DLOG_Commit(pp.dlog_pp_unsig, instance.dlog_instance[1], witness.dlog_witness[1], chl, proof.dlog_proof[1]);
    SIGMA_DLOG_Commit(pp.dlog_pp_sig, instance.dlog_instance[2], witness.dlog_witness[2], chl, proof.dlog_proof[2]);

}

void Witness_Encryption_AndR_Res(Witness_Encryption_AndR_PP &pp, 
                            Witness_Encryption_AndR_Instance &instance, 
                            Witness_Encryption_AndR_Witness &witness,
                            string &chl, 
                            Witness_Encryption_AndR_Proof &proof){
    
    SIGMA_DLOG_Res(pp.dlog_pp_unsig, instance.dlog_instance[0], witness.dlog_witness[0], chl, proof.dlog_proof[0]);
    SIGMA_DLOG_Res(pp.dlog_pp_unsig, instance.dlog_instance[1], witness.dlog_witness[1], chl, proof.dlog_proof[1]);
    SIGMA_DLOG_Res(pp.dlog_pp_sig, instance.dlog_instance[2], witness.dlog_witness[2], chl, proof.dlog_proof[2]);

}

void Witness_Encryption_AndR_Prove(Witness_Encryption_AndR_PP &pp, 
                            Witness_Encryption_AndR_Instance &instance, 
                            Witness_Encryption_AndR_Witness &witness,
                            string &chl, 
                            Witness_Encryption_AndR_Proof &proof){
    
    SIGMA_DLOG_Prove(pp.dlog_pp_unsig, instance.dlog_instance[0], witness.dlog_witness[0], chl, proof.dlog_proof[0]);
    SIGMA_DLOG_Prove(pp.dlog_pp_unsig, instance.dlog_instance[1], witness.dlog_witness[1], chl, proof.dlog_proof[1]);
    SIGMA_DLOG_Prove(pp.dlog_pp_sig, instance.dlog_instance[2], witness.dlog_witness[2], chl, proof.dlog_proof[2]);

}


bool Witness_Encryption_AndR_Verify(Witness_Encryption_AndR_PP &pp, 
                            Witness_Encryption_AndR_Instance &instance,  
                            string &chl, 
                            Witness_Encryption_AndR_Proof &proof){

    
    SIGMA_DLOG_Verify(pp.dlog_pp_unsig, instance.dlog_instance[0], chl, proof.dlog_proof[0]);
    SIGMA_DLOG_Verify(pp.dlog_pp_unsig, instance.dlog_instance[1], chl, proof.dlog_proof[1]);
    SIGMA_DLOG_Verify(pp.dlog_pp_sig, instance.dlog_instance[2], chl, proof.dlog_proof[2]);

}

bool Witness_Encryption_AndR_Verify(Witness_Encryption_AndR_PP &pp, 
                            Witness_Encryption_AndR_Instance &instance,  
                            string &chl, 
                            Witness_Encryption_AndR_Proof &proof,
                            string &res){
    
    SIGMA_DLOG_Verify(pp.dlog_pp_unsig, instance.dlog_instance[0], chl, proof.dlog_proof[0], res);
    SIGMA_DLOG_Verify(pp.dlog_pp_unsig, instance.dlog_instance[1], chl, proof.dlog_proof[1], res);
    SIGMA_DLOG_Verify(pp.dlog_pp_sig, instance.dlog_instance[2], chl, proof.dlog_proof[2], res);

}

#endif
