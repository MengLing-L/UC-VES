/****************************************************************************
this hpp implements NIZKPoK for discrete logarithm equality 
*****************************************************************************
* @author     This file is part of PGC, developed by Yu Chen
* @paper      https://eprint.iacr.org/2019/319
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/
#ifndef __Original_Relation__
#define __Original_Relation__

#include "../common/global.hpp"
#include "../common/hash.hpp"
#include "../common/print.hpp"
#include "../common/routines.hpp"
#include "../dlog/sigma_dlog.hpp"
#include "../twisted_elgamal/twisted_elgamal.hpp"
#include "../rangeproofs/range_proofs.hpp"


struct Original_Relation_PP
{
    SIGMA_DLOG_PP dlog_pp_sig;
    vector<Range_PP> range_pp;
};

struct Original_Relation_Instance
{ 
    SIGMA_DLOG_Instance dlog_instance;
    vector<Range_Instance> range_instance;
}; 

struct Original_Relation_Witness
{
    SIGMA_DLOG_Witness dlog_witness;
    vector<Range_Witness> range_witness;
}; 
 
struct Original_Relation_Proof
{   
    SIGMA_DLOG_Proof dlog_proof;
    vector<Range_Proof> range_proof;
};

void Original_Relation_PP_new(Original_Relation_PP &pp){
    SIGMA_DLOG_PP_new(pp.dlog_pp_sig);
    pp.range_pp.resize(RANGE_SIZE);
    for(int j=0; j < RANGE_SIZE; j++){
        Range_PP_new(pp.range_pp[j]);
    }
}

void Original_Relation_PP_free(Original_Relation_PP &pp)
{ 
    SIGMA_DLOG_PP_free(pp.dlog_pp_sig);
    for(int j=0; j < RANGE_SIZE; j++){
        Range_PP_free(pp.range_pp[j]);
    }
}

void Original_Relation_Instance_new(Original_Relation_Instance &instance)
{
    
    SIGMA_DLOG_Instance_new(instance.dlog_instance);

    instance.range_instance.resize(RANGE_SIZE);
    for(int j=0; j < RANGE_SIZE; j++){
        Range_Instance_new(instance.range_instance[j]);
    }
    
}

void Original_Relation_Instance_free(Original_Relation_Instance &instance)
{
    
    SIGMA_DLOG_Instance_free(instance.dlog_instance);
    
    for(int j=0; j < RANGE_SIZE; j++){
        Range_Instance_free(instance.range_instance[j]);
    }
    
}

void Original_Relation_Witness_new(Original_Relation_Witness &witness)
{ 
    
    SIGMA_DLOG_Witness_new(witness.dlog_witness);
    witness.range_witness.resize(RANGE_SIZE);
    
    for(int j=0; j < RANGE_SIZE; j++){
        Range_Witness_new(witness.range_witness[j]);
    }
    
}

void Original_Relation_Witness_free(Original_Relation_Witness &witness)
{
    SIGMA_DLOG_Witness_free(witness.dlog_witness);
    
    for(int j=0; j < RANGE_SIZE; j++){
        Range_Witness_free(witness.range_witness[j]);
    }
}

void Original_Relation_Proof_new(Original_Relation_Proof &proof)
{
    
    SIGMA_DLOG_Proof_new(proof.dlog_proof);
    
    proof.range_proof.resize(RANGE_SIZE);        
    for(int j=0; j < RANGE_SIZE; j++){
        Range_Proof_new(proof.range_proof[j]);
    }
    
}

void Original_Relation_Proof_free(Original_Relation_Proof &proof)
{
    SIGMA_DLOG_Proof_free(proof.dlog_proof);

    for(int j=0; j < RANGE_SIZE; j++){
        Range_Proof_free(proof.range_proof[j]);
    }
}

void Original_Relation_PP_print(Original_Relation_PP &pp)
{
    SIGMA_DLOG_PP_print(pp.dlog_pp_sig);
    //Range_PP_print(pp.range_pp);
}

void Original_Relation_Instance_print(Original_Relation_Instance &instance)
{
    SIGMA_DLOG_Instance_print(instance.dlog_instance);

    for(int j=0; j < RANGE_SIZE; j++){
        Range_Instance_print(instance.range_instance[j]);
    }
} 

void Original_Relation_Witness_print(Original_Relation_Witness &witness)
{
    SIGMA_DLOG_Witness_print(witness.dlog_witness);
    
    for(int j=0; j < RANGE_SIZE; j++){
        Range_Witness_print(witness.range_witness[j]);
    }
} 

void Original_Relation_Proof_print(Original_Relation_Proof &proof)
{

    SIGMA_DLOG_Proof_print(proof.dlog_proof);
    
    
    for(int j=0; j < RANGE_SIZE; j++){
        Range_Proof_print(proof.range_proof[j]);
    }
}


void Original_Relation_Setup(Original_Relation_PP &pp, EC_POINT* &h){
    SIGMA_DLOG_Setup(pp.dlog_pp_sig, h, true);
    for(int j=0; j < RANGE_SIZE; j++){
        Range_Setup(pp.range_pp[j], h);
    }
}

void Original_Relation_Commit(Original_Relation_PP &pp, 
                            Original_Relation_Instance &instance, 
                            Original_Relation_Witness &witness,
                            //string &chl,
                            Original_Relation_Proof &proof,
                            EC_POINT* &EK){
    SIGMA_DLOG_Commit(pp.dlog_pp_sig, instance.dlog_instance, witness.dlog_witness, proof.dlog_proof, EK);
    
    for(int j=0; j < RANGE_SIZE; j++){
        Range_Prove_Commit(pp.range_pp[j], instance.range_instance[j], witness.range_witness[j], proof.range_proof[j]);
    }
}

void Original_Relation_Copy(Original_Relation_PP &pp, 
                            Original_Relation_Proof &org_proof,
                            Original_Relation_Proof &tar_proof){
    SIGMA_DLOG_Copy(pp.dlog_pp_sig, org_proof.dlog_proof, tar_proof.dlog_proof);
    
    for(int j=0; j < RANGE_SIZE; j++){
        Range_Prove_Copy(pp.range_pp[j], org_proof.range_proof[j], tar_proof.range_proof[j]);
    }
}

void Original_Relation_Res(Original_Relation_PP &pp, 
                            Original_Relation_Instance &instance, 
                            Original_Relation_Witness &witness,
                            string &chl, 
                            Original_Relation_Proof &proof){
    
    SIGMA_DLOG_Res(pp.dlog_pp_sig, instance.dlog_instance, witness.dlog_witness, chl, proof.dlog_proof);

    for(int j=0; j < RANGE_SIZE; j++){
        Range_Prove_Res(pp.range_pp[j], instance.range_instance[j], witness.range_witness[j], chl, proof.range_proof[j]);
    }
    
}

void Original_Relation_Res(Original_Relation_PP &pp, 
                            Original_Relation_Instance &instance, 
                            Original_Relation_Witness &witness,
                            BIGNUM *&chl, 
                            Original_Relation_Proof &proof){
    
    SIGMA_DLOG_Res(pp.dlog_pp_sig, instance.dlog_instance, witness.dlog_witness, chl, proof.dlog_proof);

    for(int j=0; j < RANGE_SIZE; j++){
        Range_Prove_Res(pp.range_pp[j], instance.range_instance[j], witness.range_witness[j], chl, proof.range_proof[j]);
    }
    
}


bool Original_Relation_Verify(Original_Relation_PP &pp, 
                            Original_Relation_Instance &instance,  
                            BIGNUM *&chl, 
                            Original_Relation_Proof &proof,
                            EC_POINT* &EK){
    bool validity = true;
    validity = validity && SIGMA_DLOG_Verify(pp.dlog_pp_sig, instance.dlog_instance, chl, proof.dlog_proof, EK);
    for(int j=0; j < RANGE_SIZE; j++){
        validity = validity && Range_Verify(pp.range_pp[j], instance.range_instance[j], chl, proof.range_proof[j]);
    }
    return validity;
}

bool Original_Relation_Verify(Original_Relation_PP &pp, 
                            Original_Relation_Instance &instance,  
                            string &chl, 
                            Original_Relation_Proof &proof,
                            string &res,
                            EC_POINT* &EK){
    
    SIGMA_DLOG_Verify(pp.dlog_pp_sig, instance.dlog_instance, chl, proof.dlog_proof, res, EK);

    for(int j=0; j < RANGE_SIZE; j++){
        Range_Verify(pp.range_pp[j], instance.range_instance[j], chl, proof.range_proof[j], res);
    }
}

#endif
