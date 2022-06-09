/****************************************************************************
this hpp implements NIZKPoK for discrete logarithm equality 
*****************************************************************************
* @author     This file is part of PGC, developed by Yu Chen
* @paper      https://eprint.iacr.org/2019/319
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/
#ifndef __Simulation_Encrypt_Signature__
#define __Simulation_Encrypt_Signature__

#include "../common/global.hpp"
#include "../common/hash.hpp"
#include "../common/print.hpp"
#include "../common/routines.hpp"
#include "../COCO-framework/nizk_dlog.hpp"
#include "../twisted_elgamal/twisted_elgamal.hpp"

const size_t DLOG_SIZE = 3;

struct Simulation_Encrypt_Signature_PP
{
    DLOG_PP dlog_pp;
};

struct Simulation_Encrypt_Signature_Instance
{ 
    DLOG_Instance dlog_instance;
}; 

struct Simulation_Encrypt_Signature_Witness
{
    DLOG_Witness dlog_witness;
}; 
 
struct Simulation_Encrypt_Signature_Proof
{   
    DLOG_Proof dlog_proof;
    
};

void NIZK_Simulation_Encrypt_Signature_PP_new(Simulation_Encrypt_Signature_PP &pp){
    NIZK_DLOG_PP_new(pp.dlog_pp);
}

void NIZK_Simulation_Encrypt_Signature_PP_free(Simulation_Encrypt_Signature_PP &pp)
{ 
    NIZK_DLOG_PP_free(pp.dlog_pp);
}

void NIZK_Simulation_Encrypt_Signature_Instance_new(Simulation_Encrypt_Signature_Instance &instance)
{   
    NIZK_DLOG_Instance_new(instance.dlog_instance);
}

void NIZK_Simulation_Encrypt_Signature_Instance_free(Simulation_Encrypt_Signature_Instance &instance)
{
    NIZK_DLOG_Instance_free(instance.dlog_instance);
}

void NIZK_Simulation_Encrypt_Signature_Witness_new(Simulation_Encrypt_Signature_Witness &witness)
{ 

    NIZK_DLOG_Witness_new(witness.dlog_witness);
}

void NIZK_Simulation_Encrypt_Signature_Witness_free(Simulation_Encrypt_Signature_Witness &witness)
{
    NIZK_DLOG_Witness_free(witness.dlog_witness);
}

void NIZK_Simulation_Encrypt_Signature_Proof_new(Simulation_Encrypt_Signature_Proof &proof)
{
    NIZK_DLOG_Proof_new(proof.dlog_proof);
}

void NIZK_Simulation_Encrypt_Signature_Proof_free(Simulation_Encrypt_Signature_Proof &proof)
{
    NIZK_DLOG_Proof_free(proof.dlog_proof);
}

void Simulation_Encrypt_Signature_PP_print(Simulation_Encrypt_Signature_PP &pp)
{
    DLOG_PP_print(pp.dlog_pp);
}

void Simulation_Encrypt_Signature_Instance_print(Simulation_Encrypt_Signature_Instance &instance)
{
    DLOG_Instance_print(instance.dlog_instance);
} 

void Simulation_Encrypt_Signature_Witness_print(Simulation_Encrypt_Signature_Witness &witness)
{
    DLOG_Witness_print(witness.dlog_witness); 
} 

void Simulation_Encrypt_Signature_Proof_print(Simulation_Encrypt_Signature_Proof &proof)
{
    DLOG_Proof_print(proof.dlog_proof);
}



void NIZK_Simulation_Encrypt_Signature_Setup(Simulation_Encrypt_Signature_PP &pp, EC_POINT* &h, EC_POINT* &EK){
    NIZK_DLOG_Setup(pp.dlog_pp, h, EK, true);
}


void NIZK_Simulation_Encrypt_Signature_Simulate_Proof(Simulation_Encrypt_Signature_PP &pp, 
                            Simulation_Encrypt_Signature_Instance &instance,
                            string &chl, 
                            Simulation_Encrypt_Signature_Proof &proof){
    
    NIZK_DLOG_Simulate_Proof(pp.dlog_pp, instance.dlog_instance, chl, proof.dlog_proof);

}


bool NIZK_Simulation_Encrypt_Signature_Verify(Simulation_Encrypt_Signature_PP &pp, 
                            Simulation_Encrypt_Signature_Instance &instance, 
                            Simulation_Encrypt_Signature_Witness &witness, 
                            string &chl, 
                            Simulation_Encrypt_Signature_Proof &proof,
                            string &res){

    
    NIZK_DLOG_Verify(pp.dlog_pp, instance.dlog_instance, chl, proof.dlog_proof, res);

}

#endif
