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
#include "../COCO-framework/sigma_dlog.hpp"
#include "../twisted_elgamal/twisted_elgamal.hpp"


struct Simulation_Encrypt_Signature_PP
{
    SIGMA_DLOG_PP dlog_pp;
};

struct Simulation_Encrypt_Signature_Instance
{ 
    SIGMA_DLOG_Instance dlog_instance;
}; 

struct Simulation_Encrypt_Signature_Witness
{
    SIGMA_DLOG_Witness dlog_witness;
}; 
 
struct Simulation_Encrypt_Signature_Proof
{   
    SIGMA_DLOG_Proof dlog_proof;
    
};

void Simulation_Encrypt_Signature_PP_new(Simulation_Encrypt_Signature_PP &pp){
    SIGMA_DLOG_PP_new(pp.dlog_pp);
}

void Simulation_Encrypt_Signature_PP_free(Simulation_Encrypt_Signature_PP &pp)
{ 
    SIGMA_DLOG_PP_free(pp.dlog_pp);
}

void Simulation_Encrypt_Signature_Instance_new(Simulation_Encrypt_Signature_Instance &instance)
{   
    SIGMA_DLOG_Instance_new(instance.dlog_instance);
}

void Simulation_Encrypt_Signature_Instance_free(Simulation_Encrypt_Signature_Instance &instance)
{
    SIGMA_DLOG_Instance_free(instance.dlog_instance);
}

void Simulation_Encrypt_Signature_Witness_new(Simulation_Encrypt_Signature_Witness &witness)
{ 

    SIGMA_DLOG_Witness_new(witness.dlog_witness);
}

void Simulation_Encrypt_Signature_Witness_free(Simulation_Encrypt_Signature_Witness &witness)
{
    SIGMA_DLOG_Witness_free(witness.dlog_witness);
}

void Simulation_Encrypt_Signature_Proof_new(Simulation_Encrypt_Signature_Proof &proof)
{
    SIGMA_DLOG_Proof_new(proof.dlog_proof);
}

void Simulation_Encrypt_Signature_Proof_free(Simulation_Encrypt_Signature_Proof &proof)
{
    SIGMA_DLOG_Proof_free(proof.dlog_proof);
}

void Simulation_Encrypt_Signature_PP_print(Simulation_Encrypt_Signature_PP &pp)
{
    SIGMA_DLOG_PP_print(pp.dlog_pp);
}

void Simulation_Encrypt_Signature_Instance_print(Simulation_Encrypt_Signature_Instance &instance)
{
    SIGMA_DLOG_Instance_print(instance.dlog_instance);
} 

void Simulation_Encrypt_Signature_Witness_print(Simulation_Encrypt_Signature_Witness &witness)
{
    SIGMA_DLOG_Witness_print(witness.dlog_witness); 
} 

void Simulation_Encrypt_Signature_Proof_print(Simulation_Encrypt_Signature_Proof &proof)
{
    SIGMA_DLOG_Proof_print(proof.dlog_proof);
}



void Simulation_Encrypt_Signature_Setup(Simulation_Encrypt_Signature_PP &pp, EC_POINT* &h){
    SIGMA_DLOG_Setup(pp.dlog_pp, h, true);
}


void Simulation_Encrypt_Signature_Simulate_Proof(Simulation_Encrypt_Signature_PP &pp, 
                            Simulation_Encrypt_Signature_Instance &instance,
                            string &chl,
                            string &chl1, 
                            Simulation_Encrypt_Signature_Proof &proof,
                            EC_POINT* &EK){
    
    SIGMA_DLOG_Simulate_Proof(pp.dlog_pp, instance.dlog_instance, chl, chl1, proof.dlog_proof, EK);

}


bool Simulation_Encrypt_Signature_Verify(Simulation_Encrypt_Signature_PP &pp, 
                            Simulation_Encrypt_Signature_Instance &instance, 
                            string &chl, 
                            Simulation_Encrypt_Signature_Proof &proof,
                            EC_POINT* &EK){

    
    SIGMA_DLOG_Verify(pp.dlog_pp, instance.dlog_instance, chl, proof.dlog_proof, EK);

}

bool Simulation_Encrypt_Signature_Verify(Simulation_Encrypt_Signature_PP &pp, 
                            Simulation_Encrypt_Signature_Instance &instance, 
                            string &chl, 
                            Simulation_Encrypt_Signature_Proof &proof,
                            string &res,
                            EC_POINT* &EK){

    
    SIGMA_DLOG_Verify(pp.dlog_pp, instance.dlog_instance, chl, proof.dlog_proof, res, EK);

}

#endif
