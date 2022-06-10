/****************************************************************************
this hpp implements NIZKPoK for discrete logarithm equality 
*****************************************************************************
* @author     This file is part of PGC, developed by Yu Chen
* @paper      https://eprint.iacr.org/2019/319
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/
#ifndef __Encrypt_witNess_or_Encrypt_signature__
#define __Encrypt_witNess_or_Encrypt_signature__

#include "../common/global.hpp"
#include "../common/hash.hpp"
#include "../common/print.hpp"
#include "../common/routines.hpp"
#include "../COCO-framework/simulate_encrypt_signature.hpp"
#include "../COCO-framework/encrypt_witness.hpp"
#include "../twisted_elgamal/twisted_elgamal.hpp"


struct Encrypt_witNess_or_Encrypt_signature_PP
{
    Witness_Encryption_AndR_PP enc_witness_pp;
    Simulation_Encrypt_Signature_PP sim_sig_pp;
};

struct Encrypt_witNess_or_Encrypt_signature_Instance
{ 
    Witness_Encryption_AndR_Instance enc_witness_instance;
    Simulation_Encrypt_Signature_Instance sim_sig_instance;
}; 

struct Encrypt_witNess_or_Encrypt_signature_Witness
{
    Witness_Encryption_AndR_Witness enc_witness_witness;
    Simulation_Encrypt_Signature_Witness sim_sig_witness;
}; 
 
struct Encrypt_witNess_or_Encrypt_signature_Proof
{   
    Witness_Encryption_AndR_Proof enc_witness_proof;
    Simulation_Encrypt_Signature_Proof sim_sig_proof;
};

void Encrypt_witNess_or_Encrypt_signature_PP_new(Encrypt_witNess_or_Encrypt_signature_PP &pp){
    Witness_Encryption_AndR_PP_new(pp.enc_witness_pp);
    Simulation_Encrypt_Signature_PP_new(pp.sim_sig_pp);
}

void Encrypt_witNess_or_Encrypt_signature_PP_free(Encrypt_witNess_or_Encrypt_signature_PP &pp)
{ 
    Witness_Encryption_AndR_PP_free(pp.enc_witness_pp);
    Simulation_Encrypt_Signature_PP_free(pp.sim_sig_pp);
}

void Encrypt_witNess_or_Encrypt_signature_Instance_new(Encrypt_witNess_or_Encrypt_signature_Instance &instance)
{   
    Witness_Encryption_AndR_Instance_new(instance.enc_witness_instance);
    Simulation_Encrypt_Signature_Instance_new(instance.sim_sig_instance);
}

void Encrypt_witNess_or_Encrypt_signature_Instance_free(Encrypt_witNess_or_Encrypt_signature_Instance &instance)
{
    Witness_Encryption_AndR_Instance_free(instance.enc_witness_instance);
    Simulation_Encrypt_Signature_Instance_free(instance.sim_sig_instance);
}

void Encrypt_witNess_or_Encrypt_signature_Witness_new(Encrypt_witNess_or_Encrypt_signature_Witness &witness)
{ 

    Witness_Encryption_AndR_Witness_new(witness.enc_witness_witness);
    Simulation_Encrypt_Signature_Witness_new(witness.sim_sig_witness);
}

void Encrypt_witNess_or_Encrypt_signature_Witness_free(Encrypt_witNess_or_Encrypt_signature_Witness &witness)
{
    Witness_Encryption_AndR_Witness_free(witness.enc_witness_witness);
    Simulation_Encrypt_Signature_Witness_free(witness.sim_sig_witness);
}

void Encrypt_witNess_or_Encrypt_signature_Proof_new(Encrypt_witNess_or_Encrypt_signature_Proof &proof)
{
    Witness_Encryption_AndR_Proof_new(proof.enc_witness_proof);
    Simulation_Encrypt_Signature_Proof_new(proof.sim_sig_proof);
}

void Encrypt_witNess_or_Encrypt_signature_Proof_free(Encrypt_witNess_or_Encrypt_signature_Proof &proof)
{
    Witness_Encryption_AndR_Proof_free(proof.enc_witness_proof);
    Simulation_Encrypt_Signature_Proof_free(proof.sim_sig_proof);
}

void Encrypt_witNess_or_Encrypt_signature_PP_print(Encrypt_witNess_or_Encrypt_signature_PP &pp)
{
    Witness_Encryption_AndR_PP_print(pp.enc_witness_pp);
    Simulation_Encrypt_Signature_PP_print(pp.sim_sig_pp);
}

void Encrypt_witNess_or_Encrypt_signature_Instance_print(Encrypt_witNess_or_Encrypt_signature_Instance &instance)
{
    Witness_Encryption_AndR_Instance_print(instance.enc_witness_instance);
    Simulation_Encrypt_Signature_Instance_print(instance.sim_sig_instance);
} 

void Encrypt_witNess_or_Encrypt_signature_Witness_print(Encrypt_witNess_or_Encrypt_signature_Witness &witness)
{
    Witness_Encryption_AndR_Witness_print(witness.enc_witness_witness); 
    Simulation_Encrypt_Signature_Witness_print(witness.sim_sig_witness);
} 

void Encrypt_witNess_or_Encrypt_signature_Proof_print(Encrypt_witNess_or_Encrypt_signature_Proof &proof)
{
    Witness_Encryption_AndR_Proof_print(proof.enc_witness_proof);
    Simulation_Encrypt_Signature_Proof_print(proof.sim_sig_proof);
}



void Encrypt_witNess_or_Encrypt_signature_Setup(Encrypt_witNess_or_Encrypt_signature_PP &pp, EC_POINT* &h, EC_POINT* &EK){
    Witness_Encryption_AndR_Setup(pp.enc_witness_pp, h, EK);
    Simulation_Encrypt_Signature_Setup(pp.sim_sig_pp, h, EK);
}


void Encrypt_witNess_or_Encrypt_signature_Prove(Encrypt_witNess_or_Encrypt_signature_PP &pp, 
                            Encrypt_witNess_or_Encrypt_signature_Instance &instance,
                            Encrypt_witNess_or_Encrypt_signature_Witness &witness,
                            string &chl,
                            string &chl1,
                            string &chl0, 
                            Encrypt_witNess_or_Encrypt_signature_Proof &proof){
    
    
    BIGNUM* tmp_chl1 = BN_new();
    BIGNUM* tmp_chl0 = BN_new();

    BN_random(tmp_chl1);

    chl1 = BN_bn2string(tmp_chl1);

    Simulation_Encrypt_Signature_Simulate_Proof(pp.sim_sig_pp, instance.sim_sig_instance, chl, chl1, proof.sim_sig_proof);

    Witness_Encryption_AndR_Commit(pp.enc_witness_pp, instance.enc_witness_instance, witness.enc_witness_witness, chl, proof.enc_witness_proof);

    BIGNUM *e = BN_new();
    Hash_String_to_BN(chl, e);

    BN_sub (tmp_chl0, e, tmp_chl1);

    chl0 = BN_bn2string(tmp_chl0);

    Witness_Encryption_AndR_Res(pp.enc_witness_pp, instance.enc_witness_instance, witness.enc_witness_witness, chl0, proof.enc_witness_proof);

    BN_free(e);
    BN_free(tmp_chl1);
    BN_free(tmp_chl0);
}


bool Encrypt_witNess_or_Encrypt_signature_Verify(Encrypt_witNess_or_Encrypt_signature_PP &pp, 
                            Encrypt_witNess_or_Encrypt_signature_Instance &instance, 
                            string &chl, 
                            string &chl1,
                            string &chl0,
                            Encrypt_witNess_or_Encrypt_signature_Proof &proof,
                            string &res){

    Witness_Encryption_AndR_Verify(pp.enc_witness_pp, instance.enc_witness_instance, chl0, proof.enc_witness_proof, res);
    
    Simulation_Encrypt_Signature_Verify(pp.sim_sig_pp, instance.sim_sig_instance, chl1, proof.sim_sig_proof, res);


    /*BIGNUM *e = BN_new();
    BIGNUM *tmp = BN_new();
    BIGNUM* tmp_chl1 = BN_new();
    BIGNUM* tmp_chl0 = BN_new();
    Hash_String_to_BN(chl, e);
    Hash_String_to_BN(chl1, tmp_chl1);
    Hash_String_to_BN(chl0, tmp_chl0);

    BN_add(tmp, tmp_chl1, tmp_chl0);


    if (BN_cmp (tmp, e) == 0){
        cout << "chl = chl1 + chl0" << endl;
    }

    BN_free(e);
    BN_free(tmp_chl1);
    BN_free(tmp_chl0);
    BN_free(tmp);*/
}

#endif
