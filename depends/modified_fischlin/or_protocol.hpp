/****************************************************************************
this hpp implements NIZKPoK for discrete logarithm equality 
*****************************************************************************
* @author     This file is part of PGC, developed by Yu Chen
* @paper      https://eprint.iacr.org/2019/319
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/
#ifndef __OR__
#define __OR__

#include "../common/global.hpp"
#include "../common/hash.hpp"
#include "../common/print.hpp"
#include "../common/routines.hpp"
#include "../modified_fischlin/samplable_hard.hpp"
#include "../customized_relation/original_relation.hpp"
#include "../twisted_elgamal/twisted_elgamal.hpp"


struct OR_PP
{
    Original_Relation_PP original_relation_pp;
    SAMPLABLE_HARD_PP samplable_hard_pp;
};

struct OR_Instance
{ 
    Original_Relation_Instance original_relation_instance;
    SAMPLABLE_HARD_Instance samplable_hard_instance;
}; 

struct OR_Witness
{
    Original_Relation_Witness original_relation_witness;
    SAMPLABLE_HARD_Witness samplable_hard_witness;
}; 
 
struct OR_Proof
{   
    Original_Relation_Proof original_relation_proof;
    SAMPLABLE_HARD_Proof samplable_hard_proof;
};

void OR_PP_new(OR_PP &pp){
    Original_Relation_PP_new(pp.original_relation_pp);
    SAMPLABLE_HARD_PP_new(pp.samplable_hard_pp);
}

void OR_PP_free(OR_PP &pp)
{ 
    Original_Relation_PP_free(pp.original_relation_pp);
    SAMPLABLE_HARD_PP_free(pp.samplable_hard_pp);
}

void OR_Instance_new(OR_Instance &instance)
{   
    Original_Relation_Instance_new(instance.original_relation_instance);
    SAMPLABLE_HARD_Instance_new(instance.samplable_hard_instance);
}

void OR_Instance_free(OR_Instance &instance)
{
    Original_Relation_Instance_free(instance.original_relation_instance);
    SAMPLABLE_HARD_Instance_free(instance.samplable_hard_instance);
}

void OR_Witness_new(OR_Witness &witness)
{ 

    Original_Relation_Witness_new(witness.original_relation_witness);
    SAMPLABLE_HARD_Witness_new(witness.samplable_hard_witness);
}

void OR_Witness_free(OR_Witness &witness)
{
    Original_Relation_Witness_free(witness.original_relation_witness);
    SAMPLABLE_HARD_Witness_free(witness.samplable_hard_witness);
}

void OR_Proof_new(OR_Proof &proof)
{
    Original_Relation_Proof_new(proof.original_relation_proof);
    SAMPLABLE_HARD_Proof_new(proof.samplable_hard_proof);
}

void OR_Proof_free(OR_Proof &proof)
{
    Original_Relation_Proof_free(proof.original_relation_proof);
    SAMPLABLE_HARD_Proof_free(proof.samplable_hard_proof);
}

void OR_PP_print(OR_PP &pp)
{
    Original_Relation_PP_print(pp.original_relation_pp);
    SAMPLABLE_HARD_PP_print(pp.samplable_hard_pp);
}

void OR_Instance_print(OR_Instance &instance)
{
    Original_Relation_Instance_print(instance.original_relation_instance);
    SAMPLABLE_HARD_Instance_print(instance.samplable_hard_instance);
} 

void OR_Witness_print(OR_Witness &witness)
{
    Original_Relation_Witness_print(witness.original_relation_witness); 
    SAMPLABLE_HARD_Witness_print(witness.samplable_hard_witness);
} 

void OR_Proof_print(OR_Proof &proof)
{
    Original_Relation_Proof_print(proof.original_relation_proof);
    SAMPLABLE_HARD_Proof_print(proof.samplable_hard_proof);
}



void OR_Setup(OR_PP &pp, EC_POINT* &h){
    Original_Relation_Setup(pp.original_relation_pp, h);
    SAMPLABLE_HARD_Setup(pp.samplable_hard_pp);
}


/*void OR_Prove(OR_PP &pp, 
                            OR_Instance &instance,
                            OR_Witness &witness,
                            string &chl,
                            string &chl1,
                            string &chl0, 
                            OR_Proof &proof,
                            EC_POINT* &EK,
                            BIGNUM* &tmp_chl1){
    
    
    //BIGNUM* tmp_chl1 = BN_new();
    BIGNUM* tmp_chl0 = BN_new();

    chl1 = BN_bn2string(tmp_chl1);

    SAMPLABLE_HARD_Simulate_Proof(pp.samplable_hard_pp, instance.samplable_hard_instance, chl, chl1, proof.samplable_hard_proof);

    Original_Relation_Commit(pp.original_relation_pp, instance.original_relation_instance, witness.original_relation_witness, chl, proof.original_relation_proof, EK);

    BIGNUM *e = BN_new();
    String_to_BN(chl, e);

    BN_sub (tmp_chl0, e, tmp_chl1);

    chl0 = BN_bn2string(tmp_chl0);

    Original_Relation_Res(pp.original_relation_pp, instance.original_relation_instance, witness.original_relation_witness, chl0, proof.original_relation_proof);

    BN_free(e);
    //BN_free(tmp_chl1);
    BN_free(tmp_chl0);
}*/

void OR_Commit(OR_PP &pp, 
                            OR_Instance &instance,
                            OR_Witness &witness,
                            //string &chl,
                            BIGNUM *&chl1,
                            OR_Proof &proof,
                            EC_POINT* &EK){
    
    
    //BIGNUM* tmp_chl1 = BN_new();

    //chl1 = BN_bn2string(tmp_chl1);

    SAMPLABLE_HARD_Simulate_Proof(pp.samplable_hard_pp, instance.samplable_hard_instance, chl1, proof.samplable_hard_proof);

    Original_Relation_Commit(pp.original_relation_pp, instance.original_relation_instance, witness.original_relation_witness, proof.original_relation_proof, EK);

}

void OR_Copy(OR_PP &pp, 
                            OR_Instance &instance,
                            //string &chl,
                            BIGNUM *&chl1,
                            OR_Proof &org_proof,
                            OR_Proof &tar_proof){
    
    
    //BIGNUM* tmp_chl1 = BN_new();

    //chl1 = BN_bn2string(tmp_chl1);

    SAMPLABLE_HARD_Simulate_Proof(pp.samplable_hard_pp, instance.samplable_hard_instance, chl1, tar_proof.samplable_hard_proof);

    Original_Relation_Copy(pp.original_relation_pp,  org_proof.original_relation_proof, tar_proof.original_relation_proof);

}

void OR_Res(OR_PP &pp, 
                            OR_Instance &instance,
                            OR_Witness &witness,
                            OR_Proof &proof,
                            EC_POINT* &EK,
                            BIGNUM* &chl0){
    Original_Relation_Res(pp.original_relation_pp, instance.original_relation_instance, witness.original_relation_witness, chl0, proof.original_relation_proof);
}


bool OR_Verify(OR_PP &pp, 
                            OR_Instance &instance, 
                            string &chl, 
                            string &chl1,
                            string &chl0,
                            OR_Proof &proof,
                            string &res,
                            EC_POINT* &EK){
    SAMPLABLE_HARD_Verify(pp.samplable_hard_pp, instance.samplable_hard_instance, chl1, proof.samplable_hard_proof, res);

    Original_Relation_Verify(pp.original_relation_pp, instance.original_relation_instance, chl0, proof.original_relation_proof, res, EK);
    


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

bool OR_Verify(OR_PP &pp, 
                            OR_Instance &instance, 
                            BIGNUM *&chl, 
                            BIGNUM *&chl1,
                            BIGNUM *&chl0,
                            OR_Proof &proof,
                            EC_POINT* &EK){
    return SAMPLABLE_HARD_Verify(pp.samplable_hard_pp, instance.samplable_hard_instance, chl1, proof.samplable_hard_proof, EK) 
                && Original_Relation_Verify(pp.original_relation_pp, instance.original_relation_instance, chl0, proof.original_relation_proof, EK);
    


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
