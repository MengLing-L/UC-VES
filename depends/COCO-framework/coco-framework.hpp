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
#include "../COCO-framework/or_protocol.hpp"
#include "../twisted_elgamal/twisted_elgamal.hpp"

struct COCO_Framework_PP
{
    Encrypt_witNess_or_Encrypt_signature_PP pp;
};

struct COCO_Framework_Instance
{ 
    Encrypt_witNess_or_Encrypt_signature_Instance instance; 
}; 

struct COCO_Framework_Witness
{
    Encrypt_witNess_or_Encrypt_signature_Witness witness;
}; 
 
struct COCO_Framework_Proof
{
    Encrypt_witNess_or_Encrypt_signature_Proof proof;
    string chl1;
    string chl0;
};

void COCO_Framework_PP_new(COCO_Framework_PP &pp){
    Encrypt_witNess_or_Encrypt_signature_PP_new(pp.pp);
}

void COCO_Framework_PP_free(COCO_Framework_PP &pp)
{ 
    Encrypt_witNess_or_Encrypt_signature_PP_free(pp.pp);
}

void COCO_Framework_Instance_new(COCO_Framework_Instance &instance)
{
    
    Encrypt_witNess_or_Encrypt_signature_Instance_new(instance.instance);
}

void COCO_Framework_Instance_free(COCO_Framework_Instance &instance)
{
    Encrypt_witNess_or_Encrypt_signature_Instance_free(instance.instance);
}

void COCO_Framework_Witness_new(COCO_Framework_Witness &witness)
{
    Encrypt_witNess_or_Encrypt_signature_Witness_new(witness.witness);
}

void COCO_Framework_Witness_free(COCO_Framework_Witness &witness)
{
    Encrypt_witNess_or_Encrypt_signature_Witness_free(witness.witness);
}

void COCO_Framework_Proof_new(COCO_Framework_Proof &proof)
{
    Encrypt_witNess_or_Encrypt_signature_Proof_new(proof.proof);
    proof.chl1 = "";
    proof.chl0 = "";
}

void COCO_Framework_Proof_free(COCO_Framework_Proof &proof)
{
    Encrypt_witNess_or_Encrypt_signature_Proof_free(proof.proof);
}

void COCO_Framework_PP_print(COCO_Framework_PP &pp)
{
    Encrypt_witNess_or_Encrypt_signature_PP_print(pp.pp);
}

void COCO_Framework_Instance_print(COCO_Framework_Instance &instance)
{
    Encrypt_witNess_or_Encrypt_signature_Instance_print(instance.instance);
} 

void COCO_Framework_Witness_print(COCO_Framework_Witness &witness)
{
    Encrypt_witNess_or_Encrypt_signature_Witness_print(witness.witness); 
} 

void COCO_Framework_Proof_print(COCO_Framework_Proof &proof)
{
    Encrypt_witNess_or_Encrypt_signature_Proof_print(proof.proof);
}


void COCO_Framework_Setup(COCO_Framework_PP &pp, EC_POINT* &h){
    Encrypt_witNess_or_Encrypt_signature_Setup(pp.pp, h);
}


void COCO_Framework_Prove(COCO_Framework_PP &pp, 
                            COCO_Framework_Instance &instance, 
                            COCO_Framework_Witness &witness,
                            string &chl,
                            COCO_Framework_Proof &proof,
                            EC_POINT* &EK,
                            EC_POINT* &EK1,
                            Twisted_ElGamal_PP &pp_tt){

    vector<BIGNUM *> split_each_4bytes_m(BN_LEN/4);
    BN_vec_new(split_each_4bytes_m);
    get_32bit_4bytes_BigNumVec(split_each_4bytes_m, witness.witness.enc_witness_witness.dlog_witness[2].w, pp_tt);

    vector<BIGNUM *> each_4bytes_m_beta(BN_LEN/4);
    BN_vec_new(each_4bytes_m_beta);
    
    vector<Twisted_ElGamal_CT> each_4bytes_m_res_U_V(BN_LEN/4);
    for(auto i = 0; i < each_4bytes_m_res_U_V.size(); i++){
        Twisted_ElGamal_CT_new(each_4bytes_m_res_U_V[i]); 
    }
    BIGNUM *tmp = BN_new();
    //encrypt the first witness
    //BIGNUM *beta = BN_new(); 
    for(int i=0; i<split_each_4bytes_m.size(); i++){
        BN_random(each_4bytes_m_beta[i]);
        BN_mod(split_each_4bytes_m[i], split_each_4bytes_m[i], pp_tt.BN_MSG_SIZE, bn_ctx);
        //BN_print(split_each_4bytes_m[i], "split_each_4bytes_m");
        Twisted_ElGamal_Enc(pp_tt, EK, split_each_4bytes_m[i], each_4bytes_m_beta[i], each_4bytes_m_res_U_V[i]);     
    }

    for(int j=0; j<each_4bytes_m_beta.size(); j++){
        BN_set_word(tmp, pp_tt.MSG_LEN*(each_4bytes_m_beta.size()-j-1));
        BN_mod_exp(tmp, BN_2, tmp, order, bn_ctx);
        BN_mod_mul(tmp, each_4bytes_m_beta[j], tmp, order, bn_ctx);
        BN_mod_add(witness.witness.enc_witness_witness.dlog_witness[0].gamma, witness.witness.enc_witness_witness.dlog_witness[0].gamma, tmp, order, bn_ctx);
    }

    for(int j=0; j < split_each_4bytes_m.size(); j++){
        BN_copy(witness.witness.enc_witness_witness.range_witness[0][j].w, split_each_4bytes_m[j]);
        BN_copy(witness.witness.enc_witness_witness.range_witness[0][j].r, each_4bytes_m_beta[j]);
        EC_POINT_copy(instance.instance.enc_witness_instance.range_instance[0][j].C, each_4bytes_m_res_U_V[j].Y);
    }

    BN_copy(witness.witness.enc_witness_witness.dlog_witness[0].w, witness.witness.enc_witness_witness.dlog_witness[2].w);

    getU(instance.instance.enc_witness_instance.dlog_instance[0].U, each_4bytes_m_res_U_V, pp_tt); 

    getV(instance.instance.enc_witness_instance.dlog_instance[0].V, each_4bytes_m_res_U_V, pp_tt); 

    //encrypt the second witness
    //vector<BIGNUM *> split_each_4bytes_m1(BN_LEN/4);
    BN_vec_new(split_each_4bytes_m);
    get_32bit_4bytes_BigNumVec(split_each_4bytes_m, witness.witness.enc_witness_witness.dlog_witness[2].gamma, pp_tt);

    //vector<BIGNUM *> each_4bytes_m_beta1(BN_LEN/4);
    BN_vec_new(each_4bytes_m_beta);
    
    //vector<Twisted_ElGamal_CT> each_4bytes_m_res_U_V1(BN_LEN/4);
    for(auto i = 0; i < each_4bytes_m_res_U_V.size(); i++){
        Twisted_ElGamal_CT_new(each_4bytes_m_res_U_V[i]); 
    }

    for(int i=0; i<split_each_4bytes_m.size(); i++){
        BN_random(each_4bytes_m_beta[i]);
        BN_mod(split_each_4bytes_m[i], split_each_4bytes_m[i], pp_tt.BN_MSG_SIZE, bn_ctx);
        Twisted_ElGamal_Enc(pp_tt, EK, split_each_4bytes_m[i], each_4bytes_m_beta[i], each_4bytes_m_res_U_V[i]);     
    }

    for(int j=0; j < each_4bytes_m_beta.size(); j++){
        BN_set_word(tmp, pp_tt.MSG_LEN*(each_4bytes_m_beta.size()-j-1));
        BN_mod_exp(tmp, BN_2, tmp, order, bn_ctx);
        BN_mod_mul(tmp, each_4bytes_m_beta[j], tmp, order, bn_ctx);
        BN_mod_add(witness.witness.enc_witness_witness.dlog_witness[1].gamma, witness.witness.enc_witness_witness.dlog_witness[1].gamma, tmp, order, bn_ctx);
    }

    for(int j=0; j < split_each_4bytes_m.size(); j++){
        BN_copy(witness.witness.enc_witness_witness.range_witness[1][j].w, split_each_4bytes_m[j]);
        BN_copy(witness.witness.enc_witness_witness.range_witness[1][j].r, each_4bytes_m_beta[j]);
        EC_POINT_copy(instance.instance.enc_witness_instance.range_instance[1][j].C, each_4bytes_m_res_U_V[j].Y);
    }

    BN_copy(witness.witness.enc_witness_witness.dlog_witness[1].w, witness.witness.enc_witness_witness.dlog_witness[2].gamma);

    getU(instance.instance.enc_witness_instance.dlog_instance[1].U, each_4bytes_m_res_U_V, pp_tt); 

    getV(instance.instance.enc_witness_instance.dlog_instance[1].V, each_4bytes_m_res_U_V, pp_tt); 

    //simulation of the proof for the invalid signature.
    BIGNUM *m = BN_new();
    BN_random(m);
    EC_POINT_mul(group, instance.instance.sim_sig_instance.dlog_instance.U, NULL, generator, m, bn_ctx);

    BN_random(m);
    EC_POINT_mul(group, instance.instance.sim_sig_instance.dlog_instance.V, NULL, generator, m, bn_ctx);

    BN_random(m);
    EC_POINT_mul(group, instance.instance.sim_sig_instance.dlog_instance.B, NULL, pp_tt.g, m, bn_ctx);
    EC_POINT_mul(group, instance.instance.sim_sig_instance.dlog_instance.A, NULL, instance.instance.sim_sig_instance.dlog_instance.B, witness.witness.sim_sig_witness.dlog_witness.w, bn_ctx);

    Encrypt_witNess_or_Encrypt_signature_Prove(pp.pp, instance.instance, witness.witness, chl, proof.chl1, proof.chl0, proof.proof, EK, EK1);

    BN_vec_free(split_each_4bytes_m);
    BN_vec_free(each_4bytes_m_beta);
}

void COCO_Framework_Verify(COCO_Framework_PP &pp, 
                            COCO_Framework_Instance &instance, 
                            string &chl,  
                            COCO_Framework_Proof &proof,
                            string &res,
                            EC_POINT* &EK,
                            EC_POINT* &EK1){

    Encrypt_witNess_or_Encrypt_signature_Verify(pp.pp, instance.instance, chl, proof.chl1, proof.chl0, proof.proof, res, EK, EK1);
}

#endif
