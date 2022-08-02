//#define DEBUG

#include "../depends/COCO-framework/coco-framework.hpp"
#include "../depends/modified_fischlin/modified_fischlin.hpp"
//#include "../depends/COCO-framework/coco-framework_not_encrypt_random.hpp"
#include "../depends/twisted_elgamal/twisted_elgamal.hpp"
#include "../depends/signature/signature.hpp"
#include "../depends/bulletproofs/aggregate_bulletproof.hpp"
#include "../depends/sigma/sigma_proof.hpp"
#include <string.h>
#include <vector> 
using namespace std;

void generate_random_instance_witness(Bullet_PP &pp, 
                                      Bullet_Instance &instance, 
                                      Bullet_Witness &witness,
                                      vector<BIGNUM *> &m,
                                      vector<BIGNUM *> &beta, 
                                      bool STATEMENT_FLAG)
{
    BIGNUM *exp = BN_new(); 
    BN_set_word(exp, pp.RANGE_LEN);

    BIGNUM *BN_range_size = BN_new(); 
    BN_mod_exp(BN_range_size, BN_2, exp, order, bn_ctx); 
    //cout << "range = [" << 0 << "," << BN_bn2hex(BN_range_size) <<")"<<endl; 
    for(auto i = 0; i < pp.AGG_NUM; i++)
    {
        BN_copy(witness.r[i], beta[i]);
        BN_copy(witness.v[i], m[i]);
        if (STATEMENT_FLAG == true){
            BN_mod(witness.v[i], witness.v[i], BN_range_size, bn_ctx);  
        }
        EC_POINT_mul(group, instance.C[i], witness.r[i], pp.h, witness.v[i], bn_ctx); 
    }
     
}

void generate_sigma_random_instance_witness(Twisted_ElGamal_PP &pp_tt,
                                Sigma_PP &pp, 
                                Sigma_Instance &instance, 
                                Sigma_Witness &witness, 
                                BIGNUM* &m,
                                vector<BIGNUM *> &beta,
                                vector<Twisted_ElGamal_CT> &CT,
                                EC_POINT* &pk,
                                EC_POINT* &R,
                                EC_POINT* &A,
                                bool flag)
{
    BIGNUM *tmp = BN_new();
    for(int j=0; j<beta.size(); j++){
        BN_set_word(tmp, pp_tt.MSG_LEN*(beta.size()-j-1));
        BN_mod_exp(tmp, BN_2, tmp, order, bn_ctx);
        BN_mod_mul(tmp, beta[j], tmp, order, bn_ctx);
        BN_mod_add(witness.r, witness.r, tmp, order, bn_ctx);
    }
    BN_copy(witness.v, m);

    EC_POINT_copy(instance.twisted_ek, pk);
    EC_POINT_copy(instance.R, R);
    EC_POINT_copy(instance.A, A);
    
    //ECP_print(instance.U, "instance.U");
    getU(instance.U, CT, pp_tt); 
    //ECP_print(instance.U, "instance.U");
    EC_POINT *point = EC_POINT_new(group);
    const EC_POINT *vec_A[2]; 
    const BIGNUM *vec_x[2];
    vec_A[0] = pp.g; 
    vec_A[1] = pp.h;
    vec_x[0] = m; 
    vec_x[1] = witness.r;
    EC_POINTs_mul(group, point, NULL, 2, vec_A, vec_x, bn_ctx); //g^m h^beta
    #ifdef DEBUG
    ECP_print(point, "point");
    bool val = (EC_POINT_cmp(group, point, instance.U, bn_ctx) == 0); 
    if (val) 
    { 
        cout<< "equal point and U >>>" << endl; 
    }
    else 
    {
        cout<< "unequal point and U >>>" << endl; 
    }
    #endif
    getV(instance.V, CT, pp_tt); 
}

void test_protocol()
{
    
    size_t MSG_LEN = 32; 
    size_t TUNNING = 7; 
    size_t DEC_THREAD_NUM = 4;
    size_t IO_THREAD_NUM = 4; 

    Signature_PP signature;
    Signature_PP_new(signature);    
    Signature_Setup(signature);
    Signature_Instance signature_instance; 
    Signature_Instance_new(signature_instance);
    Signature_Result signature_result;
    Signature_Result_new(signature_result);

    Twisted_ElGamal_PP pp_enc_wit; 
    Twisted_ElGamal_PP_new(pp_enc_wit);
    Twisted_ElGamal_Setup(pp_enc_wit, MSG_LEN, TUNNING, DEC_THREAD_NUM, IO_THREAD_NUM);
    Twisted_ElGamal_Initialize(pp_enc_wit); 
    Twisted_ElGamal_KP pp_enc_wit_keypair;
    Twisted_ElGamal_KP_new(pp_enc_wit_keypair); 
    Twisted_ElGamal_KeyGen(pp_enc_wit, pp_enc_wit_keypair); 

    Twisted_ElGamal_PP enc_pp; 
    Twisted_ElGamal_PP_new(enc_pp);     
    Twisted_ElGamal_Setup(enc_pp, MSG_LEN, TUNNING, DEC_THREAD_NUM, IO_THREAD_NUM);
    Twisted_ElGamal_Initialize(enc_pp); 
    Twisted_ElGamal_KP keypair;
    Twisted_ElGamal_KP_new(keypair); 
    Twisted_ElGamal_KeyGen(enc_pp, keypair); 

    COCO_Framework_PP pp;
    COCO_Framework_PP_new(pp);
    COCO_Framework_Setup(pp, enc_pp.h);
    COCO_Framework_Instance instance;
    COCO_Framework_Instance_new(instance);
    COCO_Framework_Witness witness;
    COCO_Framework_Witness_new(witness);
    COCO_Framework_Proof proof;
    COCO_Framework_Proof_new(proof);

    Modified_Fischlin_PP pp_mf;
    Modified_Fischlin_PP_new(pp_mf);
    Modified_Fischlin_Setup(pp_mf, enc_pp.h);
    Modified_Fischlin_Instance instance_mf;
    Modified_Fischlin_Instance_new(instance_mf);
    Modified_Fischlin_Witness witness_mf;
    Modified_Fischlin_Witness_new(witness_mf);
    Modified_Fischlin_Proof proof_mf;
    Modified_Fischlin_Proof_new(proof_mf);

    size_t RANGE_LEN = 32; // range size
    size_t AGG_NUM = BN_LEN/4;
    Bullet_PP pp_but; 
    Bullet_PP_new(pp_but, RANGE_LEN, AGG_NUM);  
    Bullet_Setup(pp_but, RANGE_LEN, AGG_NUM);
    Bullet_Instance instance_but; 
    Bullet_Witness witness_but; 
    Bullet_Proof proof_but; 
    Bullet_Instance_new(pp_but, instance_but); 
    Bullet_Witness_new(pp_but, witness_but); 
    Bullet_Proof_new(proof_but); 

    Sigma_PP sigma;
    Sigma_PP_new(sigma);    
    Sigma_Setup(sigma, enc_pp.h);
    Sigma_Instance sigma_instance; 
    Sigma_Instance_new(sigma_instance); 
    Sigma_Witness sigma_witness; 
    Sigma_Witness_new(sigma_witness); 
    Sigma_Proof sigma_proof; 
    Sigma_Proof_new(sigma_proof);

    BIGNUM *m_prime = BN_new();
    BIGNUM *m = BN_new();

    BN_hex2bn(&m,"4b688df40bcedbe641ddb16ff0a1842d9c67ea1c3bf63f3e0471baa664531d1a");
    
    BIGNUM *hash=BN_new();
    //BN_print(m, "m");
    Hash_BN_to_BN(m, hash);
    SplitLine_print('-');
    cout << "UC-SECURE Escrow Protocol Based on COCO Framework." << endl;
    Signature_KeyGen(signature, signature_instance);
    auto start_time = chrono::steady_clock::now();
    Signature_Sign(signature, signature_instance, hash, signature_result);
    
    vector<BIGNUM *> split_each_4bytes_m(BN_LEN/4);
    BN_vec_new(split_each_4bytes_m);
    
    vector<BIGNUM *> each_4bytes_m_beta(BN_LEN/4);
    BN_vec_new(each_4bytes_m_beta);
    
    vector<Twisted_ElGamal_CT> each_4bytes_m_res_U_V(BN_LEN/4);
    for(auto i = 0; i < each_4bytes_m_res_U_V.size(); i++){
        Twisted_ElGamal_CT_new(each_4bytes_m_res_U_V[i]); 
    }

    get_32bit_4bytes_BigNumVec(split_each_4bytes_m, signature_result.s, enc_pp);
    
    //BIGNUM *beta = BN_new(); 
    for(int i=0; i<split_each_4bytes_m.size(); i++){
        BN_random(each_4bytes_m_beta[i]);
        BN_mod(split_each_4bytes_m[i], split_each_4bytes_m[i], enc_pp.BN_MSG_SIZE, bn_ctx);
        //BN_print(split_each_4bytes_m[i], "split_each_4bytes_m");
        Twisted_ElGamal_Enc(enc_pp, keypair.pk, split_each_4bytes_m[i], each_4bytes_m_beta[i], each_4bytes_m_res_U_V[i]);     
    }

    BIGNUM *tmp = BN_new();
    
    for(int j=0; j<each_4bytes_m_beta.size(); j++){
        BN_set_word(tmp, enc_pp.MSG_LEN*(each_4bytes_m_beta.size()-j-1));
        BN_mod_exp(tmp, BN_2, tmp, order, bn_ctx);
        BN_mod_mul(tmp, each_4bytes_m_beta[j], tmp, order, bn_ctx);
        BN_mod_add(witness.witness.enc_witness_witness.dlog_witness[2].gamma, witness.witness.enc_witness_witness.dlog_witness[2].gamma, tmp, order, bn_ctx);
    }

    for(int j=0; j < split_each_4bytes_m.size(); j++){
        BN_copy(witness.witness.enc_witness_witness.range_witness[2][j].w, split_each_4bytes_m[j]);
        BN_copy(witness.witness.enc_witness_witness.range_witness[2][j].r, each_4bytes_m_beta[j]);
        EC_POINT_copy(instance.instance.enc_witness_instance.range_instance[2][j].C, each_4bytes_m_res_U_V[j].Y);
    }
    
    BN_copy(witness.witness.enc_witness_witness.dlog_witness[2].w, signature_result.s);

    getU(instance.instance.enc_witness_instance.dlog_instance[2].U, each_4bytes_m_res_U_V, enc_pp); 

    getV(instance.instance.enc_witness_instance.dlog_instance[2].V, each_4bytes_m_res_U_V, enc_pp); 
    
    EC_POINT_copy(instance.instance.enc_witness_instance.dlog_instance[2].B, signature_result.R);

    EC_POINT_copy(instance.instance.enc_witness_instance.dlog_instance[2].A, signature_result.A);/*
    for(int j=0; j<each_4bytes_m_beta.size(); j++){
        BN_set_word(tmp, enc_pp.MSG_LEN*(each_4bytes_m_beta.size()-j-1));
        BN_mod_exp(tmp, BN_2, tmp, order, bn_ctx);
        BN_mod_mul(tmp, each_4bytes_m_beta[j], tmp, order, bn_ctx);
        BN_mod_add(witness.witness.enc_witness_witness.dlog_witness[1].gamma, witness.witness.enc_witness_witness.dlog_witness[1].gamma, tmp, order, bn_ctx);
    }

    for(int j=0; j < split_each_4bytes_m.size(); j++){
        BN_copy(witness.witness.enc_witness_witness.range_witness[1][j].w, split_each_4bytes_m[j]);
        BN_copy(witness.witness.enc_witness_witness.range_witness[1][j].r, each_4bytes_m_beta[j]);
        EC_POINT_copy(instance.instance.enc_witness_instance.range_instance[1][j].C, each_4bytes_m_res_U_V[j].Y);
    }
    
    BN_copy(witness.witness.enc_witness_witness.dlog_witness[1].w, signature_result.s);

    getU(instance.instance.enc_witness_instance.dlog_instance[1].U, each_4bytes_m_res_U_V, enc_pp); 

    getV(instance.instance.enc_witness_instance.dlog_instance[1].V, each_4bytes_m_res_U_V, enc_pp); 
    
    EC_POINT_copy(instance.instance.enc_witness_instance.dlog_instance[1].B, signature_result.R);

    EC_POINT_copy(instance.instance.enc_witness_instance.dlog_instance[1].A, signature_result.A);*/
    
    BIGNUM *chl = BN_new();
    BN_random(chl);
   
    COCO_Framework_Prove(pp, instance, witness, chl, proof, pp_enc_wit_keypair.pk, keypair.pk, pp_enc_wit);
    auto end_time = chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    cout << "VESSig phase takes time = "
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;
    start_time = chrono::steady_clock::now();
    bool Validity = COCO_Framework_Verify(pp, instance, chl, proof, pp_enc_wit_keypair.pk, keypair.pk);
    end_time = chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    if (Validity){ 
        cout<< "COCO framework proof accepts." << endl; 
    }
    else{
        cout<< "COCO framework proof rejects." << endl; 
    }
    cout << "VESVer phase takes time = "
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;

    start_time = chrono::steady_clock::now();
    vector<BIGNUM *> m_recoverys(BN_LEN/4);
    BN_vec_new(m_recoverys);
    for(int i=0; i<each_4bytes_m_res_U_V.size(); i++){
        Twisted_ElGamal_Parallel_Dec(enc_pp, keypair.sk, each_4bytes_m_res_U_V[i], m_recoverys[i]);
        //BN_print(m_recoverys[i], "m'");
    }
    recovery_bignum_from_dec_nums(m_recoverys, signature_result.s, enc_pp);
    end_time = chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    cout << "Adjudication phase takes time = "
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;


    SplitLine_print('-');
    cout << "UC-SECURE Escrow Protocol Based on Modified Fischlin." << endl;
    Signature_Sign(signature, signature_instance, hash, signature_result);

    get_32bit_4bytes_BigNumVec(split_each_4bytes_m, signature_result.s, enc_pp);
    
    //BIGNUM *beta = BN_new(); 
    for(int i=0; i<split_each_4bytes_m.size(); i++){
        BN_random(each_4bytes_m_beta[i]);
        BN_mod(split_each_4bytes_m[i], split_each_4bytes_m[i], enc_pp.BN_MSG_SIZE, bn_ctx);
        //BN_print(split_each_4bytes_m[i], "split_each_4bytes_m");
        Twisted_ElGamal_Enc(enc_pp, keypair.pk, split_each_4bytes_m[i], each_4bytes_m_beta[i], each_4bytes_m_res_U_V[i]);     
    }

    for(int j=0; j<each_4bytes_m_beta.size(); j++){
        BN_set_word(tmp, enc_pp.MSG_LEN*(each_4bytes_m_beta.size()-j-1));
        BN_mod_exp(tmp, BN_2, tmp, order, bn_ctx);
        BN_mod_mul(tmp, each_4bytes_m_beta[j], tmp, order, bn_ctx); 
        BN_mod_add(witness_mf.witness[0].original_relation_witness.dlog_witness.gamma, witness_mf.witness[0].original_relation_witness.dlog_witness.gamma, tmp, order, bn_ctx); 
    }
    for (size_t k = 1; k < r; k++)
    {
        BN_copy(witness_mf.witness[k].original_relation_witness.dlog_witness.gamma, witness_mf.witness[0].original_relation_witness.dlog_witness.gamma);
    }

    for(int j=0; j < split_each_4bytes_m.size(); j++){
        for (size_t k = 0; k < r; k++)
        {
            BN_copy(witness_mf.witness[k].original_relation_witness.range_witness[j].w, split_each_4bytes_m[j]);
            BN_copy(witness_mf.witness[k].original_relation_witness.range_witness[j].r, each_4bytes_m_beta[j]);
            EC_POINT_copy(instance_mf.instance[k].original_relation_instance.range_instance[j].C, each_4bytes_m_res_U_V[j].Y);
        } 
    }
    
    for (size_t k = 0; k < r; k++){
        BN_copy(witness_mf.witness[k].original_relation_witness.dlog_witness.w, signature_result.s);
    }

    for (size_t k = 0; k < r; k++){
        getU(instance_mf.instance[k].original_relation_instance.dlog_instance.U, each_4bytes_m_res_U_V, enc_pp); 
    }

    for (size_t k = 0; k < r; k++){
        getV(instance_mf.instance[k].original_relation_instance.dlog_instance.V, each_4bytes_m_res_U_V, enc_pp); 
    }

    for (size_t k = 0; k < r; k++){
        EC_POINT_copy(instance_mf.instance[k].original_relation_instance.dlog_instance.B, signature_result.R);
    }

    for (size_t k = 0; k < r; k++){
        EC_POINT_copy(instance_mf.instance[k].original_relation_instance.dlog_instance.A, signature_result.A);
    }
    
    BN_random(m);

    for (size_t k = 0; k < r; k++){
        EC_POINT_mul(group, instance_mf.instance[k].samplable_hard_instance.Q, NULL, generator, m, bn_ctx);
    }

    //bool Validity = (res == chl); 
    start_time = chrono::steady_clock::now();
    Modified_Fischlin_Prove(pp_mf, instance_mf, witness_mf, proof_mf, keypair.pk);
    end_time = chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    cout << "VESSig phase takes time = "
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;

    start_time = chrono::steady_clock::now();
    Modified_Fischlin_Verify(pp_mf, instance_mf, proof_mf, keypair.pk);
    end_time = chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    cout << "VESVer phase takes time = "
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;

    start_time = chrono::steady_clock::now();
    for(int i=0; i<each_4bytes_m_res_U_V.size(); i++){
        Twisted_ElGamal_Parallel_Dec(enc_pp, keypair.sk, each_4bytes_m_res_U_V[i], m_recoverys[i]);
        //BN_print(m_recoverys[i], "m'");
    }
    recovery_bignum_from_dec_nums(m_recoverys, signature_result.s, enc_pp);
    end_time = chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    cout << "Adjudication phase takes time = "
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;

    SplitLine_print('-');
    cout << "NON UC-SECURE Escrow Protocol Based on [Yang 2022]." << endl;
    Signature_Sign(signature, signature_instance, hash, signature_result);
    get_32bit_4bytes_BigNumVec(split_each_4bytes_m, signature_result.s, enc_pp);

    for(int i=0; i<split_each_4bytes_m.size(); i++){
        BN_random(each_4bytes_m_beta[i]);
        BN_mod(split_each_4bytes_m[i], split_each_4bytes_m[i], enc_pp.BN_MSG_SIZE, bn_ctx);
        //BN_print(split_each_4bytes_m[i], "split_each_4bytes_m");
        Twisted_ElGamal_Enc(enc_pp, keypair.pk, split_each_4bytes_m[i], each_4bytes_m_beta[i], each_4bytes_m_res_U_V[i]);     
    }
    generate_random_instance_witness(pp_but, instance_but, witness_but, split_each_4bytes_m, each_4bytes_m_beta, true);  

    generate_sigma_random_instance_witness(enc_pp, sigma, sigma_instance, sigma_witness, signature_result.s, each_4bytes_m_beta, each_4bytes_m_res_U_V, keypair.pk, signature_result.R, signature_result.A, true); 
    
    string transcript_str; 
    string sigma_transcript_str; 

    start_time = chrono::steady_clock::now(); // start to count the time
    transcript_str = ""; 
    Bullet_Prove(pp_but, instance_but, witness_but, transcript_str, proof_but);
    sigma_transcript_str = ""; 
    Sigma_Prove(sigma, sigma_instance, sigma_witness, sigma_transcript_str, sigma_proof);
    end_time = chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    cout << "VESSig phase takes time = "
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;

    transcript_str = ""; 
    start_time = chrono::steady_clock::now();
    bool validity = true;
    validity = validity && Bullet_Verify(pp_but, instance_but, transcript_str, proof_but);
    sigma_transcript_str = ""; 
    validity = validity && Sigma_Verify(sigma, sigma_instance, sigma_transcript_str, sigma_proof);
    if (validity){
        cout << "[Yang 2022] proof accepts. " << endl;
    }
    end_time = chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    cout << "VESVer phase takes time = "
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;

    start_time = chrono::steady_clock::now();
    for(int i=0; i<each_4bytes_m_res_U_V.size(); i++){
        Twisted_ElGamal_Parallel_Dec(enc_pp, keypair.sk, each_4bytes_m_res_U_V[i], m_recoverys[i]);
        //BN_print(m_recoverys[i], "m'");
    }
    recovery_bignum_from_dec_nums(m_recoverys, signature_result.s, enc_pp);
    end_time = chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    cout << "Adjudication phase takes time = "
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;
    
    SplitLine_print('-');

    Twisted_ElGamal_PP_free(enc_pp); 
    Twisted_ElGamal_KP_free(keypair); 

    COCO_Framework_PP_free(pp);
    COCO_Framework_Instance_free(instance);
    COCO_Framework_Witness_free(witness);
    COCO_Framework_Proof_free(proof);

    Modified_Fischlin_PP_free(pp_mf);
    Modified_Fischlin_Instance_free(instance_mf);
    Modified_Fischlin_Witness_free(witness_mf);
    Modified_Fischlin_Proof_free(proof_mf);

    BN_free(m);
    BN_free(tmp);
    BN_vec_free(split_each_4bytes_m);
    BN_vec_free(each_4bytes_m_beta);
    BN_vec_free(m_recoverys);
}

int main()
{  
    // curve id = NID_secp256k1
    global_initialize(NID_secp256k1);    
    // global_initialize(NID_secp256k1); 
    test_protocol();
    global_finalize();
    
    return 0; 
}
