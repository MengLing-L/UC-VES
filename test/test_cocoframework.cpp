//#define DEBUG

//#include "../depends/COCO-framework/coco-framework.hpp"
#include "../depends/COCO-framework/coco-framework_not_encrypt_random.hpp"
#include "../depends/twisted_elgamal/twisted_elgamal.hpp"
#include "../depends/signature/signature.hpp"
#include <string.h>
#include <vector> 
using namespace std;



void test_protocol()
{
    SplitLine_print('-'); 
    cout << "Initialization >>>" << endl;
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

    BIGNUM *m_prime = BN_new();
    BIGNUM *m = BN_new();

    BN_hex2bn(&m,"4b688df40bcedbe641ddb16ff0a1842d9c67ea1c3bf63f3e0471baa664531d1a");
    BIGNUM *hash=BN_new();
    BN_print(m, "m");
    Hash_BN_to_BN(m, hash);
    Signature_KeyGen(signature, signature_instance);
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
    /*
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

    EC_POINT_copy(instance.instance.enc_witness_instance.dlog_instance[2].A, signature_result.A);*/
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

    EC_POINT_copy(instance.instance.enc_witness_instance.dlog_instance[1].A, signature_result.A);

    BIGNUM *chl = BN_new();
    BN_random(chl);
    auto start_time = chrono::steady_clock::now();
    COCO_Framework_Prove(pp, instance, witness, chl, proof, pp_enc_wit_keypair.pk, keypair.pk, pp_enc_wit);
    auto end_time = chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    cout << "COCO framework proving phase takes time = "
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;

    start_time = chrono::steady_clock::now();
    bool Validity = COCO_Framework_Verify(pp, instance, chl, proof, pp_enc_wit_keypair.pk, keypair.pk);
    end_time = chrono::steady_clock::now(); // end to count the time
    running_time = end_time - start_time;
    cout << "COCO framework verifing phase takes time = "
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;

    //bool Validity = (res == chl); 

    
    if (Validity){ 
        cout<< "COCO framework proof accepts." << endl; 
        #ifdef DEBUG
        cout<< "chl: " << chl << endl;
        cout<< "H(*): " << res << endl;
        #endif
    }
    else{
        cout<< "COCO framework proof rejects." << endl; 
    }
    
    Twisted_ElGamal_PP_free(enc_pp); 
    Twisted_ElGamal_KP_free(keypair); 

    COCO_Framework_PP_free(pp);
    COCO_Framework_Instance_free(instance);
    COCO_Framework_Witness_free(witness);
    COCO_Framework_Proof_free(proof);

    BN_free(m);
    BN_free(tmp);
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
