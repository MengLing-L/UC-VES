#define DEBUG

#include "../depends/modified_fischlin/or_protocol.hpp"
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

    Twisted_ElGamal_PP enc_pp; 
    Twisted_ElGamal_PP_new(enc_pp);     
    Twisted_ElGamal_Setup(enc_pp, MSG_LEN, TUNNING, DEC_THREAD_NUM, IO_THREAD_NUM);
    Twisted_ElGamal_Initialize(enc_pp); 
    Twisted_ElGamal_KP keypair;
    Twisted_ElGamal_KP_new(keypair); 
    Twisted_ElGamal_KeyGen(enc_pp, keypair);

    OR_PP pp;
    OR_PP_new(pp);
    OR_Setup(pp, enc_pp.h);
    OR_Instance instance;
    OR_Instance_new(instance);
    OR_Witness witness;
    OR_Witness_new(witness);
    
    OR_Proof proof;
    OR_Proof_new(proof);

    BIGNUM *m_prime = BN_new();
    BIGNUM *m = BN_new();
    BIGNUM *tmp = BN_new();

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
        BN_print(split_each_4bytes_m[i], "split_each_4bytes_m");
        Twisted_ElGamal_Enc(enc_pp, keypair.pk, split_each_4bytes_m[i], each_4bytes_m_beta[i], each_4bytes_m_res_U_V[i]);     
    }

    for(int j=0; j<each_4bytes_m_beta.size(); j++){
        BN_set_word(tmp, enc_pp.MSG_LEN*(each_4bytes_m_beta.size()-j-1));
        BN_mod_exp(tmp, BN_2, tmp, order, bn_ctx);
        BN_mod_mul(tmp, each_4bytes_m_beta[j], tmp, order, bn_ctx);
        BN_mod_add(witness.original_relation_witness.dlog_witness.gamma, witness.original_relation_witness.dlog_witness.gamma, tmp, order, bn_ctx);
    }

    for(int j=0; j < split_each_4bytes_m.size(); j++){
        BN_copy(witness.original_relation_witness.range_witness[j].w, split_each_4bytes_m[j]);
        BN_copy(witness.original_relation_witness.range_witness[j].r, each_4bytes_m_beta[j]);
        EC_POINT_copy(instance.original_relation_instance.range_instance[j].C, each_4bytes_m_res_U_V[j].Y);
    }
    
    
    BN_copy(witness.original_relation_witness.dlog_witness.w, signature_result.s);

    getU(instance.original_relation_instance.dlog_instance.U, each_4bytes_m_res_U_V, enc_pp); 

    getV(instance.original_relation_instance.dlog_instance.V, each_4bytes_m_res_U_V, enc_pp); 
    
    EC_POINT_copy(instance.original_relation_instance.dlog_instance.B, signature_result.R);

    EC_POINT_copy(instance.original_relation_instance.dlog_instance.A, signature_result.A);

    
    BN_random(m);

    EC_POINT_mul(group, instance.samplable_hard_instance.Q, NULL, generator, m, bn_ctx);

    //BN_random(witness.w);
    //BN_set_word(witness.w, 200);
    //BN_set_word(witness.r, 200);

    
    string chl = "";

    string chl1 = "";
    string chl0 = "";

    OR_Prove(pp, instance, witness, chl, chl1, chl0, proof, keypair.pk);

    string res = "";
    OR_Verify(pp, instance, chl, chl1, chl0, proof, res, keypair.pk);

    bool Validity = (res == chl); 
    
    if (Validity){ 
        cout<< "DLOG Proof Accepts >>>" << endl; 
        cout<< "chl: " << chl << endl;
        cout<< "H(*): " << res << endl;
    }
    else{
        cout<< "DLOG Proof Rejects >>>" << endl; 
        cout<< "chl: " << chl << endl;
        cout<< "H(*): " << res << endl;
    }
    
    Twisted_ElGamal_PP_free(enc_pp); 
    Twisted_ElGamal_KP_free(keypair); 

    OR_PP_free(pp);
    OR_Instance_free(instance);
    OR_Witness_free(witness);
    OR_Proof_free(proof);

    BN_free(m);}

int main()
{  
    // curve id = NID_secp256k1
    global_initialize(NID_secp256k1);    
    // global_initialize(NID_secp256k1); 
    test_protocol();
    global_finalize();
    
    return 0; 
}
