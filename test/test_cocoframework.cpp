#define DEBUG

#include "../depends/COCO-framework/coco-framework.hpp"
#include "../depends/twisted_elgamal/twisted_elgamal.hpp"
#include "../depends/signature/signature.hpp"
#include <string.h>
#include <vector> 
using namespace std;



void test_protocol()
{
    SplitLine_print('-'); 
    cout << "Initialization >>>" << endl;
    
    Signature_PP signature;
    Signature_PP_new(signature);    
    Signature_Setup(signature);
    Signature_Instance signature_instance; 
    Signature_Instance_new(signature_instance);
    Signature_Result signature_result;
    Signature_Result_new(signature_result);

    Twisted_ElGamal_PP enc_pp; 
    Twisted_ElGamal_PP_new(enc_pp);
    size_t MSG_LEN = 32; 
    size_t TUNNING = 7; 
    size_t DEC_THREAD_NUM = 4;
    size_t IO_THREAD_NUM = 4;      
    Twisted_ElGamal_Setup(enc_pp, MSG_LEN, TUNNING, DEC_THREAD_NUM, IO_THREAD_NUM);
    Twisted_ElGamal_Initialize(enc_pp); 

    Twisted_ElGamal_KP keypair;
    Twisted_ElGamal_KP_new(keypair); 
    Twisted_ElGamal_KeyGen(enc_pp, keypair); 

    Twisted_ElGamal_CT CT; 
    Twisted_ElGamal_CT_new(CT); 

    COCO_Framework_PP pp;
    COCO_Framework_PP_new(pp);
    COCO_Framework_Setup(pp, enc_pp.h, keypair.pk);
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
    //BN_hex2bn(&hash,"4b688df40bcedbe641ddb16ff0a1842d9c67ea1c3bf63f3e0471baa664531d1a"); 
    cout << "generate hash value of private message >>>" << endl;
    BN_print(hash, "hash");

    cout << "generate the signature key pair >>>" << endl;
    Signature_KeyGen(signature, signature_instance);

    cout << "generate the signature of hash >>>" << endl;
    SplitLine_print('-');
    cout << "begin count signature generation time >>>" << endl;
    auto start_time = chrono::steady_clock::now(); // start to count the time
    Signature_Sign(signature, signature_instance, hash, signature_result);
    auto end_time = chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;
    cout << "Signature generation takes time = "
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;
    SplitLine_print('-');
    cout << "begin the twisted elgamal encryption >>>" << endl;  
    BN_print(signature_result.s, "signature_result.s"); 
    cout << "begin count encryption time >>>" << endl;
    start_time = chrono::steady_clock::now(); // start to count the time

    vector<BIGNUM *> split_each_4bytes_m(BN_LEN/4);
    BN_vec_new(split_each_4bytes_m);
    get_32bit_4bytes_BigNumVec(split_each_4bytes_m, signature_result.s, enc_pp);

    vector<BIGNUM *> each_4bytes_m_beta(BN_LEN/4);
    BN_vec_new(each_4bytes_m_beta);
    
    vector<Twisted_ElGamal_CT> each_4bytes_m_res_U_V(BN_LEN/4);
    for(auto i = 0; i < each_4bytes_m_res_U_V.size(); i++){
        Twisted_ElGamal_CT_new(each_4bytes_m_res_U_V[i]); 
    }
    
    //BIGNUM *beta = BN_new(); 
    for(int i=0; i<split_each_4bytes_m.size(); i++){
        BN_random(each_4bytes_m_beta[i]);
        BN_mod(split_each_4bytes_m[i], split_each_4bytes_m[i], enc_pp.BN_MSG_SIZE, bn_ctx);
        BN_print(split_each_4bytes_m[i], "split_each_4bytes_m");
        Twisted_ElGamal_Enc(enc_pp, keypair.pk, split_each_4bytes_m[i], each_4bytes_m_beta[i], each_4bytes_m_res_U_V[i]);     
    }

    BIGNUM *tmp = BN_new();
    for(int j=0; j<each_4bytes_m_beta.size(); j++){
        BN_set_word(tmp, enc_pp.MSG_LEN*(each_4bytes_m_beta.size()-j-1));
        BN_mod_exp(tmp, BN_2, tmp, order, bn_ctx);
        BN_mod_mul(tmp, each_4bytes_m_beta[j], tmp, order, bn_ctx);
        BN_mod_add(witness.witness.enc_witness_witness.dlog_witness[2].gamma, witness.witness.enc_witness_witness.dlog_witness[2].gamma, tmp, order, bn_ctx);
    }
    
    BN_copy(witness.witness.enc_witness_witness.dlog_witness[2].w, signature_result.s);

    getU(instance.instance.enc_witness_instance.dlog_instance[2].U, each_4bytes_m_res_U_V, enc_pp); 

    getV(instance.instance.enc_witness_instance.dlog_instance[2].V, each_4bytes_m_res_U_V, enc_pp); 
    
    EC_POINT_copy(instance.instance.enc_witness_instance.dlog_instance[2].B, signature_result.R);

    EC_POINT_copy(instance.instance.enc_witness_instance.dlog_instance[2].A, signature_result.A);

    string chl = "";


    COCO_Framework_Prove(pp, instance, witness, chl, proof);

    string res = "";
    COCO_Framework_Verify(pp, instance, chl, proof, res);

    bool Validity = (res == chl); 

    
    if (Validity){ 
        cout<< "COCO framework Proof Accepts >>>" << endl; 
        cout<< "chl: " << chl << endl;
        cout<< "H(*): " << res << endl;
    }
    else{
        cout<< "COCO framework Proof Rejects >>>" << endl; 
        cout<< "chl: " << chl << endl;
        cout<< "H(*): " << res << endl;
    }
    
    Twisted_ElGamal_PP_free(enc_pp); 
    Twisted_ElGamal_KP_free(keypair); 
    Twisted_ElGamal_CT_free(CT); 

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
