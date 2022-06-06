#define DEBUG

#include "../depends/COCO-framework/nizk_dlog.hpp"
#include "../depends/twisted_elgamal/twisted_elgamal.hpp"
#include <string.h>
#include <vector> 
using namespace std;



void test_protocol()
{
    SplitLine_print('-'); 


    Twisted_ElGamal_PP pp; 
    Twisted_ElGamal_PP_new(pp);
    size_t MSG_LEN = 32; 
    size_t TUNNING = 7; 
    size_t DEC_THREAD_NUM = 4;
    size_t IO_THREAD_NUM = 4;      
    Twisted_ElGamal_Setup(pp, MSG_LEN, TUNNING, DEC_THREAD_NUM, IO_THREAD_NUM);
    Twisted_ElGamal_Initialize(pp); 

    Twisted_ElGamal_KP keypair;
    Twisted_ElGamal_KP_new(keypair); 
    Twisted_ElGamal_KeyGen(pp, keypair); 

    Twisted_ElGamal_CT CT; 
    Twisted_ElGamal_CT_new(CT); 

    DLOG_PP dlog_pp;
    NIZK_DLOG_PP_new(dlog_pp);
    NIZK_DLOG_Setup(dlog_pp, pp.h, keypair.pk, false);
    DLOG_Instance dlog_instance;
    NIZK_DLOG_Instance_new(dlog_instance);
    DLOG_Witness dlog_witness;
    NIZK_DLOG_Witness_new(dlog_witness);
    
    
    DLOG_Proof dlog_proof;
    NIZK_DLOG_Proof_new(dlog_proof);

    BIGNUM *m = BN_new(); 
    BIGNUM *m_prime = BN_new();

    /* random test */ 
    SplitLine_print('-'); 
    cout << "begin the random test >>>" << endl; 
    //BN_random(m); 
    BN_hex2bn(&dlog_witness.w, "65BB42E0");
    BN_hex2bn(&dlog_witness.gamma, "65BB42E6");
    BN_mod(dlog_witness.w, dlog_witness.w, pp.BN_MSG_SIZE, bn_ctx);
    BN_print(dlog_witness.w, "dlog_witness.w"); 
    Twisted_ElGamal_Enc(pp, keypair.pk, dlog_witness.w, dlog_witness.gamma, CT);
    //Twisted_ElGamal_Dec(pp, keypair.sk, CT, m_prime); 
    //BN_print(m_prime, "m'"); 


    EC_POINT_copy(dlog_instance.U, CT.Y);
    EC_POINT_copy(dlog_instance.V, CT.X);

    NIZK_DLOG_Prove(dlog_pp, dlog_instance, dlog_witness, dlog_proof);
    NIZK_DLOG_Verify(dlog_pp, dlog_instance, dlog_proof);

 
    Twisted_ElGamal_PP_free(pp); 
    Twisted_ElGamal_KP_free(keypair); 
    Twisted_ElGamal_CT_free(CT); 
    BN_free(m);
    BN_free(m_prime);

    NIZK_DLOG_PP_free(dlog_pp);
    NIZK_DLOG_Instance_free(dlog_instance);
    NIZK_DLOG_Witness_free(dlog_witness);
    NIZK_DLOG_Proof_free(dlog_proof);

}

void test_protocol2()
{
    SplitLine_print('-'); 


    Twisted_ElGamal_PP pp; 
    Twisted_ElGamal_PP_new(pp);
    size_t MSG_LEN = 32; 
    size_t TUNNING = 7; 
    size_t DEC_THREAD_NUM = 4;
    size_t IO_THREAD_NUM = 4;      
    Twisted_ElGamal_Setup(pp, MSG_LEN, TUNNING, DEC_THREAD_NUM, IO_THREAD_NUM);
    Twisted_ElGamal_Initialize(pp); 

    Twisted_ElGamal_KP keypair;
    Twisted_ElGamal_KP_new(keypair); 
    Twisted_ElGamal_KeyGen(pp, keypair); 

    Twisted_ElGamal_CT CT; 
    Twisted_ElGamal_CT_new(CT); 

    DLOG_PP dlog_pp;
    NIZK_DLOG_PP_new(dlog_pp);
    NIZK_DLOG_Setup(dlog_pp, pp.h, keypair.pk, true);
    DLOG_Instance dlog_instance;
    NIZK_DLOG_Instance_new(dlog_instance);
    DLOG_Witness dlog_witness;
    NIZK_DLOG_Witness_new(dlog_witness);
    
    
    DLOG_Proof dlog_proof;
    NIZK_DLOG_Proof_new(dlog_proof);

    BIGNUM *m = BN_new(); 
    BIGNUM *m_prime = BN_new();

    /* random test */ 
    SplitLine_print('-'); 
    cout << "begin the random test >>>" << endl; 
    //BN_random(m); 
    BN_hex2bn(&dlog_witness.w, "65BB42E0");
    BN_hex2bn(&dlog_witness.gamma, "65BB42E6");
    BN_mod(dlog_witness.w, dlog_witness.w, pp.BN_MSG_SIZE, bn_ctx);
    BN_print(dlog_witness.w, "dlog_witness.w"); 
    Twisted_ElGamal_Enc(pp, keypair.pk, dlog_witness.w, dlog_witness.gamma, CT);
    //Twisted_ElGamal_Dec(pp, keypair.sk, CT, m_prime); 
    //BN_print(m_prime, "m'"); 


    EC_POINT_copy(dlog_instance.U, CT.Y);
    EC_POINT_copy(dlog_instance.V, CT.X);

    BN_random(m);

    EC_POINT_mul(group, dlog_instance.B, NULL, pp.g, m, bn_ctx);
    EC_POINT_mul(group, dlog_instance.A, NULL, dlog_instance.B, dlog_witness.w, bn_ctx);

    NIZK_DLOG_Prove(dlog_pp, dlog_instance, dlog_witness, dlog_proof);
    NIZK_DLOG_Verify(dlog_pp, dlog_instance, dlog_proof);

 
    Twisted_ElGamal_PP_free(pp); 
    Twisted_ElGamal_KP_free(keypair); 
    Twisted_ElGamal_CT_free(CT); 
    BN_free(m);
    BN_free(m_prime);

    NIZK_DLOG_PP_free(dlog_pp);
    NIZK_DLOG_Instance_free(dlog_instance);
    NIZK_DLOG_Witness_free(dlog_witness);
    NIZK_DLOG_Proof_free(dlog_proof);

}

int main()
{  
    // curve id = NID_secp256k1
    global_initialize(NID_secp256k1);    
    // global_initialize(NID_secp256k1); 
    test_protocol2();
    global_finalize();
    
    return 0; 
}
