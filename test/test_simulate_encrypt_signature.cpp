#define DEBUG

#include "../depends/COCO-framework/simulate_encrypt_signature.hpp"
#include "../depends/twisted_elgamal/twisted_elgamal.hpp"
#include <string.h>
#include <vector> 
using namespace std;



void test_protocol()
{
    SplitLine_print('-'); 
    cout << "Initialization >>>" << endl;
    

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

    Simulation_Encrypt_Signature_PP pp;
    NIZK_Simulation_Encrypt_Signature_PP_new(pp);
    NIZK_Simulation_Encrypt_Signature_Setup(pp, enc_pp.h, keypair.pk);
    Simulation_Encrypt_Signature_Instance instance;
    NIZK_Simulation_Encrypt_Signature_Instance_new(instance);
    Simulation_Encrypt_Signature_Witness witness;
    NIZK_Simulation_Encrypt_Signature_Witness_new(witness);
    
    
    Simulation_Encrypt_Signature_Proof proof;
    NIZK_Simulation_Encrypt_Signature_Proof_new(proof);

    BN_hex2bn(&witness.dlog_witness.w, "65BB42E0");
    BN_hex2bn(&witness.dlog_witness.gamma, "65BB42E6");

    
    Twisted_ElGamal_Enc(enc_pp, keypair.pk, witness.dlog_witness.w, witness.dlog_witness.gamma, CT);
        //Twisted_ElGamal_Dec(pp, keypair.sk, CT, m_prime); 
        //BN_print(m_prime, "m'"); 

    EC_POINT_copy(instance.dlog_instance.U, CT.Y);
    EC_POINT_copy(instance.dlog_instance.V, CT.X);
    

    BIGNUM *m = BN_new(); 

    BN_random(m);
    EC_POINT_mul(group, instance.dlog_instance.B, NULL, enc_pp.g, m, bn_ctx);
    EC_POINT_mul(group, instance.dlog_instance.A, NULL, instance.dlog_instance.B, witness.dlog_witness.w, bn_ctx);


    //BN_random(witness.w);
    //BN_set_word(witness.w, 200);
    //BN_set_word(witness.r, 200);


    BN_random(m);
    string chl = BN_bn2string(m);
    NIZK_Simulation_Encrypt_Signature_Simulate_Proof(pp, instance, chl, proof);


    string res = "";
    NIZK_Simulation_Encrypt_Signature_Verify(pp, instance, witness, chl, proof, res);

    if (res == chl){
	cout << "Simulated proof accept." << endl;
    	cout << "chl: " << chl << endl;
    	cout << "res: " << res << endl;
    }

    Twisted_ElGamal_PP_free(enc_pp); 
    Twisted_ElGamal_KP_free(keypair); 
    Twisted_ElGamal_CT_free(CT); 

    NIZK_Simulation_Encrypt_Signature_PP_free(pp);
    NIZK_Simulation_Encrypt_Signature_Instance_free(instance);
    NIZK_Simulation_Encrypt_Signature_Witness_free(witness);
    NIZK_Simulation_Encrypt_Signature_Proof_free(proof);

    BN_free(m);

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
