#define DEBUG

#include "../depends/COCO-framework/encrypt_witness.hpp"
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

    Witness_Encryption_AndR_PP pp;
    NIZK_Witness_Encryption_AndR_PP_new(pp);
    NIZK_Witness_Encryption_AndR_Setup(pp, enc_pp.h, keypair.pk);
    Witness_Encryption_AndR_Instance instance;
    NIZK_Witness_Encryption_AndR_Instance_new(instance);
    Witness_Encryption_AndR_Witness witness;
    NIZK_Witness_Encryption_AndR_Witness_new(witness);
    
    
    Witness_Encryption_AndR_Proof proof;
    NIZK_Witness_Encryption_AndR_Proof_new(proof);

    BN_hex2bn(&witness.dlog_witness[0].w, "65BB42E0");
    BN_hex2bn(&witness.dlog_witness[0].gamma, "65BB42E6");
    BN_hex2bn(&witness.dlog_witness[1].w, "69BB42E0");
    BN_hex2bn(&witness.dlog_witness[1].gamma, "67BB42E0");
    BN_hex2bn(&witness.dlog_witness[2].w, "65AB42E6");
    BN_hex2bn(&witness.dlog_witness[2].gamma, "6CBB42E6");
    for (int i=0; i < 3; i++){
        BN_mod(witness.dlog_witness[i].w, witness.dlog_witness[i].w, enc_pp.BN_MSG_SIZE, bn_ctx);
        BN_print(witness.dlog_witness[i].w, "dlog_witness.w"); 
        Twisted_ElGamal_Enc(enc_pp, keypair.pk, witness.dlog_witness[i].w, witness.dlog_witness[i].gamma, CT);
        //Twisted_ElGamal_Dec(pp, keypair.sk, CT, m_prime); 
        //BN_print(m_prime, "m'"); 

        EC_POINT_copy(instance.dlog_instance[i].U, CT.Y);
        EC_POINT_copy(instance.dlog_instance[i].V, CT.X);
    }

    BIGNUM *m = BN_new(); 

    BN_random(m);
    EC_POINT_mul(group, instance.dlog_instance[2].B, NULL, enc_pp.g, m, bn_ctx);
    EC_POINT_mul(group, instance.dlog_instance[2].A, NULL, instance.dlog_instance[2].B, witness.dlog_witness[2].w, bn_ctx);


    //BN_random(witness.w);
    //BN_set_word(witness.w, 200);
    //BN_set_word(witness.r, 200);


    string chl = "";
    NIZK_Witness_Encryption_AndR_Prove_Compute_Chl(pp, instance, witness, chl, proof);

    NIZK_Witness_Encryption_AndR_Prove_Compute_Proof(pp, instance, witness, chl, proof);


    string res = "";
    NIZK_Witness_Encryption_AndR_Verify(pp, instance, witness, chl, proof, res);

    if (res == chl){
	cout << "Range proof accept." << endl;
    	cout << "chl: " << chl << endl;
    	cout << "res: " << res << endl;
    }

    Twisted_ElGamal_PP_free(enc_pp); 
    Twisted_ElGamal_KP_free(keypair); 
    Twisted_ElGamal_CT_free(CT); 

    NIZK_Witness_Encryption_AndR_PP_free(pp);
    NIZK_Witness_Encryption_AndR_Instance_free(instance);
    NIZK_Witness_Encryption_AndR_Witness_free(witness);
    NIZK_Witness_Encryption_AndR_Proof_free(proof);

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
