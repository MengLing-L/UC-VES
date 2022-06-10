#define DEBUG

#include "../depends/COCO-framework/encrypt_witness_or_encrypt_signature.hpp"
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

    Encrypt_witNess_or_Encrypt_signature_PP pp;
    Encrypt_witNess_or_Encrypt_signature_PP_new(pp);
    Encrypt_witNess_or_Encrypt_signature_Setup(pp, enc_pp.h, keypair.pk);
    Encrypt_witNess_or_Encrypt_signature_Instance instance;
    Encrypt_witNess_or_Encrypt_signature_Instance_new(instance);
    Encrypt_witNess_or_Encrypt_signature_Witness witness;
    Encrypt_witNess_or_Encrypt_signature_Witness_new(witness);
    
    
    Encrypt_witNess_or_Encrypt_signature_Proof proof;
    Encrypt_witNess_or_Encrypt_signature_Proof_new(proof);

    BN_hex2bn(&witness.enc_witness_witness.dlog_witness[0].w, "65BB42E0");
    BN_hex2bn(&witness.enc_witness_witness.dlog_witness[0].gamma, "65BB42E6");
    BN_hex2bn(&witness.enc_witness_witness.dlog_witness[1].w, "69BB42E0");
    BN_hex2bn(&witness.enc_witness_witness.dlog_witness[1].gamma, "67BB42E0");
    BN_hex2bn(&witness.enc_witness_witness.dlog_witness[2].w, "65AB42E6");
    BN_hex2bn(&witness.enc_witness_witness.dlog_witness[2].gamma, "6CBB42E6");
    for (int i=0; i < 3; i++){
        BN_mod(witness.enc_witness_witness.dlog_witness[i].w, witness.enc_witness_witness.dlog_witness[i].w, enc_pp.BN_MSG_SIZE, bn_ctx);
        BN_print(witness.enc_witness_witness.dlog_witness[i].w, "dlog_witness.w"); 
        Twisted_ElGamal_Enc(enc_pp, keypair.pk, witness.enc_witness_witness.dlog_witness[i].w, witness.enc_witness_witness.dlog_witness[i].gamma, CT);
        //Twisted_ElGamal_Dec(pp, keypair.sk, CT, m_prime); 
        //BN_print(m_prime, "m'"); 

        EC_POINT_copy(instance.enc_witness_instance.dlog_instance[i].U, CT.Y);
        EC_POINT_copy(instance.enc_witness_instance.dlog_instance[i].V, CT.X);
    }

    BIGNUM *m = BN_new(); 

    BN_random(m);
    EC_POINT_mul(group, instance.enc_witness_instance.dlog_instance[2].B, NULL, enc_pp.g, m, bn_ctx);
    EC_POINT_mul(group, instance.enc_witness_instance.dlog_instance[2].A, NULL, instance.enc_witness_instance.dlog_instance[2].B, witness.enc_witness_witness.dlog_witness[2].w, bn_ctx);

    BN_hex2bn(&witness.sim_sig_witness.dlog_witness.w, "65BB42E0");
    BN_hex2bn(&witness.sim_sig_witness.dlog_witness.gamma, "65BB42E6");

    
    Twisted_ElGamal_Enc(enc_pp, keypair.pk, witness.sim_sig_witness.dlog_witness.w, witness.sim_sig_witness.dlog_witness.gamma, CT);
        //Twisted_ElGamal_Dec(pp, keypair.sk, CT, m_prime); 
        //BN_print(m_prime, "m'"); 

    EC_POINT_copy(instance.sim_sig_instance.dlog_instance.U, CT.Y);
    EC_POINT_copy(instance.sim_sig_instance.dlog_instance.V, CT.X);
    

    BN_random(m);
    EC_POINT_mul(group, instance.sim_sig_instance.dlog_instance.B, NULL, enc_pp.g, m, bn_ctx);
    EC_POINT_mul(group, instance.sim_sig_instance.dlog_instance.A, NULL, instance.sim_sig_instance.dlog_instance.B, witness.sim_sig_witness.dlog_witness.w, bn_ctx);


    //BN_random(witness.w);
    //BN_set_word(witness.w, 200);
    //BN_set_word(witness.r, 200);


    BN_random(m);
    string chl = "";

    string chl1 = "";
    string chl0 = "";

    Encrypt_witNess_or_Encrypt_signature_Prove(pp, instance, witness, chl, chl1, chl0, proof);

    string res = "";
    Encrypt_witNess_or_Encrypt_signature_Verify(pp, instance, chl, chl1, chl0, proof, res);

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
    Twisted_ElGamal_CT_free(CT); 

    Encrypt_witNess_or_Encrypt_signature_PP_free(pp);
    Encrypt_witNess_or_Encrypt_signature_Instance_free(instance);
    Encrypt_witNess_or_Encrypt_signature_Witness_free(witness);
    Encrypt_witNess_or_Encrypt_signature_Proof_free(proof);

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
