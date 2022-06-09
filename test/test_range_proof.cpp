#define DEBUG

#include "../depends/rangeproofs/range_proofs.hpp"
#include "../depends/twisted_elgamal/twisted_elgamal.hpp"
#include <string.h>
#include <vector> 
using namespace std;



void test_protocol()
{
    SplitLine_print('-'); 
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
    cout << "Initialization >>>" << endl;
    Range_PP pp;
    NIZK_Range_PP_new(pp);
    Range_Instance instance;
    NIZK_Range_Instance_new(instance);
    Range_Witness witness;
    NIZK_Range_Witness_new(witness);
    NIZK_Range_Setup(pp, enc_pp.h, 4);
    
    Range_Proof proof;
    NIZK_Range_Proof_new(proof,pp);

    


    //BN_random(witness.w);

    BN_hex2bn(&witness.w, "55BB42E0");
    BN_hex2bn(&witness.r, "65BB42E6");

    Twisted_ElGamal_Enc(enc_pp, keypair.pk, witness.w, witness.r, CT);

    EC_POINT_copy(instance.C, CT.Y);

    string chl = "";
    NIZK_Range_Prove_Compute_Chl(pp, instance, witness, chl, proof);

    NIZK_Range_Prove_Compute_Proof(pp, instance, witness, chl, proof);


    string res = "";
    NIZK_Range_Verify(pp, instance, witness, chl, proof, res);

    if (res == chl){
	cout << "Range proof accept." << endl;
    	cout << "chl: " << chl << endl;
    	cout << "res: " << res << endl;
    }

    NIZK_Range_PP_free(pp);
    NIZK_Range_Instance_free(instance);
    NIZK_Range_Witness_free(witness);
    NIZK_Range_Proof_free(proof);

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
