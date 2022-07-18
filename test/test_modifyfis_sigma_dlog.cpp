#define DEBUG

#include "../depends/modified_fischlin/samplable_hard.hpp"
#include <string.h>
#include <vector> 
using namespace std;



void test_protocol()
{
    SplitLine_print('-'); 

    SAMPLABLE_HARD_PP dlog_pp;
    SAMPLABLE_HARD_PP_new(dlog_pp);
    SAMPLABLE_HARD_Setup(dlog_pp);
    SAMPLABLE_HARD_Instance dlog_instance;
    SAMPLABLE_HARD_Instance_new(dlog_instance);
    SAMPLABLE_HARD_Witness dlog_witness;
    SAMPLABLE_HARD_Witness_new(dlog_witness);
    
    
    SAMPLABLE_HARD_Proof dlog_proof;
    SAMPLABLE_HARD_Proof_new(dlog_proof);

    BIGNUM *m = BN_new(); 
    BIGNUM *m_prime = BN_new();

    /* random test */ 
    SplitLine_print('-'); 
    cout << "begin the random test >>>" << endl; 
    //BN_random(m); 
    BN_hex2bn(&dlog_witness.w, "65BB42E0");
    //Twisted_ElGamal_Dec(pp, keypair.sk, CT, m_prime); 
    //BN_print(m_prime, "m'"); 



    EC_POINT_mul(group, dlog_instance.Q, NULL, generator, dlog_witness.w, bn_ctx);

    string chl = "";
    SAMPLABLE_HARD_Commit(dlog_pp, dlog_instance, dlog_witness, chl, dlog_proof);

    SAMPLABLE_HARD_Res(dlog_pp, dlog_instance, dlog_witness, chl, dlog_proof);

    string res = "";
    SAMPLABLE_HARD_Verify(dlog_pp, dlog_instance, chl, dlog_proof, res);

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

    BN_free(m);
    BN_free(m_prime);

    SAMPLABLE_HARD_PP_free(dlog_pp);
    SAMPLABLE_HARD_Instance_free(dlog_instance);
    SAMPLABLE_HARD_Witness_free(dlog_witness);
    SAMPLABLE_HARD_Proof_free(dlog_proof);

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
