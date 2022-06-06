#define DEBUG

#include "../depends/rangeproofs/range_proofs.hpp"
#include <string.h>
#include <vector> 
using namespace std;



void test_protocol()
{
    SplitLine_print('-'); 
    cout << "Initialization >>>" << endl;
    Range_PP pp;
    NIZK_Range_PP_new(pp);
    Range_Instance instance;
    NIZK_Range_Instance_new(instance);
    Range_Witness witness;
    NIZK_Range_Witness_new(witness);
    NIZK_Range_Setup(pp, 4);
    
    Range_Proof proof;
    NIZK_Range_Proof_new(proof,pp);


    //BN_random(witness.w);
    BN_set_word(witness.w, 200);
    BN_set_word(witness.r, 200);


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
