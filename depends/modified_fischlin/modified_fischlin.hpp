/****************************************************************************
this hpp implements NIZKPoK for discrete logarithm equality 
*****************************************************************************
* @author     This file is part of PGC, developed by Yu Chen
* @paper      https://eprint.iacr.org/2019/319
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/
#ifndef __Modified_Fischlin__
#define __Modified_Fischlin__

#include "../common/global.hpp"
#include "../common/hash.hpp"
#include "../common/print.hpp"
#include "../common/routines.hpp"
#include "../modified_fischlin/or_protocol.hpp"
using namespace std;
const size_t b=9;
const size_t t=12;  
const size_t r=10; 
const size_t S=10;

struct Modified_Fischlin_PP
{
    vector<OR_PP> pp;
};

struct Modified_Fischlin_Instance
{ 
    vector<OR_Instance> instance; 
}; 

struct Modified_Fischlin_Witness
{
    vector<OR_Witness> witness;
}; 
 
struct Modified_Fischlin_Proof
{
    vector<OR_Proof> proof;
    vector<BIGNUM *> chl1;
    vector<BIGNUM *> chl0;
    vector<BIGNUM *> chl;
    //vector<string> res;
    vector<BIGNUM *> tmp_sum;
};

void Modified_Fischlin_PP_new(Modified_Fischlin_PP &pp){
    pp.pp.resize(r);
    for (int i=0; i < r; i++){
        OR_PP_new(pp.pp[i]);
    }
}

void Modified_Fischlin_PP_free(Modified_Fischlin_PP &pp)
{ 
    for (int i=0; i < r; i++){
        OR_PP_free(pp.pp[i]);
    }
}

void Modified_Fischlin_Instance_new(Modified_Fischlin_Instance &instance)
{
    instance.instance.resize(r);
    for (int i=0; i < r; i++){
        OR_Instance_new(instance.instance[i]);
    }
}

void Modified_Fischlin_Instance_free(Modified_Fischlin_Instance &instance)
{
    for (int i=0; i < r; i++){
        OR_Instance_free(instance.instance[i]);
    }
}

void Modified_Fischlin_Witness_new(Modified_Fischlin_Witness &witness)
{
    witness.witness.resize(r);
    for (int i=0; i < r; i++){
        OR_Witness_new(witness.witness[i]);
    }
}

void Modified_Fischlin_Witness_free(Modified_Fischlin_Witness &witness)
{
    for (int i=0; i < r; i++){
        OR_Witness_free(witness.witness[i]);
    }
}

void Modified_Fischlin_Proof_new(Modified_Fischlin_Proof &proof)
{
    proof.proof.resize(r);
    proof.chl1.resize(r);
    proof.chl0.resize(r);
    proof.chl.resize(r);
    proof.tmp_sum.resize(r);
    for (int i=0; i < r; i++){
        OR_Proof_new(proof.proof[i]);
        proof.chl1[i] = BN_new();
        proof.chl0[i] = BN_new();
        proof.chl[i] = BN_new();
        proof.tmp_sum[i] = BN_new();
    }
}

void Modified_Fischlin_Proof_free(Modified_Fischlin_Proof &proof)
{
    for (int i=0; i < r; i++){
        OR_Proof_free(proof.proof[i]);
    }
}

void Modified_Fischlin_PP_print(Modified_Fischlin_PP &pp)
{
    //OR_PP_print(pp.pp);
}

void Modified_Fischlin_Instance_print(Modified_Fischlin_Instance &instance)
{
    for (int i=0; i < r; i++){
        OR_Instance_print(instance.instance[i]);
    }
} 

void Modified_Fischlin_Witness_print(Modified_Fischlin_Witness &witness)
{
    for (int i=0; i < r; i++){
        OR_Witness_print(witness.witness[i]); 
    }
} 

void Modified_Fischlin_Proof_print(Modified_Fischlin_Proof &proof)
{
    for (int i=0; i < r; i++){
        OR_Proof_print(proof.proof[i]); 
    }
}


void Modified_Fischlin_Setup(Modified_Fischlin_PP &pp, EC_POINT* &h){
    for (int i=0; i < r; i++){
        OR_Setup(pp.pp[i], h);
    }
}

void Modified_Fischlin_Prove(Modified_Fischlin_PP &pp, 
                            Modified_Fischlin_Instance &instance, 
                            Modified_Fischlin_Witness &witness,
                            //string &chl,
                            Modified_Fischlin_Proof &proof,
                            EC_POINT* &EK){
    BIGNUM *tmp_hash = BN_new();
    BIGNUM *size = BN_new();
    BN_set_word(size, uint64_t(pow(2, b)));
    BIGNUM *BN_S = BN_new();
    BN_set_word(BN_S, 1);
    /*auto start_time = chrono::steady_clock::now();
    auto end_time = chrono::steady_clock::now(); // end to count the time
    auto running_time = end_time - start_time;*/
    //OR_Commit(pp.pp[0], instance.instance[0], witness.witness[0], proof.chl1[0], proof.proof[0], EK);
    for (int i=0; i < r; i++){
        BN_random(proof.chl1[i]);
        //start_time = chrono::steady_clock::now();
        OR_Commit(pp.pp[i], instance.instance[i], witness.witness[i], proof.chl1[i], proof.proof[i], EK);
        //OR_Copy(pp.pp[i],instance.instance[i], proof.chl1[i], proof.proof[0], proof.proof[i]);
        BN_set_word(proof.chl[i], 1);
        
        do{
            BN_sub (proof.chl0[i], proof.chl1[i], proof.chl[i]);
            OR_Res(pp.pp[i], instance.instance[i], witness.witness[i], proof.proof[i], EK, proof.chl0[i]);
            Hash_BN_to_BN(proof.chl0[i], tmp_hash, size);
            BN_add(proof.chl[i], proof.chl[i], BN_1);
        }while(BN_cmp (tmp_hash, BN_S) > 0);
        //end_time = chrono::steady_clock::now(); // end to count the time
        //running_time = end_time - start_time;
        //cout << "It takes time = "
        //<< chrono::duration <double, milli> (running_time).count() << " ms" << endl;
        BN_copy(proof.tmp_sum[i],tmp_hash);
    }
    
    BN_free(BN_S);
    BN_free(tmp_hash);
    BN_free(size);
    /*thread threads[r];

    for (int i=0; i < r; i++){
        threads[i] = std::thread(multiThread, std::ref(pp), std::ref(instance), std::ref(witness), std::ref(proof), std::ref(EK), i);
        //cout << "con: " << threads[i].hardware_concurrency() << endl;
    }  
    
    for (auto &thread : threads)
        thread.join();*/
}

void Modified_Fischlin_Verify(Modified_Fischlin_PP &pp, 
                            Modified_Fischlin_Instance &instance, 
                            //string &chl,  
                            Modified_Fischlin_Proof &proof,
                            //string &res,
                            EC_POINT* &EK){

    BIGNUM *size = BN_new();
    BN_set_word(size, uint64_t(pow(2, b)));
    bool Validity = true;
    for (int i=0; i < r; i++){
        Validity =  Validity && OR_Verify(pp.pp[i], instance.instance[i], proof.chl[i], proof.chl1[i], proof.chl0[i], proof.proof[i], EK);
        //Validity = Validity && (proof.chl[i] == proof.res[i]); 
    }

    #ifdef DEBUG
        if(!Validity){
            cout << "Modified Fischlin r proofs rejects." << endl;
        } 
    #endif

    BIGNUM *tmp_hash = BN_new();
    BIGNUM *BN_S = BN_new();
    BIGNUM *tmp_sum = BN_new();
    BN_set_word(BN_S, S);
    BN_copy(BN_0, tmp_sum);
    BIGNUM *chl_bn = BN_new();
    for (int i=0; i < r; i++){
        //Hash_BN_to_BN(proof.chl0[i], tmp_hash);
        //BN_mod(tmp_hash, tmp_hash, size, bn_ctx);
        BN_add(tmp_sum, tmp_sum, proof.tmp_sum[i]);
        //BN_add(tmp_sum, tmp_sum, tmp_hash);
    }

    if(BN_cmp (tmp_sum, BN_S) <= 0 && Validity){
        cout << "Modified Fischlin proof accepts." << endl;
    }else{
        cout << "Modified Fischlin proof rejects." << endl;
        BN_print(tmp_sum, "sum");
        BN_print(BN_S, "S");
    }

    BN_free(BN_S);
    BN_free(tmp_sum);
    BN_free(tmp_hash);
    BN_free(size);

}

#endif
