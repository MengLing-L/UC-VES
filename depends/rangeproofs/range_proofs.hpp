/****************************************************************************
this hpp implements NIZKPoK for discrete logarithm equality 
*****************************************************************************
* @author     This file is part of PGC, developed by Yu Chen
* @paper      https://eprint.iacr.org/2019/319
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/
#ifndef __RANGE__
#define __RANGE__

#include "../common/global.hpp"
#include "../common/hash.hpp"
#include "../common/print.hpp"
#include "../common/routines.hpp"
#include <map>
size_t VECTOR_LEN = 4;

struct Range_PP
{
    EC_POINT *g, *h; 
     // VECTOR_LEN = 4;
};

struct Range_Instance
{
    EC_POINT *C; // c = g^x h^r;
    
}; 

struct Range_Witness
{
    BIGNUM *w; 
    BIGNUM *r; // r = twisted elgamal encryption's random value beta
}; 
 
struct Range_Proof
{
    //string delta;     
    vector<EC_POINT *> c;
    //BIGNUM *chl;
    vector<BIGNUM *> z; 
    vector<BIGNUM *> t;
    BIGNUM *tau;

    vector<BIGNUM *> x;
    vector<BIGNUM *> r;
    vector<BIGNUM *> m;
    vector<BIGNUM *> s;

    BIGNUM *sigma;

};

void Range_PP_new(Range_PP &pp){
    pp.g = EC_POINT_new(group);
    pp.h = EC_POINT_new(group);
}

void Range_PP_free(Range_PP &pp)
{ 
    EC_POINT_free(pp.g); 
    EC_POINT_free(pp.h); 
}

void Range_Instance_new(Range_Instance &instance)
{
    
    instance.C = EC_POINT_new(group);
}

void Range_Instance_free(Range_Instance &instance)
{
    EC_POINT_free(instance.C);
}

void Range_Witness_new(Range_Witness &witness)
{
    witness.w = BN_new();
    witness.r = BN_new();
}

void Range_Witness_free(Range_Witness &witness)
{
    BN_free(witness.w);
    BN_free(witness.r);
}

void Range_Proof_new(Range_Proof &proof)
{
    //chl = "";
    proof.tau = BN_new();
    proof.c.resize(VECTOR_LEN); 
    proof.z.resize(VECTOR_LEN); 
    proof.t.resize(VECTOR_LEN); 
    ECP_vec_new(proof.c);
    BN_vec_new(proof.z); 
    BN_vec_new(proof.t);

    proof.x.resize(VECTOR_LEN); 
    proof.r.resize(VECTOR_LEN); 
    proof.m.resize(VECTOR_LEN); 
    proof.s.resize(VECTOR_LEN);
    BN_vec_new(proof.x);
    BN_vec_new(proof.r); 
    BN_vec_new(proof.m);
    BN_vec_new(proof.s);

    proof.sigma = BN_new();
}

void Range_Proof_free(Range_Proof &proof)
{
  
    ECP_vec_free(proof.c);
    BN_free(proof.tau);
    BN_vec_free(proof.z); 
    BN_vec_free(proof.t);
    proof.c.resize(0);

    BN_vec_free(proof.x);
    BN_vec_free(proof.r);
    BN_vec_free(proof.m);
    BN_vec_free(proof.s);
}

void Range_PP_print(Range_PP &pp)
{
    cout << "Range Proofs Public parameters >>> " << endl;
    ECP_print(pp.g, "pp.g"); 
    ECP_print(pp.h, "pp.h"); 
    cout << "VECTOR_LEN: " << VECTOR_LEN << endl;
}

void Range_Instance_print(Range_Instance &instance)
{
    cout << "Range Proofs Instance >>> " << endl;  
    ECP_print(instance.C, "instance.c"); 
    
} 

void Range_Witness_print(Range_Witness &witness)
{
    cout << "Range Proofs Witness >>> " << endl; 
    BN_print(witness.w, "w"); 
    BN_print(witness.r, "r"); 
} 

void Range_Proof_print(Range_Proof &proof)
{
    SplitLine_print('-'); 
    cout << "NIZKPoK for Range Proofs >>> " << endl; 
    //cout << "chl: " << chl << endl;
    ECP_vec_print(proof.c, "proof.c");
    BN_print(proof.tau, "proof.tau");
    BN_vec_print(proof.z, "proof.z");
    BN_vec_print(proof.t, "proof.t");
}

void Range_Proof_serialize(Range_Proof &proof, ofstream &fout)
{ 
    ECP_vec_serialize(proof.c, fout);

    BN_serialize(proof.tau,  fout);
} 

void Range_Proof_deserialize(Range_Proof &proof, ifstream &fin)
{
    
    ECP_vec_deserialize(proof.c, fin);

    BN_deserialize(proof.tau,  fin);
} 


void Range_Setup(Range_PP &pp, EC_POINT* &h){
    EC_POINT_copy(pp.g, h); 
    //EC_POINT_copy(pp.h, h);
    EC_POINT_copy(pp.h, generator);
}

void Range_Prove_Commit(Range_PP &pp, 
                            Range_Instance &instance, 
                            Range_Witness &witness, 
                            string &chl,
                            Range_Proof &proof){
    //hard code C

    const EC_POINT *vec_A[2]; 
    const BIGNUM *vec_x[2];
/*
    vec_A[0] = pp.g; 
    vec_A[1] = pp.h;
    vec_x[0] = witness.w; 
    vec_x[1] = witness.r;
    EC_POINTs_mul(group, instance.C, NULL, 2, vec_A, vec_x, bn_ctx);*/
    BIGNUM *negone = BN_new();
    BN_copy(negone, BN_1);
    BN_set_negative(negone, 1);
    BIGNUM *sum = BN_new(); 
    BIGNUM *tmp_sum = BN_new();
    BIGNUM *tmp_sum0 = BN_new();
    BIGNUM *tmp_sum1 = BN_new(); 
    BIGNUM *tmp_sum2 = BN_new();
    BIGNUM *tmp_sum3 = BN_new();
    BIGNUM *B = BN_new();
    //BIGNUM *sigma = BN_new();
    BIGNUM *FOUR = BN_new();
    BIGNUM *x_r_sum = BN_new();
    EC_POINT *Cinv = EC_POINT_new(group);
    EC_POINT *D = EC_POINT_new(group);
    EC_POINT *D_tmp = EC_POINT_new(group);
    EC_POINT *Cinvm_sum = EC_POINT_new(group);
    
    vector<EC_POINT *> d(VECTOR_LEN);
    ECP_vec_new(d);
    //vector<EC_POINT *> c(VECTOR_LEN);
    //ECP_vec_new(c);
    vector<EC_POINT *> c_minv(VECTOR_LEN);
    ECP_vec_new(c_minv);

    BN_set_word(FOUR, 4);

    //BN_set_word(B, uint64_t(pow(2, BN_LEN*8))); 
    BN_set_word(B, uint64_t(pow(2, 32))); 
    //BN_print(B, "B");
    BN_sub (proof.x[0], B, witness.w); //B-x
    //BN_print(proof.x[0], "B-x");

    BN_mul (sum, proof.x[0], witness.w, bn_ctx); //x(B-x)
    //BN_mod (sum, sum, B, bn_ctx);
    
    BN_mul (sum, sum, FOUR, bn_ctx); //4x(B-x)
    //BN_mod (sum, sum, B, bn_ctx);

    BN_add (sum, sum, BN_1);
    //BN_mod (sum, sum, B, bn_ctx);

    //BN_set_word (sum, 30);
    //BN_print(sum, "sum");
    //BN_mul (tmp_sum0, proof.x[0], proof.x[0], bn_ctx); // x_0^2


                
/*
    while(BN_cmp(proof.x[1], sum) == -1){
        BN_mul (tmp_sum1, proof.x[1], proof.x[1], bn_ctx); //x_1^2
    //  BN_mod (tmp_sum1, tmp_sum1, B, bn_ctx);
        while(BN_cmp(proof.x[2], sum) == -1){
            BN_mul (tmp_sum2, proof.x[2], proof.x[2], bn_ctx); //x_2^2
    //      BN_mod (tmp_sum2, tmp_sum2, B, bn_ctx);
            while(BN_cmp(proof.x[3], sum) == -1){
                    BN_mul (tmp_sum3, proof.x[3], proof.x[3], bn_ctx); //x_3^2
    //          BN_mod (tmp_sum3, tmp_sum3, B, bn_ctx);
                    BN_add (tmp_sum, tmp_sum1, tmp_sum2); //x_1^2 + x_2^2
                    BN_add (tmp_sum, tmp_sum, tmp_sum3); //x_3^2 + x_1^2 + x_2^2
    //          BN_mod (tmp_sum, tmp_sum, B, bn_ctx);

                    if (BN_cmp(tmp_sum, sum) == 0){
                    BN_print(proof.x[1], "proof.x[1]");
                    BN_print(proof.x[2], "proof.x[2]");
                    BN_print(proof.x[3], "proof.x[3]");
                        break;
                    }
                    BN_add (proof.x[3], proof.x[3], BN_1);
        }
                if (BN_cmp(tmp_sum, sum) == 0){
                    break;
            }
            BN_add (proof.x[2], proof.x[2], BN_1);
            BN_set_word (proof.x[3], 0);
        }
        if (BN_cmp(tmp_sum, sum) == 0){
            break;
        }
        BN_add (proof.x[1], proof.x[1], BN_1);
        BN_set_word (proof.x[2], 0);
    }*/
    string index = BN_bn2string(sum);
    index = "./3squares " + index;

    string res = exec(index.c_str());
    vector<string> elems = stringSplit(res, ' ');
    vector<unsigned long int> inter(elems.size());

    for (int i = 0; i < elems.size()-1; ++i)
    {
        inter[i] = std::stoul (elems[i], 0, 10);
        //cout << inter[i] << endl;
        BN_set_word (proof.x[i+1], inter[i]);
    }
    //BN_set_word (proof.x[1], 2504069926);
    //BN_set_word (proof.x[2], 869357514);
    //BN_set_word (proof.x[3], 3067414581);
    BN_mul (tmp_sum1, proof.x[1], proof.x[1], bn_ctx); //x_1^2
    BN_mul (tmp_sum2, proof.x[2], proof.x[2], bn_ctx); //x_2^2
    BN_mul (tmp_sum3, proof.x[3], proof.x[3], bn_ctx); //x_3^2
    BN_add (tmp_sum, tmp_sum1, tmp_sum2); //x_1^2 + x_2^2
    BN_add (tmp_sum, tmp_sum, tmp_sum3); //x_3^2 + x_1^2 + x_2^2
    //BN_print(tmp_sum, "tmp_sum");
    if (BN_cmp(tmp_sum, sum) == 0){
        #ifdef DEBUG
            BN_print(proof.x[1], "proof.x[1]");
            BN_print(proof.x[2], "proof.x[2]");
            BN_print(proof.x[3], "proof.x[3]");
        #endif
    }

    BN_copy(proof.r[0], witness.r);
    BN_set_negative(proof.r[0], 1);
    //BN_print(proof.r[0],"proof.r[0]");

    EC_POINT_copy(Cinv, instance.C);
    EC_POINT_invert(group, Cinv, bn_ctx);

    vec_A[0] = Cinv; 
    vec_A[1] = pp.g;
    vec_x[0] = BN_1; 
    vec_x[1] = B;
    EC_POINTs_mul(group, proof.c[0], NULL, 2, vec_A, vec_x, bn_ctx);// c^-1 g^B
    //ECP_print(proof.c[0], "proof.c[0]");
    
    for (int i=1; i < VECTOR_LEN; i++){
        BN_random (proof.r[i]);
        BN_mod (proof.r[i], proof.r[i], B, bn_ctx);
        vec_A[0] = pp.g; 
        vec_A[1] = pp.h;
        vec_x[0] = proof.x[i]; 
        vec_x[1] = proof.r[i];
        EC_POINTs_mul(group, proof.c[i], NULL, 2, vec_A, vec_x, bn_ctx); // g^x_i h^r_i
    }

    for (int i=0; i < VECTOR_LEN; i++){
        BN_random (proof.m[i]);
        BN_mod (proof.m[i], proof.m[i], B, bn_ctx);
        BN_random (proof.s[i]);
        BN_mod (proof.s[i], proof.s[i], B, bn_ctx);
        vec_A[0] = pp.g; 
        vec_A[1] = pp.h;
        vec_x[0] = proof.m[i]; 
        vec_x[1] = proof.s[i];
        EC_POINTs_mul(group, d[i], NULL, 2, vec_A, vec_x, bn_ctx); // g^m_i h^s_i 
    }

    BN_random (proof.sigma);
    BN_mod (proof.sigma, proof.sigma, B, bn_ctx);


    for (int i=0; i < VECTOR_LEN; i++){
        EC_POINT_mul(group, c_minv[i], NULL, proof.c[i], proof.m[i], bn_ctx);// c_i^m_i
        EC_POINT_invert(group, c_minv[i], bn_ctx);// c_i^-m_i
    }


    vec_A[0] = c_minv[1]; 
    vec_A[1] = c_minv[2];
    vec_x[0] = BN_1;
    vec_x[1] = BN_1;
    EC_POINTs_mul(group, Cinvm_sum, NULL, 2, vec_A, vec_x, bn_ctx); //c_1^-m_1 c_2^-m_2 
    //ECP_print(Cinvm_sum, "Cinvm_sum");

    vec_A[0] = Cinvm_sum; 
    vec_A[1] = c_minv[3];
    vec_x[0] = BN_1; 
    vec_x[1] = BN_1;
    EC_POINTs_mul(group, Cinvm_sum, NULL, 2, vec_A, vec_x, bn_ctx); //c_1^-m_1 c_2^-m_2 c_3^-m_3

    BN_mul (tmp_sum1, proof.m[0], FOUR, bn_ctx);//4*m_0

    vec_A[0] = pp.h; 
    vec_A[1] = instance.C;
    vec_x[0] = proof.sigma; 
    vec_x[1] = tmp_sum1;
    EC_POINTs_mul(group, D_tmp, NULL, 2, vec_A, vec_x, bn_ctx); //h^sigma c^4m_0

    vec_A[0] = D_tmp; 
    vec_A[1] = Cinvm_sum;
    vec_x[0] = BN_1; 
    vec_x[1] = BN_1;
    EC_POINTs_mul(group, D, NULL, 2, vec_A, vec_x, bn_ctx); // h^sigma c^4m_0 c_1^-m_1 c_2^-m_2 c_3^-m_3

    for (int i=0; i < VECTOR_LEN; i++){
        chl += ECP_ep2string(d[i]);
    }

    chl += ECP_ep2string(D);
    
    //Compute challenge

    //Range_Proof_print(proof);
    

    BN_free(sum); 
    BN_free(tmp_sum);
    BN_free(tmp_sum0);
    BN_free(tmp_sum1);
    BN_free(tmp_sum2);
    //BN_free(sigma); 
    BN_free(B);
    EC_POINT_free(D);
    EC_POINT_free(D_tmp);
    EC_POINT_free(Cinvm_sum);
    BN_free(FOUR);
    BN_free(x_r_sum);
    EC_POINT_free(Cinv);

    ECP_vec_free(d);
    //ECP_vec_free(c);
    ECP_vec_free(c_minv);
}

void Range_Prove_Res(Range_PP &pp, 
                            Range_Instance &instance, 
                            Range_Witness &witness,
                            string &chl, 
                            Range_Proof &proof){

    
    BIGNUM *e = BN_new();
    BIGNUM *tmp_sum = BN_new();
    BIGNUM *tmp_sum1 = BN_new();
    BIGNUM *x_r_sum = BN_new();
    BIGNUM *FOUR = BN_new();

    BN_set_word(FOUR, 4);
    
    //Compute challenge

    Hash_String_to_BN(chl, e);


    for (int i=0; i < VECTOR_LEN; i++){
        BN_mul (proof.z[i], e, proof.x[i], bn_ctx); // chl*x_i
        BN_add (proof.z[i], proof.z[i], proof.m[i]); // m_i + chl*x_i

        BN_mul (proof.t[i], e, proof.r[i], bn_ctx); // chl*r_i
        BN_add (proof.t[i], proof.t[i], proof.s[i]); // s_i + chl*r_i
    }

    BN_set_word (x_r_sum, 0);
    for (int i=1; i < VECTOR_LEN; i++){
        BN_set_word (tmp_sum1, 1);
        BN_mul (tmp_sum1, tmp_sum1, proof.x[i], bn_ctx);
        BN_mul (tmp_sum1, tmp_sum1, proof.r[i], bn_ctx); // x_ir_i

        BN_add (x_r_sum, x_r_sum, tmp_sum1);
    }

    BN_set_word (tmp_sum, 1);
    BN_mul (tmp_sum, tmp_sum, proof.x[0], bn_ctx);
    BN_mul (tmp_sum, tmp_sum, proof.r[0], bn_ctx);
    BN_mul (tmp_sum, tmp_sum, FOUR, bn_ctx);

    BN_add (proof.tau, tmp_sum, x_r_sum); // x_1r_1 + x_2r_3 + x_3r_3 + 4x_0r_0

    BN_mul (proof.tau, proof.tau, e, bn_ctx);

    BN_add (proof.tau, proof.tau, proof.sigma);

    #ifdef DEBUG
        Range_Proof_print(proof);
    #endif

    BN_free(FOUR);
    BN_free(tmp_sum);
    BN_free(tmp_sum1);
    BN_free(e);
    BN_free(x_r_sum);
}


void Range_Verify(Range_PP &pp, 
                            Range_Instance &instance, 
                            string &chl,
                            Range_Proof &proof,
                            string &res){

    const EC_POINT *vec_A[3]; 
    const BIGNUM *vec_x[3];

    vector<EC_POINT *> c_invchl(VECTOR_LEN);
    ECP_vec_new(c_invchl);
    vector<EC_POINT *> f(VECTOR_LEN);
    ECP_vec_new(f);
    EC_POINT *F = EC_POINT_new(group);
    vector<EC_POINT *> c_zinv(VECTOR_LEN);
    ECP_vec_new(c_zinv);
    EC_POINT *Cinvz_sum = EC_POINT_new(group);
    BIGNUM *FOUR_z_0 = BN_new();
    BIGNUM *FOUR = BN_new();

    BIGNUM *e = BN_new();
    
    //Compute challenge

    Hash_String_to_BN(chl, e);

    BN_set_word (FOUR, 4);



    for (int i=0; i < VECTOR_LEN; i++){
        EC_POINT_mul (group, c_invchl[i], NULL, proof.c[i], e, bn_ctx);
        EC_POINT_invert (group, c_invchl[i], bn_ctx);

        vec_A[0] = pp.g; 
        vec_A[1] = pp.h;
        vec_A[2] = c_invchl[i];
        vec_x[0] = proof.z[i]; 
        vec_x[1] = proof.t[i];
        vec_x[2] = BN_1;
        EC_POINTs_mul(group, f[i], NULL, 3, vec_A, vec_x, bn_ctx);

    }
    

    for (int i=1; i < VECTOR_LEN; i++){
        EC_POINT_mul(group, c_zinv[i], NULL, proof.c[i], proof.z[i], bn_ctx);// c_i^z_i
        EC_POINT_invert(group, c_zinv[i], bn_ctx);// c_i^-z_i
    }


    vec_A[0] = c_zinv[1]; 
    vec_A[1] = c_zinv[2];
    vec_A[2] = c_zinv[3];
    vec_x[0] = BN_1; 
    vec_x[1] = BN_1;
    vec_x[2] = BN_1;
    EC_POINTs_mul(group, Cinvz_sum, NULL, 3, vec_A, vec_x, bn_ctx); //c_1^-z_1 c_2^-z_2 c_3^-z_3

    BN_mul (FOUR_z_0, FOUR, proof.z[0], bn_ctx);

    vec_A[0] = pp.h; 
    vec_A[1] = pp.g;
    vec_A[2] = instance.C;
    vec_x[0] = proof.tau; 
    vec_x[1] = e;
    vec_x[2] = FOUR_z_0;
    EC_POINTs_mul(group, F, NULL, 3, vec_A, vec_x, bn_ctx);

    vec_A[0] = F; 
    vec_A[1] = Cinvz_sum;
    vec_x[0] = BN_1; 
    vec_x[1] = BN_1;
    EC_POINTs_mul(group, F, NULL, 2, vec_A, vec_x, bn_ctx);

    //string res = "";

    for (int i=0; i < VECTOR_LEN; i++){
        res = res + ECP_ep2string(f[i]);
    }

    res = res + ECP_ep2string(F);


    /*bool Validity = (res == chl);


    #ifdef DEBUG
    
    if (Validity) 
    { 
        cout<< "Range Proof accepts >>>" << endl; 
        cout<< "H({d_i}i=0..3, d): " << chl << endl;
        cout<< "H({f_i}i=0..3, f): " << res << endl;
    }
    else 
    {
        cout<< "Range Proof rejects >>>" << endl; 
        cout<< "H({d_i}i=0..3, d): " << res << endl;
        cout<< "H({f_i}i=0..3, f): " << chl << endl;
       
    }
    #endif*/

    ECP_vec_free (c_invchl);
    ECP_vec_free (f);
    EC_POINT_free (F);
    EC_POINT_free (Cinvz_sum);
    ECP_vec_free (c_zinv);
    BN_free (FOUR_z_0);
    BN_free (FOUR);
    BN_free (e);
    //return Validity;

}



#endif
