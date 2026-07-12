#include "stdio.h"
#include "pbc.h"
#include "gmp.h"
#include "time.h"
#include "openssl/sha.h"
#include "string.h"
#include <stdlib.h> 
#include <openssl/evp.h> 




 typedef struct {
    element_t IDi;
    element_t SP1;
    element_t SP2;
    element_t xi;
    element_t Di;
    element_t Xi;
} Vehicle;/*A Vehicle*/
 
int sha1_160bit_hash(char *hex_hash, const unsigned char *message, size_t msg_len)
{
   
    if (hex_hash == NULL) {
        return -1;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return -2;
    }

    unsigned char hash_bin[20];  //(160-bit)
    unsigned int hash_len;

    //initialize 
    if (EVP_DigestInit_ex(ctx, EVP_sha1(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return -3;
    }

    // 2. add data
    EVP_DigestUpdate(ctx, message, msg_len);

    // 3. Compute binary hash
    EVP_DigestFinal_ex(ctx, hash_bin, &hash_len);
    EVP_MD_CTX_free(ctx);

    // ==============================================
    // The hash function hex_hash
    // ==============================================
    for (int i = 0; i < 20; i++) {
        sprintf(hex_hash + i*2, "%02x", hash_bin[i]);
    }
    hex_hash[40] = '\0';  

    return 0; 
}

int hash_to_zr(element_t z, const unsigned char *data, size_t len) {
    char h[256];
    sha1_160bit_hash(h, data, len);
    element_from_bytes(z, h);
    return 0;
}/*Convert hash value h to an element z in Zr*/

int H1(element_t out, element_t IDi) {
    char buf[256];
    int pos = 0;
    pos += element_to_bytes(buf + pos, IDi);
    hash_to_zr(out, buf, pos);
}/*Hash function H1*/

int H2(element_t B, unsigned char *data){
    element_from_hash(B, data, 20);
    return 0;
}

int H3(element_t out, element_t IDi, const char *data, const char *t){
    char buf[1256];
    int pos=0;
    pos += element_to_bytes(buf + pos, IDi);
    memcpy(buf+pos, data, strlen(data));
    pos += strlen(data);
    memcpy(buf+pos, t, strlen(t));
    pos += strlen(t);
    hash_to_zr(out, buf, pos);
    return 0;
}

int H4(element_t SP, element_t ID, const char *i){
    unsigned char buf[1024];
    int pos=0;
    pos += element_to_bytes(buf+pos, ID);
    memcpy(buf+pos, i, strlen(i));
    pos += strlen(i);
    element_from_hash(SP, buf, pos);
    return 0;
}

int H5(element_t B, unsigned char *data){
    element_double(B, B);
    element_from_hash(B, data, 20);
    return 0;
}

int H6(element_t B, unsigned char *data){
    element_double(B, B);
    element_double(B, B);
    element_from_hash(B, data, 20);
    return 0;
}

int sha1_binary(const char *msg, unsigned char *hash_out) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int len;
    EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
    EVP_DigestUpdate(ctx, msg, strlen(msg));
    EVP_DigestFinal_ex(ctx, hash_out, &len);
    EVP_MD_CTX_free(ctx);
    return 0;
}
void Setup(element_t P, element_t Y, element_t y) {

   
    element_mul_zn(Y, P, y);

    //element_printf("The secret key is %B and %B\n", y, z);
    //element_printf("The public key is %B and %B\n", Y, Z);   
}

void Extraction(element_t SP1, element_t SP2, element_t IDi, element_t y, element_t P, pairing_t pairing) {
    element_t h1i;
    element_init_G1(h1i, pairing);
    H4(h1i, IDi, "1");
    //element_random(h1i);
    element_mul_zn(SP1, h1i, y);
    H4(h1i, IDi, "2");
    //element_random(h1i);
    element_mul_zn(SP2, h1i, y);
    element_clear(h1i);
    //element_printf("The secret key is %B\n", ai);
}/*Partial Private Key Extraction*/

void Keygeneration(element_t xi, element_t Di, element_t Xi,  element_t P, element_t Q){
    element_random(xi);
    element_mul_zn(Xi, P, xi);
    element_mul_zn(Di, Q, xi);
}/*the key generation algorihtm*/

void sign(element_t si,
          element_t ti,
          element_t IDi,
          element_t SP1,
          element_t SP2,
          element_t xi,
          element_t Di,
          element_t P,
          const char *mi,
          const char *t,
          pairing_t pairing)
{

    element_t h2, h3, h5,  temp_zr, temp_z2;
    element_t temp_g1, temp_g2, temp_g3, temp_g4;


    element_init_G1(h2, pairing);
    element_init_Zr(h3, pairing);
    element_init_G1(h5, pairing);
    element_init_Zr(temp_zr, pairing);
    element_init_Zr(temp_z2, pairing);
    element_init_G1(temp_g1, pairing);
    element_init_G1(temp_g2, pairing);
    element_init_G1(temp_g3, pairing);
    element_init_G1(temp_g4, pairing);

    unsigned char hash_bin[20];
    sha1_binary(t, hash_bin);
    H2(h2, hash_bin);//Pw
    H3(h3, IDi, mi, t);//ci
    H5(h5, hash_bin);//Pw
    element_random(temp_zr);  // ri
    element_mul_zn(ti, P, temp_zr);//Ti=ri*P;
    element_mul_zn(temp_g1, h2, temp_zr); // temp_gq=riPw
    element_mul_zn(temp_g3, SP2, h3);//temp_g3=ciSP2
    element_mul(temp_z2, h3, xi);
    element_mul_zn(temp_g4, h5, temp_z2);
    element_add(temp_g2, temp_g1, SP1);//temp_g1+sP1
    element_add(si, temp_g2, temp_g3);
    element_add(si, si, temp_g4);
    element_add(si, si, Di);
    
   // element_printf("The signature is %B\n", si);

    element_clear(h5);
    element_clear(h2);
    element_clear(h3);
    element_clear(temp_zr);
    element_clear(temp_z2);
    element_clear(temp_g1);
    element_clear(temp_g2);
    element_clear(temp_g3);
    element_clear(temp_g4);
}

int verify(pairing_t pairing,
           element_t s_i,
           element_t IDi,
           element_t P,
           element_t Y,
           element_t Q,
           const char *m_i,
           const char *t)
{

    element_t alpha_i, beta_i, h2t;         
    element_t left_term, right_term1, right_term2; 
    element_t pairing_left, pairing_right;    
    int result = 0;                            


    element_init_Zr(alpha_i, pairing);
    element_init_Zr(beta_i, pairing);
    element_init_G1(h2t, pairing);

    element_init_G1(left_term, pairing);
    element_init_G1(right_term1, pairing);
    element_init_G1(right_term2, pairing);

    element_init_GT(pairing_left, pairing);
    element_init_GT(pairing_right, pairing);


    H1(alpha_i, IDi);        // α_i = H1(PID_i)
    H3(beta_i, IDi, m_i, t); // β_i = H3(PID_i, m_i, t)
    unsigned char hash_bin[20];
    sha1_binary(t, hash_bin);
    H2(h2t, hash_bin);                      // H2(t)

 
    element_mul_zn(right_term1, Y, alpha_i); // α_i * Y
    element_add(right_term1, IDi, right_term1); // PID1i + α_i Y

  
    element_mul_zn(right_term2, h2t, beta_i); // β_i * Q
    element_add(right_term2, Q, right_term2); // Q + β_i H2(t)

 
    pairing_apply(pairing_left, s_i, P, pairing);       //  e(s_i, P)
    pairing_apply(pairing_right, right_term1, right_term2, pairing); //  e(...)
    
   // element_printf("The left is %B and %B\n", pairing_left, pairing_right);    
    

    
    if (element_cmp(pairing_left, pairing_right) == 0) {
        result = 1; // 
    } else {
        result = 0; // 
    }

    
    element_clear(alpha_i);
    element_clear(beta_i);
    element_clear(h2t);
    element_clear(left_term);
    element_clear(right_term1);
    element_clear(right_term2);
    element_clear(pairing_left);
    element_clear(pairing_right);

    return result;
}




int aggregate_verify(
    pairing_t pairing,
    Vehicle vehicles[20],   
    element_t S, 
    element_t T,
    const char **m,        
    const char *t,         
    element_t P,
    element_t Q,
    element_t Y,
    const int q
) {
    int result = 0;


    element_t  P_agg, H_agg, G_agg, Q_agg, temp_G1, P1[q], P2[q], P3[q], P4[q];
    element_t alpha, beta, h2t, h5t, h1i, h3i, temp_Zr;
    element_t e1, e2,e3, e4, e_left, e_right, IDi;

 

    element_init_G1(P_agg, pairing);
    element_init_G1(H_agg, pairing);
    element_init_G1(G_agg, pairing);
    element_init_G1(Q_agg, pairing);
    element_init_G1(temp_G1, pairing);
    element_init_G1(IDi, pairing);
    element_init_GT(e3, pairing);
    element_init_GT(e4, pairing);

    element_init_G1(alpha, pairing);
    element_init_Zr(beta, pairing);
    element_init_G1(h2t, pairing);
    element_init_G1(h5t, pairing);
    element_init_Zr(h1i, pairing);
    element_init_Zr(h3i, pairing);
    element_init_Zr(temp_Zr, pairing); 

    element_init_GT(e1, pairing);
    element_init_GT(e2, pairing);
    element_init_GT(e_left, pairing);
    element_init_GT(e_right, pairing);

   
    //element_set0(S);
    element_set0(P_agg);
    element_set0(H_agg);
    element_set0(G_agg);
    element_set0(Q_agg);
    element_set0(alpha);
    element_set0(beta);
    unsigned char hash_bin[20];
    sha1_binary(t, hash_bin);
    H2(h2t, hash_bin);
    H5(h5t, hash_bin);
    // ===================== =====================
    for (int i = 0; i < q; i++) {
       element_set(IDi, vehicles[i].IDi);
        //element_t si = s_arr[i];
        const char *mi = m[i]; // 
        element_init_G1(P1[i], pairing);
        H4(P1[i], IDi, "1");
        element_add(P_agg, P_agg, P1[i]);// 2. P_agg = Σ P_i1
            element_init_G1(P2[i], pairing);
      H4(P2[i], IDi, "2");//Pi2
        H3(h3i, IDi, mi, t); // 4. H3(PID_i, m[i], t)
        element_init_G1(P3[i], pairing);
        element_mul_zn(P3[i], P2[i], h3i);//H3·PID1_i
        element_init_G1(P4[i], pairing);
        element_mul_zn(P4[i], vehicles[i].Xi, h3i);
        
        element_add(H_agg, H_agg, P3[i]); // 5. H_agg = Σ H3·PID1_i
        element_add(Q_agg, Q_agg, P4[i]);
        element_add(G_agg, G_agg, vehicles[i].Xi);
    }
    
    element_add(alpha, P_agg, H_agg);//P_gg+H_gg
       
        pairing_apply(e1, T, h2t, pairing);//e(T, Pw)
       pairing_apply(e2, Y, alpha, pairing); //e(Q, P_gg+H_gg)
        pairing_apply(e3, Q_agg, h5t, pairing);
        pairing_apply(e4, G_agg, Q, pairing);
        pairing_apply(e_left, S, P, pairing);   //e(S,P)
        
      
        element_mul(e_right, e1, e2);
        element_mul(e_right, e_right, e3);
        element_mul(e_right, e_right, e4);
      //  element_add(beta, beta, temp_Zr);

    //  e1 = e(P_agg + αY, Q)
    //element_mul_zn(temp_G1, Y, alpha);
    //element_add(temp_G1, P_agg, temp_G1);
    

    // e2 = e(H_agg + βY, H2(t))
    //element_mul_zn(temp_G1, Y, beta);
    //element_add(temp_G1, H_agg, temp_G1);
    //pairing_apply(e2, temp_G1, h2t, pairing);

    // e1 * e2
    //element_mul(e_right, e1, e2);
    // e(S, P)
    //pairing_apply(e_left, S, P, pairing);

 
    result = (element_cmp(e_left, e_right) == 0) ? 1 : 0;

    for (int i = 0; i < q; i++) {
        element_clear(P1[i]);
        element_clear(P2[i]);
        element_clear(P3[i]);
        element_clear(P4[i]);
    }
    element_clear(e3);
    element_clear(e4);
    element_clear(P_agg);
    element_clear(H_agg);
    element_clear(G_agg);
    element_clear(Q_agg);
    element_clear(alpha);
    element_clear(beta);
    element_clear(h2t);
    element_clear(h5t);
    element_clear(h1i);
    element_clear(h3i);
    element_clear(temp_Zr);
    element_clear(temp_G1);
    element_clear(e1);
    element_clear(e2);
    element_clear(e_left);
    element_clear(e_right);
    element_clear(IDi);
    return result;
}



int main()
{   Vehicle V[40];
    pairing_t pairing;
     pbc_param_t param;
     struct timespec start, end, start1, end1, start2, end2, start3, end3, start4, end4, start5, end5, start6, end6, start7, end7, start8, end8, start12, end12, start_12, end_12;
     double elapsed, elapsed1, elapsed2, elapsed3, elapsed4, elapsed5, elapsed6, elapsed7, elapsed8, elapsed12, elapsed_12;
    pbc_param_init_a_gen(param, 256, 1536);
     pairing_init_pbc_param(pairing, param);
    const char *msgs[40] = {
    "model 1", "model 2", "model 3", "model 4", "model 5",
    "model 6", "model 7", "model 8", "model 9", "model 10",
    "model 11","model 12","model 13","model 14","model 15",
    "model 16","model 17","model 18","model 19","model 20",
    "model 21", "model 22", "model 23", "model 24", "model 25",
    "model 26", "model 27", "model 28", "model 29", "model 30",
    "model 31","model 32","model 33","model 34","model 35",
    "model 36","model 37","model 38","model 39","model 40"
     };
    const char *t="5th iteration";
    unsigned char hash_bin[20];
    sha1_binary(t, hash_bin);
    char hex_hash[41];  
    element_t P, Q, B, Y, Z, y, z, h1i, h2i, h3i, si[40], ti[40], left, right, S, T;
    element_init_Zr(h1i, pairing);
    element_init_G1(h2i, pairing);
    element_init_G1(S, pairing);
    element_init_G1(T, pairing);
    element_init_Zr(h3i, pairing);
    element_init_GT(left, pairing);
    element_init_GT(right, pairing);
    
     for(int i=0; i<40; i++){
         element_init_G1(V[i].IDi, pairing);
         element_init_G1(V[i].SP1, pairing); 
         element_init_G1(V[i].SP2, pairing);
         element_init_G1(si[i], pairing);
         element_init_G1(ti[i], pairing);
         element_init_Zr(V[i].xi, pairing);
         element_init_G1(V[i].Xi, pairing);
         element_init_G1(V[i].Di, pairing);
    }

    
         

    
    element_init_Zr(z, pairing);
    element_init_Zr(y, pairing);
    element_init_G1(P, pairing);
    element_init_G1(Y, pairing);
    element_init_G1(Z, pairing);
    element_init_G1(Q, pairing);
    element_random(z);
    element_random(y);
    element_random(P);
    element_random(Q);
    
    clock_gettime(CLOCK_MONOTONIC, &start);
    for(int i=0; i<40; i++){
    Setup(P, Y, y);
    }
    clock_gettime(CLOCK_MONOTONIC, &end); 
    elapsed = ((end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9)/40;   

         printf("Execution time of Setup algorithm: %f seconds\n", elapsed);  
    
    clock_gettime(CLOCK_MONOTONIC, &start1);
    for(int i=0; i<40; i++){
    Extraction(V[i].SP1, V[i].SP2, V[i].IDi, y, P, pairing); 
    }
     clock_gettime(CLOCK_MONOTONIC, &end1); 
  elapsed1 = ((end1.tv_sec - start1.tv_sec) + (end1.tv_nsec - start1.tv_nsec) / 1e9)/40;   
       printf("Execution time of an extraction algorithm from TA's side: %f seconds\n", elapsed1); 
    clock_gettime(CLOCK_MONOTONIC, &start12);
    for(int i=0; i<40; i++){
       
       H4(h2i, V[i].IDi, "1");
     
      pairing_apply(left, h2i, Y, pairing);
    
      pairing_apply(right, P, V[i].SP1, pairing);
      if (element_cmp(left, right) == 0) {
          //printf("%dth Key is generated!\n", i); 
          
          } else {
          //printf("%dth Key is not generated!\n", i); 
          }
    }
    clock_gettime(CLOCK_MONOTONIC, &end12); 
  elapsed12 = ((end12.tv_sec - start12.tv_sec) + (end12.tv_nsec - start12.tv_nsec) / 1e9)/40;  
  
       printf("Execution time of an extraction algorithm from Vehicle's side: %f seconds\n", elapsed12); 
       
       
      clock_gettime(CLOCK_MONOTONIC, &start5);
      for(int i=0; i<40; i++){
       Keygeneration(V[i].xi, V[i].Di, V[i].Xi, Q, P);
    }
     clock_gettime(CLOCK_MONOTONIC, &end5); 
    elapsed5 = ((end5.tv_sec - start5.tv_sec) + (end5.tv_nsec - start5.tv_nsec) / 1e9)/40;
    printf("Execution time of a key generation algorithm from Vehicle's side: %f seconds\n", elapsed5); 
    
    printf("execution times of 1-40 signing algorithms:\n");
      clock_gettime(CLOCK_MONOTONIC, &start2);
    for(int i=0; i<40; i++){
       sign(si[i], ti[i], V[i].IDi, V[i].SP1, V[i].SP2, V[i].xi, V[i].Di, P, msgs[i], t, pairing);
    
      
    clock_gettime(CLOCK_MONOTONIC, &end2); 
    elapsed2 = ((end2.tv_sec - start2.tv_sec) + (end2.tv_nsec - start2.tv_nsec) / 1e9);   
    printf("%f seconds\n", elapsed2);} 
    
    

   


     printf("execution times of an agg-verificaiton algorithm of 2-40 signatures:\n");
   
    clock_gettime(CLOCK_MONOTONIC, &start4);
    for(int q=2; q<=40; q++){
      element_set0(S);
      element_set0(T);
      for(int i=0; i<q; i++){
       element_add(S, S, si[i]);
       element_add(T, T, ti[i]);
      }
  
      int result=aggregate_verify(pairing, V, S, T, msgs,   t, P, Q, Y, q);
      if(result){
         //printf("The aggregate signature is valid!\n");
         }
      else{
         //printf("The aggregate signature is not valid");
         }
    
      clock_gettime(CLOCK_MONOTONIC, &end4); 
      elapsed4 = ((end4.tv_sec - start4.tv_sec) + (end4.tv_nsec - start4.tv_nsec) / 1e9)/40;  
  
          printf("%f seconds\n", elapsed4);
   }
         
          
          
     
    element_clear(h1i);
    element_clear(h2i);
    element_clear(h3i);
    element_clear(S);
    element_clear(T);
    //element_clear(B);
   

    for(int i=0; i<40; i++){
       element_clear(V[i].IDi);
       element_clear(V[i].SP1); 
       element_clear(V[i].SP2);
       element_clear(V[i].xi);
       element_clear(V[i].Xi);
       element_clear(si[i]);
       element_clear(ti[i]);
}

   
   element_clear(left);
   element_clear(right);
    element_clear(z);
    element_clear(y);
    pairing_clear(pairing);
     pbc_param_clear(param);
    return 0;
}
