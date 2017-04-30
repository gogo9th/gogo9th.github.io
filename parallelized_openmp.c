// // Program to print all combination of size r in an array of size n
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <math.h>
#include <omp.h>
#include <time.h>
#include <sys/time.h> // for clock_gettime()

#define LINE_MEMORY 1000
#define MALWARE_LEN 100
#define NORMAL_LEN  5000

/* timing function */
double get_seconds_frac(struct timeval start_timeval, struct timeval end_timeval){
    long secs_used, micros_used;
    secs_used= end_timeval.tv_sec - start_timeval.tv_sec;
    micros_used= end_timeval.tv_usec - start_timeval.tv_usec;
    
    return (double)(secs_used + micros_used/1000000.0); 
}

void produce_signature(FILE* f_write, char* normal_list[], char* chosen_malware[], int combination[], int n_pos){

    SHA_CTX ctx;
    SHA1_Init(&ctx);

    int line_index = 0;
    int c_index    = 0; //pointer to the combination of malware's position
    
    while (line_index <= n_pos) {
    
        if(c_index < 3 && line_index == combination[c_index]){   //insert malware here
            SHA1_Update(&ctx, chosen_malware[c_index], strlen(chosen_malware[c_index])-1);
            c_index  ++;                      
        }
        // line_head points to the beginning of application "measurement"
        
        // Hash each piece of data as it comes in:
        // fprintf(f_write, "%s", line_head);
        SHA1_Update(&ctx, normal_list[line_index], strlen(normal_list[line_index])-1 );

        line_index++;
    }

    ////test print/////
    //fprintf(f_write, "%s \n %s \n %s \n",chosen_malware[0], chosen_malware[1], chosen_malware[2]);
    //fprintf(f_write, "%d %d %d \n", combination[0], combination[1], combination[2]);
    /////////


    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1_Final(hash, &ctx);

    int i;
    // for (i = 0; i < SHA_DIGEST_LENGTH; i++){

    //     fprintf(f_write, "%d ", hash[i]);
    // }

    //fprintf(f_write, "\n");

    
    return;
}


int main()
{  
    int n_pos;

    for(n_pos = 6; n_pos <= 40; n_pos += 2) {

        fprintf(stdout, "n_pos = %d\n", n_pos);

        ////readin malware names and store in malware_list
        char* malware_list[MALWARE_LEN];
        char* normal_list[NORMAL_LEN];
        int i = 0;
        size_t len = 0;
        char*  line_head;
        ssize_t read;

        double time1, time2;
        struct timeval start_time1, end_time1, start_time2, end_time2;

        char * line = (char*)malloc(LINE_MEMORY);
        
        FILE *f_mal = fopen("mal.txt", "r");
        int total_malware = 0;
        int total_normal = 0;

        gettimeofday(&start_time2,NULL);
        
        while(  (read = getline(&line, &len, f_mal)) != -1 ) {
            // line_head points to the beginning of application "measurement"
            line_head = strchr(line, '/');
            // num_chars = strlen(line_head) - 1;

            malware_list[total_malware] = malloc(strlen(line_head) + 1);
            strcpy(malware_list[total_malware], line_head);
            total_malware++;

        }

        fclose(f_mal);


        ////readin normal file names and store in normal_list
        
        // reading file
        FILE *f_app = fopen("out1.txt", "r");
        
        while(  (read = getline(&line, &len, f_app)) != -1 ) {
            // line_head points to the beginning of application "measurement"
            line_head = strchr(line, '/');
            // num_chars = strlen(line_head) - 1;

            normal_list[i] = malloc(strlen(line_head) + 1);
            strcpy(normal_list[i], line_head);
            total_normal++;
            i++;
        }
        fclose(f_app);

        gettimeofday(&end_time2,NULL);

        time2 = get_seconds_frac(start_time2,end_time2);

        printf("reading time for in sec: %4.2f\n", time2);

        FILE *f_write = fopen("signatures.txt", "w");

        gettimeofday(&start_time1,NULL);


        omp_set_num_threads(12);
        

        // here, we select (three) malware to be inserted into the sequence. 
        // Since we insert 3 malware, the number of recursions is 3.
        

        #pragma omp parallel for private(i) shared(n_pos, total_malware, malware_list, normal_list,f_write)
        for (i = 0; i < total_malware; i++){
            int j, k;
            for (j = 0; j < total_malware; j++){
                for(k = 0; k < total_malware; k++){

                    //n_pos represent the number of possible insertion positions, which is equal to the number of benign files
                    ///////////////
                    int malware1_index, malware2_index, malware3_index;
                    for (malware1_index = 0 ; malware1_index < n_pos; malware1_index++){
                        for (malware2_index = 0 ; malware2_index < n_pos; malware2_index++){
                            for (malware3_index = 0 ; malware3_index < n_pos; malware3_index++){
                                if (malware1_index == malware2_index  // skip the cases where malware positions overlap
                                    || malware2_index == malware3_index 
                                    || malware1_index == malware3_index)
                                    continue;


                                //chosen_malware represents three malware chosen from all types of malwares in malware_list
                                //chosen_malware could be duplicate 
                                char* chosen_malware[3] = {malware_list[i], malware_list[j], malware_list[k]};
                                
                                //combination represents the positions to insert malwares
                                //combination of three positions cannot overlap
                                int combination[3] = {malware1_index, malware2_index, malware3_index};
                                produce_signature(f_write, normal_list, chosen_malware, combination, n_pos);

                            } 
                        }
                            
                    }
                              
                    
                }
            }
        }

       

        gettimeofday(&end_time1,NULL);

        time1 = get_seconds_frac(start_time1,end_time1);

            
        printf("processing time for in sec: %4.2f\n", time1);


        fclose(f_write);
        free(line);
        for(i = 0; i < total_malware; i++) {
            free(malware_list[i]);
        }
        for(i = 0; i < total_normal; i++) {
            free(normal_list[i]);
        }

    }
}
