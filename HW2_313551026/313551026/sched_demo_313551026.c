#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sched.h>
#include <sys/time.h>

pthread_barrier_t barrier; // threads share global variable

typedef struct {
    pthread_t thread_id;
    double time_wait;
    int thread_num;
    int sched_policy;
    int sched_priority;
} thread_info_t;

void *thread_func(void *arg){
    thread_info_t* tinfo_i;
    tinfo_i = (thread_info_t*)arg;
    pthread_barrier_wait(&barrier);
    int busy_time_msec = tinfo_i->time_wait * 1000;
    for (int i = 0; i < 3; i++) {
        printf("Thread %d is starting\n", tinfo_i->thread_num);
        /* Busy for <time_wait> seconds */
        struct timespec start_time, end_time;
        clock_gettime(CLOCK_THREAD_CPUTIME_ID, &start_time);
        int start_time_msec = start_time.tv_sec * 1000 + start_time.tv_nsec / 1000000;
        while(1){
            clock_gettime(CLOCK_THREAD_CPUTIME_ID, &end_time);
            int end_time_msec = end_time.tv_sec * 1000 + end_time.tv_nsec / 1000000;
            if ((end_time_msec - start_time_msec) >= busy_time_msec) {
                break;
            }
        }
        sched_yield();
    }

    pthread_exit(NULL); 
}

void parse_args(int argc, char* argv[], int* number_of_threads, double* time_, char* policy_string, char* priority_string){
    int opt;
    while((opt = getopt(argc, argv, "n:t:s:p:")) != -1){
        switch(opt){
            case 'n':
                *number_of_threads = atoi(optarg);
                break;
            case 't':
                *time_ = atof(optarg);
                break;
            case 's':
                strcpy(policy_string, optarg);
                break;
            case 'p':
                strcpy(priority_string, optarg);
                break;
            default:
                fprintf(stderr, "Usage: %s [-n number] [-t time] [-s scheduling_policies] [-p priorities]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }
}

char* parse_per_thread_info(int* i, char* str){
    char* per_thread_info = (char*)malloc(100*sizeof(char));
    int cur = 0;
    while(str[*i] != ',' && str[*i] != '\0'){
        per_thread_info[cur++] = str[*i];
        *i += 1;
    }
    per_thread_info[cur] = '\0';
    return per_thread_info;
}

void set_cpu_set(cpu_set_t* cpuset){
    CPU_ZERO(cpuset);
    CPU_SET(0, cpuset);
}

int main(int argc, char *argv[]){
    int number_of_threads;
    double time_;
    char* policy_string = (char*)malloc(1000*sizeof(char));
    char* priority_string  = (char*)malloc(1000*sizeof(char));
    parse_args(argc, argv, &number_of_threads, &time_, policy_string, priority_string);
    int index1 = 0;
    int index2 = 0;

    cpu_set_t cpuset;
    set_cpu_set(&cpuset);

    pthread_barrier_init(&barrier, NULL, number_of_threads);
    thread_info_t* tinfo;
    tinfo = (thread_info_t*)malloc(number_of_threads * sizeof(thread_info_t));
    char *policy, *priority;

    for(int i = 0; i < number_of_threads; i++){
        tinfo[i].thread_num = i;
        tinfo[i].time_wait = time_;
        policy = parse_per_thread_info(&index1, policy_string);
        priority = parse_per_thread_info(&index2, priority_string);
        index1++;
        index2++;

        if(strcmp(policy, "NORMAL") == 0){
            tinfo[i].sched_policy = SCHED_OTHER;
        }
        else if (strcmp(policy, "FIFO") == 0) {
            tinfo[i].sched_policy = SCHED_FIFO;
        }
        else{
            tinfo[i].sched_policy = SCHED_RR;
        }
        tinfo[i].sched_priority = atoi(priority) < 0 ? 0 : atoi(priority);

        pthread_attr_t t_attr;
        struct sched_param schedParam;
        pthread_attr_init(&t_attr);
        pthread_attr_setschedpolicy(&t_attr, tinfo[i].sched_policy);
        schedParam.sched_priority = tinfo[i].sched_priority;
        pthread_attr_setschedparam(&t_attr, &schedParam);
        pthread_attr_setaffinity_np(&t_attr, sizeof(cpuset), &cpuset);
        pthread_attr_setinheritsched(&t_attr, PTHREAD_EXPLICIT_SCHED);
        pthread_create(&(tinfo[i].thread_id), &t_attr, thread_func, &tinfo[i]);
        pthread_attr_destroy(&t_attr);
    }

    for(int i = 0; i < number_of_threads; i++){
        pthread_join(tinfo[i].thread_id, NULL);
    }

    pthread_barrier_destroy(&barrier);
    free(policy_string);
    free(priority_string);
    free(tinfo);
    return 0;
}
