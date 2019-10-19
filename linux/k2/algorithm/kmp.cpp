#include<iostream>
#include<cstring>
#include<assert.h>
using namespace std;

//前缀prefix
//后缀suffix


//既是前缀又是后缀的子串的长度
int pi[128];

int self_cmp( char *p,int len,int s,int e){
    int ret;

    int slen = e - s + 1;
    ret = strncmp( p,p + len - slen,slen );
    return ret;
}

void calc( char *str ){

    int len = strlen( str );

    pi[0] = 0;
    for( int i = 1; i < len; i++ ){
        if( pi[i - 1] ){
            if( str[i] == str[pi[i - 1]]){
                pi[i] = pi[i - 1] + 1;
            }else{
#if 0
                    |------|
                    a1 a2 a3 a4 a5  a6
                             |------|
                    a4 != a6
                    //但是如果a5 == a1,a6 == a2,那么可以快速求得pi[5]
                    //此时pi[4] - 1就是a3的位置，如果pi[pi[4] - 1]不为0,
                    //那么a3和a1匹配，在匹一下a2和a6即可
                    //如此循环
#endif
                    int ink = pi[pi[i - 1] - 1];
                while( ink ){
                    if( str[ink] == str[i] ){
                        break;
                    }
                    ink = pi[pi[ink - 1] - 1];
                }
                if(str[ink] == str[i]){
                    pi[i] = ink + 1;
                }
            }
        }else{
            if( str[i] == str[0] )
                pi[i] = 1;
        }
    }

    return;
}

#define Ma(a,b) ((a)>(b)?(a):(b))

/*

*/

void ix( char *p ){

    int len = strlen(p);

    for( int i = 0; i < len; i++ ){
        if( strncmp( p,p + len - i - 1,i+1) == 0 ){
            printf("%d\n",i + 1);
        }
    }

    return;
}

//每次计算[0....begin+i]的串后缀和串前缀
void getPartialMatch( char *str ){

    int len = strlen( str );
    
    for( int begin = 1; begin < len; begin++ ){
        for( int i = 0; begin + i < len; i++ ){
            if( pat[i] != pat[begin + i])
                break;
            int tmp = i + 1;
            pi[begin + i] = max(pi[begin + i],tmp);
        }
    }

    return;
}

#if 0
          |--------|
    a1a2a3a4a5a6a7a8a9a10
          a1a2a3a4a5a6a7a8a9a10

    a4a5a6a7和a1a2a3a4匹配,matched = 4
    a8 != a5失配
    取pi[a5]，跳过中间部分


#endif

int calc2( char *pat){
    int len = strlen( pat );

    int matched = 0;
    int begin = 1;

    while( begin + matched <= len ){
        if( pat[begin + matched] == pat[matched] ){
            matched++;
            pi[begin + matched] = matched;
        }else{
            if( matched == 0 ){
                begin++;
            }else{
                begin += matched - pi[matched - 1];
                matched = pi[matched - 1];
            }
        }
    }

    return 0;
}

//最短回文串的求法
//S翻转后得S'
//找出即是S后缀又是S’前缀的最长串H,知这个H一定是回文的
//S  = H1234H
//S' =      H4321H
//叠加 = H1234H4321H

int maxOverlap( char *str_a,char *str_b ){
    int ret = -1;

    int len_a = strlen( str_a );
    int len_b = strlen( str_b );

    int begin = 0;
    int matched = 0;

    while( begin < len_a ){
        if( matched < len_b && str_a[begin + matched] == str_b[matched]){
            matched++;
            if( begin + matched == len_a )
                return matched;
        }
        
        if( matched == 0 ){
            begin++;
        }else{
            begin += matched - pi[matched - 1];
            matched = pi[matched - 1];
        }

    }

    return ret;
}

//char buff[] = "aabaabac";
char buff[] = "ababbaba";
char text[] = "if (!initial)sleeps upto a single latency don't countif (sched_feat(NEW_FAIR_SLEEPERS) && entity_is_task(se))vruntime -= sysctl_sched_latency;ensure we never gain time by being yititititiplaced backwards.vruntime = max_vruntime(se->vruntime, vruntime);";

void print_pi( int len ){
    for( int i = 0; i < len; i++ )
        printf("%d ",pi[i]);
    printf("\n");
    return;
}


int main(){
    calc( buff );

    print_pi(8);

    ix( buff );

    return 0;
}
