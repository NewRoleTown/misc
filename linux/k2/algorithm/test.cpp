#include<iostream>
#include<cstring>
#include<assert.h>
using namespace std;

//前缀prefix
//后缀suffix


//既是前缀又是后缀的子串的长度
int pi[128];


char pat[] = "ababbaba";

int self_cmp( char *p,int len,int s,int e){
    int ret;

    int slen = e - s + 1;
    ret = strncmp( p,p + len - slen,slen );
    return ret;
}

int calc2( char *pat){
    int len = strlen( pat );

    int matched = 0;
    int begin = 1;

    while( begin + matched <= len ){
        if( pat[begin + matched] == pat[matched] ){
            matched++;
            pi[begin + matched - 1] = matched;
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

void print_pi( int len ){
    for( int i = 0; i < len; i++ )
        printf("%d ",pi[i]);
    printf("\n");
    return;
}

#if 0

#endif

int opA( char *o_state,char *des_state ){
    int ret = 0;

    return ret;
}

int main(){
    calc2( pat );

    print_pi(8);

    return 0;
}


