#include<iostream>
#include<cstring>

using namespace std;

char pat[] = "uhmhellouhmmynameislibe";

char *suffix[128];

int srank[128];

int group[128];

int lessthan( char *p1,char *p2 ){

    while( *p1 ){
        if( *p2 == 0 )
            return 0;
        if( *p1 != *p2 ){
            return (*p1 < *p2);
        }
        p1++;
        p2++;
    }
    if( *p2 == 0 )
        return 0;
    else
        return 1;
}

void pswap( char *&p1,char *&p2 ){

    char *c = p1;
    p1 = p2;
    p2 = c;

    return;
}

void init(){
    int len = strlen( pat );

    for( int i = 0; i < len; i++ ){
        suffix[i] = &pat[i];

    }

    for( int i = 0; i < len - 1; i++ ){
        for( int j = 0; j < len - i - 1; j++ ){
            if( !lessthan( suffix[j],suffix[j + 1]) ){
                pswap( suffix[j],suffix[j + 1] );
            }
        }
    }

    for( int i = 0; i < len; i++ ){
        srank[i] = (int)(suffix[i] - &pat[0]);
    }

    return;
}

int G[128][128];

int vis[128];


int main(){
    init();

    int len = strlen( pat );
    int max = 0;
    int l = 1;
    int K = 2;

    for( int i = 1; i < len; i++ ){
        int k = 0;
        for( int j = 0; j < len - srank[i - 1]; j++ ){
            int idxa = srank[ i - 1 ] ;
            int idxb = srank[ i ];
            if( pat[idxa + j] != pat[idxb + j] ){
                break;
            }
            k++;
        }
        if( k ){
            l++;
        }else{
            if( k > max )
                max = l;
            l = 1;
        }
    }

    cout<<max<<endl;

    return 0;
}

/*
*/
