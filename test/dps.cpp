#include<stdio.h>
#include<stdlib.h>
#include<string.h>

int G[100];

int dp[100][1 << 10][1 << 10];

int start[1 << 10];

int n,m;
int maxstate;

#define Ma(x,y) ((x)>(y)?(x):(y))

int calc_bits( int n ){
    int ret = 0;
    while( n ){
        if( n & 0x1 )
            ret++;
        n = n >> 1;
    }
    return ret;
}

int judge( int state,int prev){
    if( state & prev )
        return 0;
    return 1;
}

void first_line(){
    for( int i = 0; i < maxstate; i++ ){
        if( ((i >> 2) & i) || i & G[0] )
            continue;
        //start[ sc++ ] = i;
        dp[0][i][0] = calc_bits(n);
    }
    return;
}

void second_line(){

    int t;
    for( int i = 0; i < maxstate; i++ ){
        if( (i >> 2) & i || (i & G[1]) )
            continue;

        t = calc_bits( i );
        for( int j = 0; j < maxstate; j++ ){
            if( judge( i,j) ){
                dp[1][i][j] = dp[0][j][0] + t;
            }
        }
    }
    return;
}



int solve(){

    int t;
    for( int i = 2; i < n; i++ ){
        for( int j = 0; j < maxstate; j++ ){
            if( (i >> 2) & i || (i & G[1]) )
                continue;

            t = calc_bits(j);
            for( int k = 0; k < maxstate; k++ ){
                if( !judge(i,j) )
                    continue;
                for( int l = 0; l < maxstate; l++ ){
                    if( !judge(i,l) )
                        continue;
                    dp[i][j][k] = Ma(dp[i][j][k],dp[i-1][k][l]);
                }
                dp[i][j][k] += t;
            }


        }
    }
}

int main(){
    scanf("%d%d",&n,&m);

    getchar();

    char buf[16];

    for( int i = 0; i < n; i++ ){
        scanf("%s",buf);
        for( int j = 0; j < m; j++ ){
            if( buf[j] == 'H' ){
                G[i] |= ( 1 << j );
            }
        }
        printf("%d\n",G[i]);
    }

    maxstate = 1 << m;
    first_line();
    second_line();
    solve();


    return 0;
}
