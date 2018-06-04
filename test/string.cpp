#include<iostream>
#include<cstring>
using namespace std;


void calc_next( int *next,char *pattern,int pattern_len ){
    
    int begin = 1,matched = 0;

    while( begin + matched < pattern_len ){
        if( pattern[begin + matched] == pattern[matched] ){
            matched++;
            next[begin + matched - 1] = matched;
        }else{
            if( matched == 0 ){
                begin++;
            }else{
                begin += matched - next[matched - 1];
                matched = next[matched - 1];
            }
        }
    
    }
    return;
}

int match( char *pattern,char *str ){
    int str_len = strlen( str );
    int pattern_len = strlen( pattern );
    int next[32];

    calc_next( next,pattern,pattern_len );

    int begin = 0,matched = 0;
    
    while( begin + matched < str_len ){
        if( pattern[matched] == str[begin + matched] ){
            matched++;
            if( matched == pattern_len )
                return begin;
            if( !matched ){
                begin++;
            }else{
                begin += matched - next[matched - 1];
                matched = next[matched - 1];
            }
        }
    
    }

    return -1;
}


int srank[32];
int sa[32];



void swap_int( int &a,int &b ){

    if( a == b )
        return;

    a += b;
    b = a - b;
    a = a - b;
    return;
}


void print( int *arr,int n ){
    for( int i = 0; i <= n ; i++ ){
        cout<<arr[i]<<" ";
    }
    cout<<endl;
}

int rank_compare( int i,int j,int k,int n ){
    if( srank[i] != srank[j] ){
        return srank[i] - srank[j];
    }

    int ri = (i + k <= n)? srank[i + k] : -1;
    int rj = (j + k <= n)? srank[j + k] : -1;

    return ri - rj;
}

int quick_pat( int *array,int start,int end,int k,int n ){

    int i = start - 1;
    int j = start;
    for( ; j < end; j++ ){
        if( rank_compare( array[j],array[end],k,n ) < 0 ){
            //cout<<array[j]<<" -,- "<<array[end]<<endl;
            swap_int( array[++i],array[j] );
        }
    }
    swap_int( array[++i],array[end] );
    return i;
}


void quick_sort( int *array,int start,int end,int k,int n ){
    if( start >= end )
        return;

    int mid = quick_pat( array,start,end,k,n );
    quick_sort( array,start,mid - 1,k,n );
    quick_sort( array,mid + 1,end,k,n );
    return;
}

int lcp[32];

void calc_suffix( char *pattern ){

    int n = strlen( pattern );
    int tmp[32];

    //init
    for( int i = 0; i <= n; i++ ){
        sa[i] = i;
        srank[i] = (int)pattern[i];
    }
    srank[n] = -1;

    for( int k = 1; k < n; k *= 2 ){
        quick_sort( sa,0,n,k,n );
#if 1
        print( sa,n );
#endif
        tmp[ sa[0] ] = 0;
        for( int i = 1; i <= n; i++ ){
            tmp[ sa[i] ] = tmp[ sa[i - 1] ] + (rank_compare( sa[i - 1],sa[i],k,n )?1:0) ;
        }
        for( int i = 0; i <= n; i++ ){
            srank[ i ] = tmp[i];
        }
    }

    // idx          x1x2x3x4
    // idx + 1      x1x2y1y2
    //x2x3x4,x2y1y2也相邻
    //从字符串idx = 0开始计算
    //
    //当计算idx开始的字符串时，<idx 的 idx'已经计算完成，其结果h可以复用

    for( int i = 0; i <= n; i++ )
        srank[ sa[i] ] = i;

    int h = 0;
    for( int i = 0; i < n; i++ ){
        //求出排在pattern[i]开头的后缀后一个位置的后缀的其实下标
        int j = sa[ srank[i] + 1 ];

        if( h )
            h--;

        while( i + h < n && j + h < n){
            if( pattern[i + h] != pattern[j + h])
                break;
            h++;
        }
        lcp[ srank[i]  ] = h;
    }

    return;
}


int main(){
    char pattern[] = "abracadabra";
    calc_suffix( pattern );

    for( int i = 0; i < 11; i++ ){
        cout<<lcp[i]<<" ";
    }
    cout<<endl;

}
