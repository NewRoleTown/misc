#include<iostream>
#include<assert.h>
using namespace std;


int array[128];

int a[128];

int n = 0;

//求从左边开始数最后一个1所代表的数
//+n = 1111000
//-n = 0001000
//   = 0001000
int lowbit( int n ){
    return n&(-n)
}

//树状数组下标n,k = lowbit(n),则其含k项，从array[ n - k + 1 ]到array[ n ];
//n = 11000(24)时含17至24
//10100含17至20,10110含21至22
//10010含17至18

//计算时，先加array[idx]，然后分析这个idx包含了几项，再减去包含的项的数量
void calc_one( int idx ){
    int k = lowbit( n );

    a[ idx ] = array[ idx ]; 
    if( k == 1 ){
       return;
    }

    assert( k > 1 );
    int tmp_idx = idx - 1;

    while( tmp_idx > idx - k ){
        a[ idx ] += a[ tmp_idx ];
        tmp_idx -= lowbit( tmp_idx );
    }

    return;
}

//父节点
int calc_parent( int idx ){
    return idx + lowbit( idx );
}

void add( int idx,int num ){
    while( idx <= n ){
        a[ idx ] += num;
        idx = calc_parent( idx );
    }
}

int main(){

    return 0;
}
