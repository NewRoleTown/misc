#include<iostream>
#include<assert.h>
using namespace std;


int array[128];

int a[128];

int n = 0;

//�����߿�ʼ�����һ��1���������
//+n = 1111000
//-n = 0001000
//   = 0001000
int lowbit( int n ){
    return n&(-n)
}

//��״�����±�n,k = lowbit(n),���京k���array[ n - k + 1 ]��array[ n ];
//n = 11000(24)ʱ��17��24
//10100��17��20,10110��21��22
//10010��17��18

//����ʱ���ȼ�array[idx]��Ȼ��������idx�����˼���ټ�ȥ�������������
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

//���ڵ�
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
