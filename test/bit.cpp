#include<iostream>
using namespace std;


//*****100  x
//*****011  x-1
//^^^^^100  ~(x-1)

#define N 32
int Arr[N + 1];
int n;

int lowerbits( int x ){
    return (~(x - 1))&x;
}


int sum( int idx ){
    
    int sum = 0;
    while( idx ){
        sum += Arr[idx];
        idx -= lowerbits( idx );
    }
    return sum;

}

void update( int idx,int delta ){
    
    while( idx < n ){
        Arr[idx] += delta;
        idx = idx + lowerbits(idx);
    }

}

/*
int array[N];
int solve(){
    int ret = 0;

    for( int i = 0; i < n; i++ ){
        ret += i - sum(array[i]);
        update( array[i],1 );
    }

    return ret;
}*/


#if 0

[l,r)同时增加x
s(i) = 操作之前的sum(1,i)
s'(i) = 操作之后的sum(1,i)

i <= l  :   s'(i) = s(i)
i < r   :   s'(i) = s(i) + (i - l + 1) * x
i >= r  :   s'(i) = s(i) + (r - l + 1) * x

bin_idx_tree bit0,bit1


a1 + a2 + a3 + ... + ai = sum(bit1,i) * i + sum(bit0,i)

suml = [sum(bit1,i) + x] * i + sum(bit0,i) - x(l - 1)
     = sum(bit1,i) + sum(bit0,i) + x(i - l + 1)
sumr+ = sum(bit1,i) * i + sum(bit0,i) + (r - l + 1)x

#endif

int main(){


    return 0;
}
