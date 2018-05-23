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

int main(){


    return 0;
}
