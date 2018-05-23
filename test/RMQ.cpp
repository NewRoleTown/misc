#include<iostream>
using namespace std;

#define N 32
#define INF 0x3f3f3f3f
#define _Min(x,y) ((x)<(y)?(x):(y))

int a[N];
int RMQ[2*N];
int n;

void init(){

    for( int i = 0; i < 2 * N ; i++ ){
        RMQ[ i ] = INF;
    }

    return;
}

void update( int k,int val ){
    
    k += n - 1;

    RMQ[k] = val;
    while( k > 0 ){
        k = (k - 1)/2;
        RMQ[k] = _Min( RMQ[2*k+1],RMQ[2*k+2] );
    }
    k = _Min( RMQ[2*k+1],RMQ[2*k+2] );

    return;
}

//[a,b)
int query( int a,int b,int k,int l,int r ){
    if( b < l || a > r )
        return INF;
    if( a <= l && b >= r )
        return RMQ[k];

    int lm = query( a,b,2 * k + 1,l,(l + r)/2);
    int rm = query( a,b,2 * k + 2,(l + r)/2,r);
    return _Min(lm,rm);
}

/*
#define _Min(a,b) (a)<(b)?(a):(b)
#define _Max(a,b) (a)>(b)?(a):(b)

//RMQ dat_a
//RMQ dat_b

void range_add( int a,int b,int x,int k,int l,int r ){

    //range包含结点区间,则全部加上x，dat_a中的加数增加x,且不下降至下一层
    if( a <= l && r <= b ){
        dat_a[k] += x;
        return;
    }

    if( b <= l || a >= r )
        return;

    //部分包含情况
    //a------b
    //   l-------------r
    dat_b[k] += (_Min(b,r) - _Max(a,l)) * x;
    range_add( a,b,x,k * 2 + 1,l,(l + r)/2 );
    range_add( a,b,x,k * 2 + 2,(l + r)/2,r );

    return;
}

int sum( int a,int b,int k,int l,int r ){
    if( b <= l || a >= r )
        return 0;

    if( a <= l && r <= b ){
        return dat_a[k] * (r - l) + dat_b[k];
    }

    int lpart = sum( a,b,2 * k + 1,l,(l + r)/2 );
    int rpart = sum( a,b,2 * k + 2,(l + r)/2,r );

    return lpart + rpart + dat_a[k] * (_Min(b,r) - _Max(a,l));
}
*/

int main(){
    
    return 0;
}
