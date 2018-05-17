#include<iostream>
#include<vector>
#include<assert.h>
using namespace std;

template<class T>
class Heap{
    public:
#define lci(i)  (i*2+1)
#define rci(i)  (i*2+2)
#define pari(i) ((i-1)/2)
//a < b     <0
//a == b    =0
//a > b     >0
typedef int (*pcompare)(T a,T b);

        Heap( pcompare f ):fp(f){}
        virtual ~Heap(){}

        void push(T var);
        T pop();

        int size(){ return vec.size(); }
        pcompare fp;

    private:
        vector<T> vec;
};

template<class T>
void Heap<T>::push( T var ){
    int heap_size = size();
    int par_idx = -1;
    int cur_idx = heap_size;

    vec.push_back(var);

    par_idx = pari(cur_idx);

    //(-1/2 == 0 )
    while( (par_idx != cur_idx) && fp(vec[par_idx],var) > 0 ){
        vec[cur_idx] = vec[par_idx];
        cur_idx = par_idx;
        par_idx = pari(par_idx);
    }

    vec[cur_idx] = var;
}

template<class T>
T Heap<T>::pop(){

    int heap_size = size();
    assert( heap_size > 0 );

    int li,ri,mi;
    int cur_idx;
    T newIn;

    T pop_item = vec[0];

    newIn = vec[--heap_size];
    vec[0] = newIn;

    vec.pop_back();

    mi = cur_idx = 0;
    li = lci(cur_idx);
    ri = rci(cur_idx);

    while( (li < heap_size) ){
        mi = cur_idx;
        
        if( fp(vec[li],newIn) < 0 )
            mi = li;

        if( (ri < heap_size) && (fp(vec[ri],vec[mi]) < 0) )
            mi = ri;

        if( mi == cur_idx )
            break;

        vec[cur_idx] = vec[mi];
        cur_idx = mi;
        li = lci(cur_idx);
        ri = rci(cur_idx);
    }
    vec[mi] = newIn;

    return pop_item;
}

/*
int fun(int a,int b){
    return a - b;
}

int main(){

    Heap<int> h(fun);

    h.push(10);
    h.push(9);
    h.push(8);
    h.push(7);
    h.push(6);
    h.push(5);
    h.push(4);


    h.pop();
    h.pop();
    h.pop();
    h.pop();
    h.pop();
    h.pop();
    h.pop();


    return 0;
}*/
