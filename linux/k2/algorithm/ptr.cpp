#include<iostream>
#include<memory>
using namespace std;

void del( int *ptr ){
    cout<<"aaasasa"<<endl;
    delete[] ptr;
}


int main(){
    /*
       unique_ptr<int> p(new int(25));
       int *q = p.get();
       p.release();
       cout<<*q<<endl;
       */
    {
        unique_ptr<int[],void (*)(int *)> p(new int[10],del);
        int *q = p.get();
        *q = 1;
        cout<<p[0]<<endl;
        //p.release();
        cout<<*q<<endl;
    }

    return 0;
}
