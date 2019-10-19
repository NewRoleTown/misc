#include<stdio.h>

void f1(unsigned long long a1){
    return;
}

void f2(unsigned long long a1,unsigned long long a2){
    return;
}

void f3(unsigned long long a1,unsigned long long a2,unsigned long long a3){
    return;
}

void f4(unsigned long long a1,unsigned long long a2,unsigned long long a3,unsigned long long a4){
    return;
}

void f5(unsigned long long a1,unsigned long long a2,unsigned long long a3,unsigned long long a4,unsigned long long a5){
    return;
}

void f6(unsigned long long a1,unsigned long long a2,unsigned long long a3,unsigned long long a4,unsigned long long a5,unsigned long long a6){
    return;
}

unsigned long long f7(unsigned long long a1,unsigned long long a2,unsigned long long a3,unsigned long long a4,unsigned long long a5,unsigned long long a6,unsigned long long a7){
    unsigned long long ret = a1 + a2 + a3 + a7;
    return ret;
}

int main(){

    f1(1);
    f2(1,2);
    f3(1,2,3);
    f4(1,2,3,4);
    f5(1,2,3,4,5);
    f6(1,2,3,4,5,6);
    f7(1,2,3,4,5,6,7);

    return 0;
}
