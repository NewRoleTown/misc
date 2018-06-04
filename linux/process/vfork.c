#include<stdio.h>
#include<sys/types.h>
#include<unistd.h>

int main(){
    int a = 10;
    
    if( vfork() == 0 ){
        a++;
        _exit(0);
    }else{
        printf("%d\n",a);
    }


    return 0;
}

