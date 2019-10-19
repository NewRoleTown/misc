#include<stdio.h>

int main(){
    FILE *p = stdout;
    printf("%x\n",p->_flags );
setvbuf(p, (char *)NULL, _IOFBF, 0);
    printf("%x\n",p->_flags );
    //printf("%x\n",(p->_IO_file_flags & _IO_LINE_BUF) );
    fflush(p);
    //printf("%x\n",p->_flags & _IO_UNBUFFERED);
    fflush(p);

    fprintf(p,"aaa");
    while(1);
    return 0;
}
