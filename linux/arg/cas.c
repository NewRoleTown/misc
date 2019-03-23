#include<stdio.h>
#include<pthread.h>

volatile int count = 0;

void *thread0( void *p ){
	int i = 30000000;
	while( i ){
		int tmp = count;
		int succ;
		asm volatile("cmpxchg %2,%1":"=a"(succ):"m"(count),"b"(tmp+1),"a"(tmp):);
		if( succ == tmp )
			i--;
		else
			;
	}
}

void *thread1( void *p ){
	int i = 40000000;
	while( i ){
		int tmp = count;
		int succ;
		asm volatile("cmpxchg %2,%1":"=a"(succ):"m"(count),"b"(tmp+1),"a"(tmp):);
		/*if( %1(r/m) == eax ){
			(r/m) = %2(r/m)	
		}else{
			eax = %1(r/m)
		}*/
		if( succ == tmp )
			i--;
		else
			;
	}

}

int main(){
	pthread_t tid0,tid1;
	pthread_create( &tid0,NULL,thread0,NULL );
	pthread_create( &tid1,NULL,thread1,NULL );

	pthread_join(tid0,NULL);
	pthread_join(tid1,NULL);

	printf("count = %d\n",count);
	return 0;
}
