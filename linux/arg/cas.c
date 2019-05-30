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



#if 0
#include<stdio.h>
#include<stdlib.h>

#define rw_write_flag	(0x100000)

struct rw_lock{
	int count;
};

void init_rw_lock( struct rw_lock *pl ){
	pl->count = rw_write_flag;
	return;
}

int read_try_lock( struct rw_lock *pl ){

	int old,new,ret;
	do{
		old = pl->count;
		new = old - 1;
		asm volatile("lock cmpxchg %2,%1":"=a"(ret):"m"(pl->count),"b"(new),"a"(old):);
	}while( old != ret );

	//fail
	if( new >= 0 )
		return 1;

	asm volatile("lock incl %0"::"m"(pl->count):);
	return 0;
}

void read_unlock( struct rw_lock *pl ){
	asm volatile("lock incl %0"::"m"(pl->count):);
	return;
}

int write_try_lock( struct rw_lock *pl ){
	int old,new,ret;
	do{
		old = pl->count;
		new = old - rw_write_flag;
		asm volatile("lock cmpxchg %2,%1":"=a"(ret):"m"(pl->count),"b"(new),"a"(old):);
	}while( old != ret );

	if( !new )
		return 1;

	asm volatile("lock addl %0,%1"::"i"(rw_write_flag),"m"(pl->count):);
	return 0;
}

int main(){
	struct rw_lock lock;
	init_rw_lock(&lock);

	int ret = read_try_lock(&lock);
	printf("%d\n",ret);
	ret = read_try_lock(&lock);
	printf("%d\n",ret);
	ret = read_try_lock(&lock);
	printf("%d\n",ret);
	ret = write_try_lock(&lock);
	printf("%d\n",ret);

}

#endif
