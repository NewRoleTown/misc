#define _GNU_SOURCE
#include<sys/types.h>
#include<sys/socket.h>
#include<sys/epoll.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<assert.h>
#include<string.h>
#include<errno.h>
#include<netdb.h>
#include<assert.h>
#include<sys/types.h>
#include<fcntl.h>
#include<unistd.h>
#include<stdlib.h>
#include<sched.h>
#include<pthread.h>
#include<sys/mman.h>
#include<sys/ipc.h>
#include<sys/shm.h>

#include<stdio.h>

#define MAX_CONNECTION_NUM	4096
#define BUFFER_DEFAULT_SIZE	512

#define log_print	printf

#define atomic_incl(x) asm volatile("lock incl %0"::"m"(x):)
#define atomic_decl(x) asm volatile("lock decl %0"::"m"(x):)

int epoll_fd = -1;
int listen_fd = -1;
int timeout = 500;
int holdlock = 0;
int g_cid = -1;

#define MAX_EPOLL_WAIT_NUM	128
struct epoll_event *pevent_ret = NULL;

union epoll_data listen_fd_epoll_data;

struct epoll_event listen_fd_epoll_event;

int SetNonBlock(int iSock){
	int iFlags = fcntl(iSock,F_GETFL,0);
	iFlags |= O_NONBLOCK;
	iFlags |= O_NDELAY;
	return fcntl(iSock, F_SETFL, iFlags);
}

int set_affinity( long idx ){
	long ncpus = sysconf(_SC_NPROCESSORS_ONLN);

	if( idx >= ncpus )
		return -1;

	cpu_set_t mask;
	CPU_ZERO(&mask);
	CPU_SET(idx, &mask); 
	if (sched_setaffinity(0, sizeof(mask), &mask) < 0) {
		log_print("sched_setaffinity\n");
		return -1;
	}

	return 0;
}

struct listening{
	void *data;
	int listen_fd;
	struct sockaddr_in sa;
	socklen_t socklen;
	int backlog;

	struct connection *conn;
};

struct event{
	void *data;
	struct connection *conn;
	void (*handler)(struct event *);
};

struct connection{
	int fd;
	void *data;
	struct event *read_event;
	struct event *write_event;
	struct listening *listen;
	struct sockaddr_in sa;

	unsigned int ref;

	char *buffer;
	unsigned int buffer_size;
	unsigned int buffer_pos;
};

void event_read( struct event *pev ){
	printf("TODO read\n");

}

#define SHM_PATH	"./shm_lock"
pthread_mutex_t *mutex;
pthread_mutexattr_t mutexAttr;


int init_ipc(){
	int shmid = shmget(0x2234,4096, IPC_CREAT | 0666);
	if( -1 == shmid ){
		log_print("shm create error\n");
		return -1;
	}
	void *p = shmat(shmid, NULL, 0);
	if( !p ){
		log_print("shmat error\n");
		return -2;
	}

	mutex = (pthread_mutex_t *)p;

	pthread_mutexattr_init(&mutexAttr);
	pthread_mutexattr_setpshared(&mutexAttr,PTHREAD_PROCESS_SHARED);
	if( pthread_mutex_init(mutex,&mutexAttr) ){
		log_print("mutex_init error\n");
		return -3;
	}


	return 0;
}

struct connection *init_client_fd( struct listening *plisten,struct sockaddr_in *psa,int client_fd ){

	struct event *pev = (struct event *)malloc( sizeof(struct event) );
	struct connection *pconn = (struct connection *)malloc( sizeof(struct connection) );

	if( !pconn || !pev ){
		if( pconn )
			free( pconn );
		if( pev )
			free( pev );
		log_print("malloc fail!\n");
		return NULL;
	}

	memcpy( &(pconn->sa),psa,sizeof(pconn->sa) );

	pev->conn = pconn;
	pev->handler = event_read;

	pconn->fd = client_fd;
	pconn->read_event = pev;
	pconn->write_event = NULL;
	pconn->listen = plisten;
	pconn->ref = 0;

	pconn->buffer = malloc( BUFFER_DEFAULT_SIZE );
	if( !pconn->buffer ){
		log_print("malloc buffer fail\n");
		free( pev );
		free( pconn );
		return NULL;
	}


	pconn->buffer_pos = 0;
	pconn->buffer_size = BUFFER_DEFAULT_SIZE;


	atomic_incl(pconn->ref);

	return pconn;
}

void event_accept( struct event *pev ){
	struct sockaddr_in sa;
	socklen_t len = sizeof(sa);


	int cli_fd = accept( pev->conn->fd,(struct sockaddr *)&sa,&len );

	if( -1 == cli_fd ){
		log_print("accept err\n");
		return;
	}

	log_print("cid:%d  %s:%d connect\n",g_cid,inet_ntoa(sa.sin_addr),ntohs(sa.sin_port));
	struct connection *pconn = init_client_fd( pev->conn->listen,&sa,cli_fd );

	if( !pconn ){
		close(cli_fd);
		log_print("init client_fd err\n");
		return;
	}


	struct epoll_event ee;
	ee.events = EPOLLIN | EPOLLET;
	ee.data.ptr = (void *)pconn;
	if( -1 == epoll_ctl( epoll_fd, EPOLL_CTL_ADD,cli_fd,&ee ) ){
		log_print("epoll_ctl add cli_fd fail!\n");
		close(cli_fd);
		free(pconn->read_event);
		free(pconn);
		return;
	}
}


struct listening g_listening;


int init_listening(){
	listen_fd = socket( AF_INET, SOCK_STREAM, 0 );

	if( -1 == listen_fd ){
		log_print("listen_fd create fail!\n");
		return -1;
	}

	if( -1 == SetNonBlock( listen_fd ) ){
		log_print("listen_fd set nonblock fail!\n");
		close(listen_fd);
		return -1;
	}

	g_listening.sa.sin_family = AF_INET;
	g_listening.sa.sin_port = htons(7001);
	g_listening.sa.sin_addr.s_addr = inet_addr("192.168.88.130");

	g_listening.socklen = sizeof(g_listening.sa);

	g_listening.listen_fd = listen_fd;

	if( bind( g_listening.listen_fd,(struct sockaddr *)&g_listening.sa,g_listening.socklen ) ){
		log_print("bind fail!\n");
		close(listen_fd);
		return -1;
	}

	g_listening.backlog = 5;

	struct event *pev = (struct event *)malloc( sizeof(struct event) );
	struct connection *pconn = (struct connection *)malloc( sizeof(struct connection) );

	if( !pconn || !pev ){
		if( pconn )
			free(pconn);
		if( pev )
			free(pev);
		log_print("malloc fail!\n");
		close(listen_fd);
		return -1;
	}

	pev->conn = pconn;
	pev->handler = event_accept;

	pconn->fd = g_listening.listen_fd;
	pconn->read_event = pev;
	pconn->write_event = NULL;
	pconn->listen = &g_listening;
	pconn->ref = 0;

	atomic_incl(pconn->ref);

	g_listening.conn = pconn;


	listen( g_listening.listen_fd,g_listening.backlog );

	return 0;
}

int enable_listening(){
	struct epoll_event ee;
	ee.events = EPOLLIN | EPOLLET;
	ee.data.ptr = (void *)g_listening.conn;

	if( -1 == epoll_ctl( epoll_fd, EPOLL_CTL_ADD,g_listening.listen_fd,&ee ) ){
		log_print("epoll_ctl add listen_fd fail! %d\n",errno);
		close(listen_fd);
		return -1;
	}
	return 0;
}

int disable_listening(){
	if( -1 == epoll_ctl( epoll_fd, EPOLL_CTL_DEL,g_listening.listen_fd,NULL ) ){
		log_print("epoll_ctl del listen_fd fail!\n");
		close(listen_fd);
		return -1;
	}
	return 0;
}

int init_epoll(){
	epoll_fd = epoll_create( MAX_CONNECTION_NUM/2 );

	if( -1 == epoll_fd ){
		log_print("epoll_fd create fail!\n");
		return -1;
	}

	pevent_ret = malloc( sizeof(struct epoll_event) * MAX_EPOLL_WAIT_NUM );

	if( !pevent_ret ){
		log_print("malloc fail0!\n");
		return -1;
	}



	return 0;
}


int try_lock_mutex(){
	int ret = pthread_mutex_trylock(mutex);
	return ret;
}

int unlock_mutex(){
	int ret = pthread_mutex_unlock(mutex);
	return ret;
}

int handle_event_entity(){
	int i;
	int ret;

	//log_print("cid:%d wait\n",g_cid);
	ret = epoll_wait( epoll_fd,pevent_ret,MAX_EPOLL_WAIT_NUM,timeout );

	if( -1 == ret ){
		log_print("epoll_wait fail!\n");
		return -3;
	}

	if( 0 == ret ){
		return 0;
	}

	//handle event

	for( i = 0; i < ret; i++ ){
		struct connection *pconn = (struct connection *)pevent_ret[i].data.ptr;
		if( !pconn ){
			log_print("handle event get ptr fail!\n");
			return -1;
		}

		if( pevent_ret[i].events & EPOLLIN){
			pconn->read_event->handler( pconn->read_event );
		}else if( pevent_ret[i].events & EPOLLOUT){

		}
	}

	return 0;

}

int start_event_loop(int cid){

	g_cid = cid;
	log_print("cid:%d start\n",cid);

	int ret = 0;
	int i = 0;

	ret = init_epoll();
	if( 0 != ret )
		return -1;


	while(1){
		if( !try_lock_mutex() ){
			if( 1 == holdlock )
				goto _handle;
			holdlock = 1;
			if( enable_listening() )
				return -2;
		}else{
			if( 1 == holdlock ){
				if( disable_listening() )
					return -3;
				holdlock = 0;
			}
		}
_handle:
		handle_event_entity();
		if( 1 == holdlock ){
			unlock_mutex();
			sleep(3);
		}
	}

	return 0;
}



int main(){

	int i = 0;
	int ret = 0;
	long ncpus = sysconf(_SC_NPROCESSORS_ONLN);

	ret = init_ipc();
	if( ret )
		return ret;

	ret = init_listening();
	if( 0 != ret )
		return -2;

	int cid = 0;

	while( i < ncpus ){
		int pid = fork();
		if( 0 == pid ){
			if( set_affinity( cid ) )
				return -1;

			ret = start_event_loop(cid);
			return 0;
		}else{
			cid++;
		}
		i++;
	}

	while(1);
}
